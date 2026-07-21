#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "checks.h"
#include "checks_internal.h"
#include "esp_parsers.h"
#include "runtime.h"

static const struct {
    const char *mount;
    const char *efi_dir;
} ESP_CANDIDATES[] = {
    {"/boot/efi", "/boot/efi/EFI"},
    {"/efi",      "/efi/EFI"},
    {"/boot",     "/boot/EFI"},
};

#define ESP_CANDIDATE_COUNT (sizeof(ESP_CANDIDATES) / sizeof(ESP_CANDIDATES[0]))

static size_t check_esp_permissions(check_result_t *results, size_t max_results) {
    size_t used = 0;
    struct stat st;

    if (used < max_results && stat("/boot", &st) == 0) {
        if (st.st_uid != 0) {
            results[used++] = make_result("/boot ownership", CHECK_WARN,
                "/boot not owned by root");
        } else if ((st.st_mode & (mode_t)0022) != 0) {
            results[used++] = make_result("/boot ownership", CHECK_WARN,
                "/boot world/group-writable");
        } else {
            results[used++] = make_result("/boot ownership", CHECK_OK,
                "root-owned and not world-writable");
        }
    }

    if (used >= max_results) return used;

    bool esp_found = false;
    for (size_t i = 0; i < ESP_CANDIDATE_COUNT; i++) {
        if (stat(ESP_CANDIDATES[i].mount, &st) == 0 &&
            bythos_file_exists(ESP_CANDIDATES[i].efi_dir)) {
            esp_found = true;
            break;
        }
    }

    if (!esp_found) {
        EMIT_SKIP("ESP mount", SKIP_FEATURE_ABSENT, "not accessible at /boot/efi, /efi, or /boot");
        return used;
    }
    if (st.st_uid != 0) {
        results[used++] = make_result("ESP ownership", CHECK_WARN,
            "not owned by root");
    } else if ((st.st_mode & (mode_t)0022) != 0) {
        results[used++] = make_result("ESP ownership", CHECK_WARN,
            "world/group-writable");
    } else {
        results[used++] = make_result("ESP ownership", CHECK_OK,
            "root-owned and not world-writable");
    }
    return used;
}

static size_t check_esp_filesystem(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    char mounts[65536] = {0};
    if (!bythos_read_file_text("/proc/mounts", mounts, sizeof(mounts))) {
        EMIT_SKIP_EXEC("ESP filesystem", "/proc/mounts");
        return used;
    }

    for (size_t i = 0; i < ESP_CANDIDATE_COUNT; i++) {
        if (!bythos_file_exists(ESP_CANDIDATES[i].efi_dir)) continue;

        char marker[64];
        snprintf(marker, sizeof(marker), " %s ", ESP_CANDIDATES[i].mount);
        const char *line = strstr(mounts, marker);
        if (line == NULL) continue;

        const char *fstype_start = line + strlen(marker);
        size_t fstype_len = strcspn(fstype_start, " \t\r\n");
        if (fstype_len == 0 || fstype_len >= 64) continue;

        char fstype[64] = {0};
        memcpy(fstype, fstype_start, fstype_len);

        if (strcmp(fstype, "vfat") == 0) {
            EMIT("ESP filesystem", CHECK_OK, "vfat");
        } else {
            char detail[BYTHOS_DETAIL_MAX];
            snprintf(detail, sizeof(detail), "unexpected: %s", fstype);
            EMIT("ESP filesystem", CHECK_WARN, detail);
        }
        return used;
    }

    EMIT_SKIP("ESP filesystem", SKIP_FEATURE_ABSENT, "ESP mount-point not found");
    return used;
}

static size_t check_efi_vendor_dirs(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    const char *esp_base = bythos_esp_efi_base();
    DIR *dir = opendir(esp_base);
    if (dir == NULL) {
        EMIT_SKIP_FEATURE("EFI vendor directories", "EFI directory");
        return used;
    }

    size_t total = 0;
    char unexpected[64] = {0};
    char names[BYTHOS_DETAIL_MAX] = {0};
    size_t names_len = 0;
    struct dirent *entry;

    while ((entry = bythos_readdir_safe(dir, NULL)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", esp_base, entry->d_name) >=
            (int)sizeof(path)) continue;
        struct stat st;
        /* FAT32 d_type is often DT_UNKNOWN; use stat to confirm directory */
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        total++;
        if (!bythos_esp_is_known_vendor(entry->d_name)) {
            if (unexpected[0] == '\0') {
                snprintf(unexpected, sizeof(unexpected), "%.60s", entry->d_name);
            }
            continue;
        }
        size_t name_len = strlen(entry->d_name);
        size_t sep_len = names_len > 0 ? 2 : 0;
        if (names_len + sep_len + name_len < sizeof(names)) {
            if (sep_len > 0) {
                names[names_len++] = ',';
                names[names_len++] = ' ';
            }
            memcpy(names + names_len, entry->d_name, name_len);
            names_len += name_len;
            names[names_len] = '\0';
        }
    }
    closedir(dir);

    if (total == 0) {
        results[used++] = make_result("EFI vendor directories", CHECK_WARN,
            "no vendor directories found");
    } else if (unexpected[0] != '\0') {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
            "unrecognized directory name: %s (name only, not a trust signal)", unexpected);
        results[used++] = make_result("EFI vendor directories", CHECK_OK, detail);
    } else {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%zu recognized: %.220s", total, names);
        results[used++] = make_result("EFI vendor directories", CHECK_OK, detail);
    }
    return used;
}

static bool find_shim(char *path_out, size_t size) {
    static const char *const shim_names[] = {"shimx64.efi", "shimaa64.efi"};
    const char *esp_base = bythos_esp_efi_base();
    DIR *efi_dir = opendir(esp_base);
    if (efi_dir == NULL) return false;
    bool found = false;
    struct dirent *vendor;
    while (!found && (vendor = bythos_readdir_safe(efi_dir, NULL)) != NULL) {
        if (vendor->d_name[0] == '.') continue;
        for (size_t i = 0; i < sizeof(shim_names) / sizeof(shim_names[0]); i++) {
            char candidate[PATH_MAX];
            if (snprintf(candidate, sizeof(candidate), "%s/%s/%s",
                         esp_base, vendor->d_name, shim_names[i]) >= (int)sizeof(candidate)) continue;
            if (bythos_file_exists(candidate)) {
                snprintf(path_out, size, "%s", candidate);
                found = true;
                break;
            }
        }
    }
    closedir(efi_dir);
    return found;
}

static size_t check_bootx64(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    /* UEFI fallback path used by attackers to persist across BootOrder resets */
    static const char *const fallback_names[] = {
        "BOOTX64.EFI", "bootx64.efi",
        "BOOTAA64.EFI", "bootaa64.efi",
    };
    const char *esp_base = bythos_esp_efi_base();
    char fallback_path[PATH_MAX] = {0};
    const char *fallback_filename = NULL;

    for (size_t i = 0; i < sizeof(fallback_names) / sizeof(fallback_names[0]); i++) {
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/BOOT/%s",
                     esp_base, fallback_names[i]) >= (int)sizeof(candidate)) continue;
        if (bythos_file_exists(candidate)) {
            snprintf(fallback_path, sizeof(fallback_path), "%s", candidate);
            fallback_filename = fallback_names[i];
            break;
        }
    }

    if (fallback_filename == NULL) {
        EMIT_SKIP_SUBJECT("default boot fallback", "default boot fallback");
        return used;
    }

    char shim[PATH_MAX] = {0};
    if (!find_shim(shim, sizeof(shim))) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%s present; shim not found for comparison", fallback_filename);
        EMIT_SKIP("default boot fallback", SKIP_SUBJECT_ABSENT, detail);
        return used;
    }

    struct stat st_boot, st_shim;
    if (stat(fallback_path, &st_boot) == 0 && stat(shim, &st_shim) == 0 &&
        st_boot.st_ino == st_shim.st_ino && st_boot.st_dev == st_shim.st_dev) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%s matches installed shim (inode)", fallback_filename);
        results[used++] = make_result("default boot fallback", CHECK_OK, detail);
        return used;
    }

    if (!bythos_command_exists("sha256sum") && used < max_results) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%s present; sha256sum unavailable for identity check",
                 fallback_filename);
        results[used++] = make_skip_actionable("default boot fallback", SKIP_TOOL_ABSENT, detail);
        return used;
    }

    const char *boot_argv[] = {"sha256sum", fallback_path, NULL};
    const char *shim_argv[] = {"sha256sum", shim,          NULL};
    char boot_out[256] = {0}, shim_out[256] = {0};
    int exit_a = -1, exit_b = -1;

    if (!bythos_capture_argv_status((const char *const *)boot_argv,
                                        boot_out, sizeof(boot_out), &exit_a) || exit_a != 0 ||
        !bythos_capture_argv_status((const char *const *)shim_argv,
                                        shim_out, sizeof(shim_out), &exit_b) || exit_b != 0) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%s present; hash unavailable", fallback_filename);
        EMIT_SKIP("default boot fallback", SKIP_EXEC_FAILED, detail);
        return used;
    }

    char boot_hash[128] = {0}, shim_hash[128] = {0};
    if (!bythos_parse_sha256sum_line(boot_out, boot_hash, sizeof(boot_hash)) ||
        !bythos_parse_sha256sum_line(shim_out, shim_hash, sizeof(shim_hash))) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%s present; hash parse failed", fallback_filename);
        EMIT_SKIP("default boot fallback", SKIP_OUTPUT_UNPARSEABLE, detail);
        return used;
    }

    char detail[BYTHOS_DETAIL_MAX];
    if (strcmp(boot_hash, shim_hash) == 0) {
        snprintf(detail, sizeof(detail), "%s matches installed shim (sha256)", fallback_filename);
        results[used++] = make_result("default boot fallback", CHECK_OK, detail);
    } else {
        snprintf(detail, sizeof(detail), "%s does not match installed shim", fallback_filename);
        results[used++] = make_result("default boot fallback", CHECK_WARN, detail);
    }
    return used;
}

static size_t check_update_capsule(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/UpdateCapsule", bythos_esp_efi_base());
    errno = 0;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        if (errno == ENOENT) {
            results[used++] = make_result("ESP UpdateCapsule", CHECK_OK,
                "no pending firmware capsules");
        } else if (errno == EACCES) {
            results[used++] = make_skip_root("ESP UpdateCapsule", SKIP_EXEC_FAILED,
                "UpdateCapsule directory unreadable");
        } else {
            results[used++] = make_skip("ESP UpdateCapsule", SKIP_EXEC_FAILED,
                "UpdateCapsule directory unreadable");
        }
        return used;
    }

    size_t count = 0;
    struct dirent *entry;
    while ((entry = bythos_readdir_safe(dir, NULL)) != NULL) {
        if (entry->d_name[0] != '.') count++;
    }
    closedir(dir);

    if (count == 0) {
        results[used++] = make_result("ESP UpdateCapsule", CHECK_OK,
            "directory empty");
    } else {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
            "%zu %s pending; firmware will apply on next reboot",
            count, bythos_pl(count, "file", "files"));
        results[used++] = make_result("ESP UpdateCapsule", CHECK_WARN, detail);
    }
    return used;
}

size_t bythos_check_esp_posture(check_result_t *results, size_t max_results) {
    size_t used = 0;
    size_t remaining;

    if (results == NULL || max_results == 0) return 0;

    remaining = max_results - used;
    used += check_esp_permissions(results + used, remaining);

    /* Without an ESP, the remaining checks have no input. */
    if (used > 0 && results[used - 1].state == CHECK_SKIP) return used;

    remaining = max_results - used;
    used += check_esp_filesystem(results + used, remaining);

    remaining = max_results - used;
    used += check_efi_vendor_dirs(results + used, remaining);

    remaining = max_results - used;
    used += check_bootx64(results + used, remaining);

    remaining = max_results - used;
    used += check_update_capsule(results + used, remaining);

    return used;
}
