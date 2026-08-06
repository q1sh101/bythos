#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "checks.h"
#include "checks_internal.h"
#include "efi_boot_parsers.h"
#include "firmware_parsers.h"
#include "runtime.h"

static size_t check_bootloader_version(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    static const char *const grub_argv[]    = {"grub-install",  "--version", NULL};
    static const char *const grub2_argv[]   = {"grub2-install", "--version", NULL};
    static const char *const bootctl_argv[] = {"bootctl",       "--version", NULL};

    const char *const *argv = NULL;

    if (bythos_command_exists("grub-install")) {
        argv = grub_argv;
    } else if (bythos_command_exists("grub2-install")) {
        argv = grub2_argv;
    } else if (bythos_command_exists("bootctl")) {
        argv = bootctl_argv;
    }

    if (argv == NULL) {
        if (bythos_command_untrusted("grub-install") ||
            bythos_command_untrusted("grub2-install") ||
            bythos_command_untrusted("bootctl")) {
            EMIT("bootloader version", CHECK_WARN,
                "bootloader tool on PATH is not root-owned; refusing to run it as root");
        } else {
            EMIT_SKIP_TOOL("bootloader version", "bootloader tool");
        }
        return used;
    }

    char buf[256] = {0};
    int exit_status = -1;
    if (!bythos_capture_argv_status(argv, buf, sizeof(buf), &exit_status) ||
        exit_status != 0 || buf[0] == '\0') {
        EMIT_SKIP_EXEC("bootloader version", "bootloader");
        return used;
    }

    char *trimmed = bythos_trim(buf);
    char detail[BYTHOS_DETAIL_MAX];
    snprintf(detail, sizeof(detail), "%.200s", trimmed);
    EMIT("bootloader version", CHECK_OK, detail);
    return used;
}

static bool find_efi_binary(const char *const *candidates, size_t candidate_count,
                            char *path_out, size_t path_out_size) {
    const char *base = bythos_esp_efi_base();
    DIR *efi_dir = opendir(base);
    if (efi_dir == NULL) {
        return false;
    }

    bool found = false;
    struct dirent *vendor;

    while (!found && (vendor = bythos_readdir_safe(efi_dir, NULL)) != NULL) {
        if (vendor->d_name[0] == '.') {
            continue;
        }

        char vendor_path[PATH_MAX];
        if (snprintf(vendor_path, sizeof(vendor_path), "%s/%s",
                     base, vendor->d_name) >= (int)sizeof(vendor_path)) {
            continue;
        }

        DIR *vendor_dir = opendir(vendor_path);
        if (vendor_dir == NULL) {
            continue;
        }

        struct dirent *entry;
        while ((entry = bythos_readdir_safe(vendor_dir, NULL)) != NULL) {
            char lower[256];
            bythos_to_lower_ascii(entry->d_name, lower, sizeof(lower));

            bool name_match = false;
            for (size_t i = 0; i < candidate_count; i++) {
                if (strcmp(lower, candidates[i]) == 0) {
                    name_match = true;
                    break;
                }
            }
            if (!name_match) {
                continue;
            }

            if (snprintf(path_out, path_out_size, "%s/%s",
                         vendor_path, entry->d_name) >= (int)path_out_size) {
                continue;
            }

            found = true;
            break;
        }

        closedir(vendor_dir);
    }

    closedir(efi_dir);
    return found;
}

#define EFI_GLOBAL_VAR_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"

typedef enum {
    SHIM_RESOLUTION_FOUND = 0,
    SHIM_RESOLUTION_FALLBACK_ALLOWED,
    SHIM_RESOLUTION_BOOTED_NON_SHIM,
    SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED,
} shim_resolution_t;

static shim_resolution_t find_booted_shim(char *path_out, size_t path_out_size) {
    unsigned char cur[8];
    size_t cur_len = 0;
    if (!bythos_read_file_binary(
            "/sys/firmware/efi/efivars/BootCurrent-" EFI_GLOBAL_VAR_GUID,
            cur, sizeof(cur), &cur_len) || cur_len < 6) {
        return SHIM_RESOLUTION_FALLBACK_ALLOWED;
    }
    unsigned int num = (unsigned int)cur[4] | ((unsigned int)cur[5] << 8);

    char var_path[PATH_MAX];
    if (snprintf(var_path, sizeof(var_path),
                 "/sys/firmware/efi/efivars/Boot%04X-" EFI_GLOBAL_VAR_GUID, num)
            >= (int)sizeof(var_path)) {
        return SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
    }

    unsigned char buf[4096];
    size_t buf_len = 0;
    bool buf_truncated = false;
    if (!bythos_read_file_binary_ex(var_path, buf, sizeof(buf), &buf_len, &buf_truncated) ||
        buf_truncated) {
        return SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
    }

    bythos_efi_boot_entry_t entry;
    if (!bythos_parse_efi_boot_entry(buf, buf_len, (uint16_t)num, &entry) ||
        entry.filepath[0] == '\0') {
        return SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
    }

    char norm[256];
    size_t k = 0;
    for (; entry.filepath[k] != '\0' && k + 1 < sizeof(norm); k++) {
        norm[k] = (entry.filepath[k] == '\\') ? '/' : entry.filepath[k];
    }
    norm[k] = '\0';

    char norm_lower[256];
    bythos_to_lower_ascii(norm, norm_lower, sizeof(norm_lower));

    if (strstr(norm_lower, "shimx64.efi") == NULL &&
        strstr(norm_lower, "shimaa64.efi") == NULL) {
        return SHIM_RESOLUTION_BOOTED_NON_SHIM;
    }

    const char *efi = strstr(norm_lower, "/efi/");
    if (efi == NULL) {
        return SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
    }
    size_t rel_off = (size_t)(efi - norm_lower) + 5;
    if (rel_off >= k) {
        return SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
    }

    if (snprintf(path_out, path_out_size, "%s/%s",
                 bythos_esp_efi_base(), norm + rel_off) >= (int)path_out_size) {
        return SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
    }
    return bythos_file_exists(path_out) ? SHIM_RESOLUTION_FOUND :
        SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED;
}

static bool find_shim(char *path_out, size_t path_out_size,
                      shim_resolution_t *resolution_out) {
    shim_resolution_t resolution = find_booted_shim(path_out, path_out_size);
    if (resolution == SHIM_RESOLUTION_FOUND) {
        if (resolution_out != NULL) {
            *resolution_out = resolution;
        }
        return true;
    }
    if (resolution != SHIM_RESOLUTION_FALLBACK_ALLOWED) {
        if (resolution_out != NULL) {
            *resolution_out = resolution;
        }
        return false;
    }
    static const char *const candidates[] = {"shimx64.efi", "shimaa64.efi"};
    bool found = find_efi_binary(candidates,
                                 sizeof(candidates) / sizeof(candidates[0]),
                                 path_out, path_out_size);
    if (resolution_out != NULL) {
        *resolution_out = found ? SHIM_RESOLUTION_FOUND :
            SHIM_RESOLUTION_FALLBACK_ALLOWED;
    }
    return found;
}

static bool find_grub(char *path_out, size_t path_out_size) {
    static const char *const candidates[] = {"grubx64.efi", "grubaa64.efi"};
    return find_efi_binary(candidates,
                           sizeof(candidates) / sizeof(candidates[0]),
                           path_out, path_out_size);
}

static size_t check_shim_signature(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    char shim_path[PATH_MAX] = {0};
    shim_resolution_t shim_resolution = SHIM_RESOLUTION_FALLBACK_ALLOWED;
    if (!find_shim(shim_path, sizeof(shim_path), &shim_resolution)) {
        if (shim_resolution == SHIM_RESOLUTION_BOOTED_NON_SHIM) {
            EMIT_SKIP("shim signature", SKIP_SUBJECT_ABSENT, "booted via non-shim path");
        } else if (shim_resolution == SHIM_RESOLUTION_BOOTCURRENT_UNRESOLVED) {
            EMIT_SKIP("shim signature", SKIP_OUTPUT_UNPARSEABLE, "BootCurrent path unresolved");
        } else {
            EMIT_SKIP_SUBJECT("shim signature", "shim");
        }
        return used;
    }

    if (!bythos_command_exists("pesign")) {
        EMIT_SKIP_TOOL_OR_UNTRUSTED("shim signature", "pesign", "pesign");
        return used;
    }

    const char *pesign_argv[] = {"pesign", "--show-signature", "--in", shim_path, NULL};
    char buf[2048] = {0};
    int exit_status = -1;

    if (!bythos_capture_argv_status(
            (const char *const *)pesign_argv, buf, sizeof(buf), &exit_status) ||
        exit_status != 0) {
        results[used++] = make_skip("shim signature", SKIP_EXEC_FAILED,
            "pesign query failed");
        return used;
    }

    char lower[2048];
    bythos_to_lower_ascii(buf, lower, sizeof(lower));

    if (buf[0] == '\0' || strstr(lower, "no signature") != NULL) {
        results[used++] = make_result("shim signature", CHECK_FAIL,
            "binary not signed");
    } else {
        results[used++] = make_result("shim signature", CHECK_OK,
            "signed; chain not validated");
    }
    return used;
}

static void note_boot_file_owner(const char *name, const struct stat *st,
                                 bool *any_warn,
                                 char *warn_detail, size_t warn_detail_size) {
    if (*any_warn) {
        return;
    }
    if (st->st_uid != 0) {
        *any_warn = true;
        snprintf(warn_detail, warn_detail_size,
            "file under /boot not root-owned: %.200s", name);
    } else if ((st->st_mode & (mode_t)0022) != 0) {
        *any_warn = true;
        snprintf(warn_detail, warn_detail_size,
            "file under /boot world/group writable: %.200s", name);
    }
}

static void scan_boot_dir(const char *dir_path, int max_depth, dev_t device,
                                size_t *count, bool *any_warn, bool *depth_exceeded,
                                bool *unverified_link,
                                char *warn_detail, size_t warn_detail_size) {
    DIR *d = opendir(dir_path);
    if (d == NULL) return;

    struct dirent *entry;
    while ((entry = bythos_readdir_safe(d, NULL)) != NULL) {
        const char *name = entry->d_name;
        if (name[0] == '.') continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dir_path, name) >= (int)sizeof(path)) {
            continue;
        }

        struct stat st;
        if (lstat(path, &st) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            if (st.st_dev != device) {
                continue;
            }
            (*count)++;
            note_boot_file_owner(name, &st, any_warn, warn_detail, warn_detail_size);
        } else if (S_ISLNK(st.st_mode)) {
            struct stat target;
            if (stat(path, &target) == 0 && S_ISREG(target.st_mode) &&
                target.st_dev == device) {
                note_boot_file_owner(name, &target, any_warn,
                                     warn_detail, warn_detail_size);
            } else {
                *unverified_link = true;
            }
        } else if (S_ISDIR(st.st_mode) && st.st_dev == device) {
            if (max_depth > 0) {
                scan_boot_dir(path, max_depth - 1, device, count, any_warn,
                              depth_exceeded, unverified_link,
                              warn_detail, warn_detail_size);
            } else {
                *depth_exceeded = true;
            }
        }
    }
    closedir(d);
}

static size_t check_boot_permissions(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    struct stat boot_st;
    if (stat("/boot", &boot_st) != 0) {
        EMIT_SKIP_EXEC("/boot file permissions", "/boot");
        return used;
    }

    {
        char mounts[65536] = {0};
        char fstype[64] = {0};
        bool mounts_truncated = false;
        if (bythos_read_file_text_ex("/proc/mounts", mounts, sizeof(mounts),
                                     &mounts_truncated) && mounts_truncated) {
            EMIT_SKIP("/boot file permissions", SKIP_PROBE_INDETERMINATE,
                "mount table larger than this tool reads");
            return used;
        }
        if (bythos_find_mount_entry(mounts, "/boot", fstype, sizeof(fstype), NULL, 0) &&
            (strcmp(fstype, "vfat") == 0 || strcmp(fstype, "msdos") == 0 ||
             strcmp(fstype, "exfat") == 0)) {
            EMIT_SKIP("/boot file permissions", SKIP_FEATURE_ABSENT,
                "this filesystem stores no per-file ownership");
            return used;
        }
    }

    size_t count = 0;
    bool any_warn = false;
    bool depth_exceeded = false;
    bool unverified_link = false;
    char warn_detail[BYTHOS_DETAIL_MAX] = {0};

    scan_boot_dir("/boot", 3, boot_st.st_dev, &count, &any_warn, &depth_exceeded,
                  &unverified_link, warn_detail, sizeof(warn_detail));

    if (used >= max_results) {
        return used;
    }

    if (count == 0) {
        EMIT_SKIP_SUBJECT("/boot file permissions", "boot files");
        return used;
    }

    if (any_warn) {
        results[used++] = make_result("/boot file permissions", CHECK_WARN, warn_detail);
    } else if (depth_exceeded) {
        results[used++] = make_skip("/boot file permissions", SKIP_PROBE_INDETERMINATE,
            "directories deeper than this tool scans; some files unchecked");
    } else if (unverified_link) {
        results[used++] = make_skip("/boot file permissions", SKIP_PROBE_INDETERMINATE,
            "some symlinks under /boot could not be verified");
    } else {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
            "%zu %s under /boot, all root-owned and not writable",
            count, bythos_pl(count, "file", "files"));
        results[used++] = make_result("/boot file permissions", CHECK_OK, detail);
    }
    return used;
}

#define BOOTLOADER_SBAT_BIN_BUF_BYTES (4u * 1024u * 1024u)
#define BOOTLOADER_SBAT_REV_BUF_BYTES 4096u

static size_t collect_sbat_entries(const char *bin_path,
                                    unsigned char *bin_buf, size_t bin_buf_size,
                                    bythos_sbat_entry_t *entries, size_t entries_capacity,
                                    size_t entries_used, bool *any_section,
                                    bool *binary_truncated) {
    if (bin_path == NULL || bin_path[0] == '\0' || entries_used >= entries_capacity) {
        return entries_used;
    }

    size_t bin_len = 0;
    bool truncated = false;
    if (!bythos_read_file_binary_ex(bin_path, bin_buf, bin_buf_size, &bin_len, &truncated)) {
        return entries_used;
    }
    if (truncated) {
        if (binary_truncated != NULL) {
            *binary_truncated = true;
        }
        return entries_used;
    }

    unsigned char section_buf[BYTHOS_SBAT_SECTION_MAX_BYTES];
    size_t section_len = 0;
    if (!bythos_extract_pe_section(bin_buf, bin_len, ".sbat",
                                   section_buf, sizeof(section_buf), &section_len)) {
        return entries_used;
    }

    if (any_section != NULL) {
        *any_section = true;
    }

    size_t parsed = bythos_parse_sbat_csv((const char *)section_buf, section_len,
                                          entries + entries_used,
                                          entries_capacity - entries_used);
    return entries_used + parsed;
}

static size_t check_bootloader_sbat(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    char shim_path[PATH_MAX] = {0};
    char grub_path[PATH_MAX] = {0};
    bool have_shim = find_shim(shim_path, sizeof(shim_path), NULL);
    bool have_grub = find_grub(grub_path, sizeof(grub_path));

    if (!have_shim && !have_grub) {
        EMIT_SKIP("bootloader SBAT", SKIP_SUBJECT_ABSENT,
            "shim/grub binary not present on this host");
        return used;
    }

    static unsigned char bin_buf[BOOTLOADER_SBAT_BIN_BUF_BYTES];
    bythos_sbat_entry_t installed[BYTHOS_SBAT_MAX_COMPONENTS];
    size_t installed_count = 0;
    bool any_section = false;
    bool binary_truncated = false;

    if (have_shim) {
        installed_count = collect_sbat_entries(shim_path, bin_buf, sizeof(bin_buf),
                                               installed, BYTHOS_SBAT_MAX_COMPONENTS,
                                               installed_count, &any_section,
                                               &binary_truncated);
    }
    if (have_grub) {
        installed_count = collect_sbat_entries(grub_path, bin_buf, sizeof(bin_buf),
                                               installed, BYTHOS_SBAT_MAX_COMPONENTS,
                                               installed_count, &any_section,
                                               &binary_truncated);
    }

    if (binary_truncated) {
        EMIT_SKIP("bootloader SBAT", SKIP_OUTPUT_UNPARSEABLE,
            "bootloader larger than this tool reads; SBAT not inspected");
        return used;
    }

    if (!any_section) {
        EMIT_SKIP("bootloader SBAT", SKIP_FEATURE_ABSENT,
            "EFI bootloader SBAT section not found");
        return used;
    }
    if (installed_count == 0) {
        EMIT_SKIP("bootloader SBAT", SKIP_OUTPUT_UNPARSEABLE,
            "SBAT section not parseable");
        return used;
    }

    if (!bythos_command_exists("mokutil")) {
        EMIT_SKIP_TOOL_OR_UNTRUSTED("bootloader SBAT", "mokutil", "mokutil");
        return used;
    }

    static const char *const rev_argv[] = {"mokutil", "--list-sbat-revocations", NULL};
    char rev_buf[BOOTLOADER_SBAT_REV_BUF_BYTES] = {0};
    int rev_exit = -1;
    bool rev_truncated = false;
    if (!bythos_capture_argv_status_ex(rev_argv, rev_buf, sizeof(rev_buf), &rev_exit, &rev_truncated) ||
        rev_exit != 0) {
        EMIT_SKIP_EXEC("bootloader SBAT", "mokutil");
        return used;
    }
    if (rev_truncated) {
        EMIT_SKIP("bootloader SBAT", SKIP_OUTPUT_UNPARSEABLE,
            "revocation list truncated; verdict unreliable");
        return used;
    }

    if (!bythos_sbat_entries_present(bythos_trim(rev_buf))) {
        EMIT_SKIP("bootloader SBAT", SKIP_PROBE_INDETERMINATE,
            "no SBAT revocation policy applied");
        return used;
    }

    bythos_sbat_entry_t revoked[BYTHOS_SBAT_MAX_COMPONENTS];
    size_t revoked_count = bythos_parse_sbat_revocation_minimums(
        rev_buf, revoked, BYTHOS_SBAT_MAX_COMPONENTS);

    if (revoked_count == 0) {
        EMIT_SKIP("bootloader SBAT", SKIP_PROBE_INDETERMINATE,
            "no SBAT revocation policy applied");
        return used;
    }

    for (size_t i = 0; i < installed_count; i++) {
        /* Multiple revocations for one component collapse to the strictest minimum. */
        unsigned int worst_revoked = 0;
        bool any_match = false;
        for (size_t j = 0; j < revoked_count; j++) {
            if (strcmp(installed[i].component, revoked[j].component) != 0) {
                continue;
            }
            any_match = true;
            if (revoked[j].generation > worst_revoked) {
                worst_revoked = revoked[j].generation;
            }
        }
        if (any_match && installed[i].generation < worst_revoked) {
            char detail[BYTHOS_DETAIL_MAX];
            snprintf(detail, sizeof(detail),
                "%.*s generation %u below revoked minimum %u",
                (int)(BYTHOS_SBAT_COMPONENT_NAME_MAX - 1),
                installed[i].component,
                installed[i].generation,
                worst_revoked);
            EMIT("bootloader SBAT", CHECK_WARN, detail);
            return used;
        }
    }

    EMIT("bootloader SBAT", CHECK_OK,
        "installed generations satisfy SBAT revocations");
    return used;
}

static size_t check_sbat_revocations(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    static const char *const sbat_argv[] = {"mokutil", "--list-sbat-revocations", NULL};
    char buf[4096] = {0};
    int exit_status = -1;

    if (!bythos_command_exists("mokutil")) {
        EMIT_SKIP_TOOL_OR_UNTRUSTED("SBAT revocations", "mokutil", "mokutil");
        return used;
    }

    if (!bythos_capture_argv_status(sbat_argv, buf, sizeof(buf), &exit_status) ||
        exit_status != 0) {
        EMIT_SKIP_EXEC("SBAT revocations", "mokutil");
        return used;
    }

    if (!bythos_sbat_entries_present(bythos_trim(buf))) {
        results[used++] = make_result("SBAT revocations", CHECK_WARN,
            "no revocation entries applied");
    } else {
        results[used++] = make_result("SBAT revocations", CHECK_OK,
            "revocation entries present");
    }
    return used;
}

size_t bythos_check_boot_chain(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (results == NULL || max_results == 0) {
        return 0;
    }

    size_t remaining;

    remaining = used < max_results ? max_results - used : 0;
    used += check_bootloader_version(results + used, remaining);

    remaining = used < max_results ? max_results - used : 0;
    used += check_bootloader_sbat(results + used, remaining);

    remaining = used < max_results ? max_results - used : 0;
    used += check_shim_signature(results + used, remaining);

    remaining = used < max_results ? max_results - used : 0;
    used += check_boot_permissions(results + used, remaining);

    remaining = used < max_results ? max_results - used : 0;
    used += check_sbat_revocations(results + used, remaining);

    return used;
}
