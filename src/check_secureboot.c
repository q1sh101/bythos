#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "efi_boot_parsers.h"
#include "firmware_ownership.h"
#include "firmware_parsers.h"
#include "runtime.h"

#define EFI_SIGDB_GUID   "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define EFI_SBAT_GUID    "605dab50-e046-4300-abb6-3dd810dd8b23"
#define EFI_DB_PATH      "/sys/firmware/efi/efivars/db-"  EFI_SIGDB_GUID
#define EFI_DBX_PATH     "/sys/firmware/efi/efivars/dbx-" EFI_SIGDB_GUID
#define EFI_SBAT_RT_PATH "/sys/firmware/efi/efivars/SbatLevelRT-" EFI_SBAT_GUID
#define EFI_SBAT_PATH    "/sys/firmware/efi/efivars/SbatLevel-"   EFI_SBAT_GUID

static void check_sigdb_variable(const char *path, const char *name,
                                 bool efi_visible,
                                 check_result_t *results, size_t *used,
                                 size_t max_results) {
    if (*used >= max_results) {
        return;
    }

    if (!efi_visible) {
        results[(*used)++] = make_skip(name, SKIP_FEATURE_ABSENT,
            "EFI runtime not available");
        return;
    }

    if (!bythos_file_exists(path)) {
        results[(*used)++] = make_result(name, CHECK_WARN,
            "UEFI visible but variable missing");
        return;
    }

    /* db/dbx presence matters; sample only enough to classify empty vs non-empty. */
    unsigned char buf[32];
    size_t len = 0;
    if (!bythos_read_file_binary(path, buf, sizeof(buf), &len)) {
        results[(*used)++] = make_result(name, CHECK_WARN, "variable unreadable");
        return;
    }

    bythos_efi_sigdb_status_t status = bythos_classify_efi_sigdb(buf, len);
    if (status == BYTHOS_EFI_SIGDB_NONEMPTY) {
        results[(*used)++] = make_result(name, CHECK_OK, "visible and non-empty");
    } else {
        results[(*used)++] = make_result(name, CHECK_WARN, "visible but empty");
    }
}

size_t bythos_check_secureboot(check_result_t *results, size_t max_results) {
    size_t used = 0;
    bool has_mokutil = false;
    static const char *mokutil_state_argv[] = {"mokutil", "--sb-state", NULL};
    char state_buffer[512] = {0};
    bool have_state_output = false;
    bythos_mok_ownership_t ownership = {0};
    bythos_secure_boot_status_t state = BYTHOS_SECURE_BOOT_UNKNOWN;

    has_mokutil = bythos_command_exists("mokutil");

    if (has_mokutil) {
        bythos_probe_mok_ownership(&ownership);
    }

    int sb_exit = -1;
    if (!has_mokutil) {
        EMIT_SKIP_TOOL_INSTALL("secure boot state", "mokutil");
    } else if (!bythos_capture_argv_status(mokutil_state_argv, state_buffer, sizeof(state_buffer), &sb_exit) || sb_exit != 0) {
        EMIT("secure boot state", CHECK_WARN, "unable to query");
    /* Disabled Secure Boot is a direct posture regression for this layer, so keep it as FAIL. */
    } else if ((state = bythos_parse_secure_boot_state(state_buffer)) == BYTHOS_SECURE_BOOT_ENABLED) {
        have_state_output = true;
        EMIT("secure boot state", CHECK_OK, "Secure Boot enabled");
    } else if (state == BYTHOS_SECURE_BOOT_DISABLED) {
        have_state_output = true;
        EMIT("secure boot state", CHECK_FAIL, "Secure Boot disabled");
    } else {
        have_state_output = true;
        EMIT("secure boot state", CHECK_WARN, "mokutil output not recognized");
    }

    if (!has_mokutil) {
        EMIT_SKIP_TOOL_INSTALL("secure boot setup mode", "mokutil");
    } else if (!have_state_output) {
        EMIT_SKIP_PROBE("secure boot setup mode", "mokutil");
    } else if (bythos_secure_boot_setup_mode(state_buffer)) {
        EMIT("secure boot setup mode", CHECK_WARN, "enabled");
    } else {
        EMIT("secure boot setup mode", CHECK_OK, "disabled");
    }

    if (!has_mokutil) {
        EMIT_SKIP_TOOL_INSTALL("shim validation", "mokutil");
    } else if (state == BYTHOS_SECURE_BOOT_DISABLED) {
        EMIT_SKIP("shim validation", SKIP_FEATURE_ABSENT, "Secure Boot not enabled");
    } else if (state != BYTHOS_SECURE_BOOT_ENABLED) {
        EMIT_SKIP_PROBE("shim validation", "mokutil");
    } else if (bythos_secure_boot_validation_disabled(state_buffer)) {
        EMIT("shim validation", CHECK_FAIL, "disabled; shim boots unsigned images");
    } else {
        EMIT("shim validation", CHECK_OK, "enforced");
    }

    if (!has_mokutil) {
        EMIT_SKIP_TOOL_INSTALL("platform key owner", "mokutil");
    } else if (!ownership.owner_readable) {
        EMIT_SKIP_EXEC("platform key owner", "mokutil");
    } else if (ownership.owner_parsed) {
        EMIT("platform key owner", CHECK_OK, ownership.owner);
    } else {
        EMIT_SKIP_PARSE("platform key owner", "mokutil");
    }

    if (!has_mokutil) {
        EMIT_SKIP_TOOL_INSTALL("MOK enrollments", "mokutil");
    } else if (!ownership.enrollments_readable) {
        EMIT_SKIP_EXEC("MOK enrollments", "mokutil");
    } else {
        char detail[BYTHOS_DETAIL_MAX];
        if (ownership.enrollment_count == 0) {
            EMIT("MOK enrollments", CHECK_OK, "none enrolled");
        } else if (ownership.enrolled_names_parsed) {
            snprintf(detail, sizeof(detail), "%zu enrolled: %.220s",
                ownership.enrollment_count, ownership.enrolled_names);
            EMIT("MOK enrollments", CHECK_OK, detail);
        } else {
            snprintf(detail, sizeof(detail), "%zu enrolled",
                ownership.enrollment_count);
            EMIT("MOK enrollments", CHECK_OK, detail);
        }
    }

    bool efi_visible = bythos_file_exists("/sys/firmware/efi");

    check_sigdb_variable(EFI_DB_PATH, "secure boot allowlist",
                         efi_visible, results, &used, max_results);

    check_sigdb_variable(EFI_DBX_PATH, "secure boot revocations",
                         efi_visible, results, &used, max_results);

    if (!efi_visible) {
        EMIT_SKIP_FEATURE("Secure Boot dbx size", "EFI runtime");
    } else {
        unsigned char dbx_buf[65536];
        size_t dbx_len = 0;
        if (!bythos_read_file_binary(EFI_DBX_PATH, dbx_buf, sizeof(dbx_buf), &dbx_len) ||
            dbx_len <= 4u) {
            EMIT_SKIP_EXEC("Secure Boot dbx size", "EFI dbx");
        } else {
            size_t payload = dbx_len - 4u;
            char detail[BYTHOS_DETAIL_MAX];
            if (payload < 100) {
                snprintf(detail, sizeof(detail),
                    "minimal (%zu bytes); may be factory default", payload);
                EMIT("Secure Boot dbx size", CHECK_WARN, detail);
            } else {
                snprintf(detail, sizeof(detail),
                    "non-minimal (%zu bytes); currency unverified", payload);
                EMIT("Secure Boot dbx size", CHECK_OK, detail);
            }
        }
    }

    if (!efi_visible) {
        EMIT_SKIP_FEATURE("Secure Boot db keys", "EFI runtime");
    } else {
        unsigned char db_buf[65536];
        size_t db_len = 0;
        if (!bythos_read_file_binary(EFI_DB_PATH, db_buf, sizeof(db_buf), &db_len)) {
            EMIT_SKIP_EXEC("Secure Boot db keys", "EFI db");
        } else {
            size_t lists = bythos_count_efi_sigdb_lists(db_buf, db_len);
            if (lists == 0) {
                EMIT("Secure Boot db keys", CHECK_WARN, "empty; Secure Boot allowlist missing");
            } else {
                char detail[BYTHOS_DETAIL_MAX];
                snprintf(detail, sizeof(detail),
                    "%zu key %s in Secure Boot allowlist",
                    lists, bythos_pl(lists, "list", "lists"));
                EMIT("Secure Boot db keys", CHECK_OK, detail);
            }
        }
    }

    if (!efi_visible) {
        EMIT_SKIP_FEATURE("SBAT policy level", "EFI runtime");
    } else {
        const char *sbat_path = NULL;
        if (bythos_file_exists(EFI_SBAT_RT_PATH)) {
            sbat_path = EFI_SBAT_RT_PATH;
        } else if (bythos_file_exists(EFI_SBAT_PATH)) {
            sbat_path = EFI_SBAT_PATH;
        }

        if (sbat_path == NULL) {
            EMIT_SKIP("SBAT policy level", SKIP_FEATURE_ABSENT, "SbatLevel variable absent; pre-SBAT firmware");
        } else {
            unsigned char sbat_buf[256];
            size_t sbat_len = 0;
            if (!bythos_read_file_binary(sbat_path, sbat_buf, sizeof(sbat_buf), &sbat_len) ||
                sbat_len <= 4u) {
                EMIT("SBAT policy level", CHECK_WARN, "SbatLevel variable unreadable");
            } else {
                char sbat_line[64] = {0};
                if (!bythos_parse_sbat_level(sbat_buf, sbat_len, sbat_line, sizeof(sbat_line))) {
                    EMIT("SBAT policy level", CHECK_WARN, "SbatLevel variable unreadable");
                } else {
                    char detail[BYTHOS_DETAIL_MAX];
                    snprintf(detail, sizeof(detail), "SbatLevel: %s", sbat_line);
                    EMIT("SBAT policy level", CHECK_OK, detail);
                }
            }
        }
    }

    if (!has_mokutil) {
        EMIT_SKIP_TOOL_INSTALL("Secure Boot trust breadth", "mokutil");
    } else {
        static const char *const db_argv[] = {"mokutil", "--db", NULL};
        char db_buf[131072] = {0};
        int db_exit = -1;
        bool db_truncated = false;
        if (!bythos_capture_argv_status_ex(db_argv, db_buf, sizeof(db_buf), &db_exit, &db_truncated) ||
            db_exit != 0) {
            EMIT_SKIP_EXEC("Secure Boot trust breadth", "mokutil");
        } else if (db_truncated) {
            EMIT("Secure Boot trust breadth", CHECK_WARN,
                "mokutil output truncated; CA detection inconclusive, verify manually");
        } else if (bythos_sb_has_ms_ca(db_buf)) {
            EMIT("Secure Boot trust breadth", CHECK_WARN,
                "Microsoft 3rd Party UEFI CA in db; widens trusted signer set");
        } else {
            EMIT("Secure Boot trust breadth", CHECK_OK,
                "Microsoft 3rd Party UEFI CA not found in db");
        }
    }

    {
        char mounts_buf[16384] = {0};
        char opts[256] = {0};
        if (!bythos_read_file_text("/proc/mounts", mounts_buf, sizeof(mounts_buf))) {
            EMIT_SKIP_EXEC("efivarfs mount mode", "proc/mounts");
        } else if (!bythos_find_mount_opts(mounts_buf, "efivarfs", opts, sizeof(opts))) {
            EMIT_SKIP_FEATURE("efivarfs mount mode", "efivarfs");
        } else if (strcmp(opts, "ro") == 0 || strncmp(opts, "ro,", 3) == 0) {
            EMIT("efivarfs mount mode", CHECK_OK, "read-only");
        } else {
            EMIT("efivarfs mount mode", CHECK_WARN, "read-write; firmware-side variable protection still applies");
        }
    }

    return used;
}
