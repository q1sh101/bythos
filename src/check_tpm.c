#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

static bool parse_max_auth_fail(const char *text, unsigned long *out) {
    if (text == NULL || out == NULL) return false;

    const char *key = strstr(text, "TPM2_PT_MAX_AUTH_FAIL");
    if (key == NULL) return false;

    const char *cursor = key + strlen("TPM2_PT_MAX_AUTH_FAIL");
    const char *search_from = (*cursor != '\0') ? cursor + 1 : cursor;
    const char *end = strstr(search_from, "TPM2_PT_");
    if (end == NULL) end = cursor + strlen(cursor);

    const char *value_kw = strstr(cursor, "value:");
    if (value_kw != NULL && value_kw < end) {
        const char *p = value_kw + strlen("value:");
        while (*p == ' ' || *p == '\t') p++;
        if (isdigit((unsigned char)*p)) {
            char *endptr = NULL;
            unsigned long v = strtoul(p, &endptr, 10);
            if (endptr != p) {
                *out = v;
                return true;
            }
        }
    }

    const char *hex = strstr(cursor, "0x");
    if (hex != NULL && hex < end) {
        char *endptr = NULL;
        unsigned long v = strtoul(hex, &endptr, 16);
        if (endptr != hex) {
            *out = v;
            return true;
        }
    }

    return false;
}

size_t bythos_check_tpm(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *tpm_class_path = "/sys/class/tpm/tpm0";
    const char *tpm_major_path = "/sys/class/tpm/tpm0/tpm_version_major";

    bool tpm_present = bythos_file_exists(tpm_class_path);

    {
        char major[64] = {0};

        if (!tpm_present) {
            EMIT("TPM presence", CHECK_WARN, "no TPM device visible");
        } else if (!bythos_read_file_text(tpm_major_path, major, sizeof(major))) {
            EMIT("TPM presence", CHECK_WARN, "TPM device visible but version unreadable");
        } else {
            char *trimmed = bythos_trim(major);

            if (strcmp(trimmed, "2") == 0) {
                EMIT("TPM presence", CHECK_OK, "TPM 2.0 device visible");
            } else if (trimmed[0] != '\0') {
                char detail[128];
                snprintf(detail, sizeof(detail), "TPM %s.x device visible; expected TPM 2.0", trimmed);
                EMIT("TPM presence", CHECK_WARN, detail);
            } else {
                EMIT("TPM presence", CHECK_WARN, "TPM device visible but version not visible");
            }
        }
    }

    {
        static const char *const getcap_argv[] = {"tpm2_getcap", "properties-variable", NULL};
        char buf[4096] = {0};
        int exit_status = -1;
        unsigned long max_auth_fail = 0;

        if (!tpm_present) {
            EMIT_SKIP_HW("DA lockout", "TPM");
        } else if (!bythos_command_exists("tpm2_getcap")) {
            EMIT_SKIP_TOOL_INSTALL("DA lockout", "tpm2-tools");
        } else if (!bythos_capture_argv_status(getcap_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            EMIT_SKIP_EXEC("DA lockout", "tpm2_getcap");
        } else if (!parse_max_auth_fail(buf, &max_auth_fail)) {
            EMIT_SKIP_PARSE("DA lockout", "tpm2_getcap");
        } else {
            char detail[BYTHOS_DETAIL_MAX];
            if (max_auth_fail == 0u) {
                EMIT("DA lockout", CHECK_WARN,
                    "maxAuthFail=0; lockout disabled or misconfigured");
            } else if (max_auth_fail <= 32u) {
                snprintf(detail, sizeof(detail), "maxAuthFail=%lu; strict policy", max_auth_fail);
                EMIT("DA lockout", CHECK_OK, detail);
            } else if (max_auth_fail <= 255u) {
                snprintf(detail, sizeof(detail), "maxAuthFail=%lu; moderate policy", max_auth_fail);
                EMIT("DA lockout", CHECK_OK, detail);
            } else if (max_auth_fail < 1000u) {
                snprintf(detail, sizeof(detail), "maxAuthFail=%lu; loose policy", max_auth_fail);
                EMIT("DA lockout", CHECK_WARN, detail);
            } else {
                snprintf(detail, sizeof(detail),
                    "maxAuthFail=%lu; very loose policy (PIN brute-force risk)", max_auth_fail);
                EMIT("DA lockout", CHECK_WARN, detail);
            }
        }
    }

    {
        static const char *const pcr7_argv[] = {"tpm2_pcrread", "sha256:7", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!tpm_present) {
            EMIT_SKIP_HW("TPM PCR 7", "TPM");
        } else if (!bythos_command_exists("tpm2_pcrread")) {
            EMIT_SKIP_TOOL_INSTALL("TPM PCR 7", "tpm2-tools");
        } else if (!bythos_capture_argv_status(pcr7_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            EMIT_SKIP_EXEC("TPM PCR 7", "tpm2_pcrread");
        } else {
            int z = bythos_pcr_zero_check(buf, 7);
            if (z < 0) {
                EMIT_SKIP_FIELD("TPM PCR 7", "PCR", "tpm2_pcrread");
            } else if (z == 1) {
                EMIT("TPM PCR 7", CHECK_WARN, "empty; Secure Boot state not measured into TPM");
            } else {
                EMIT("TPM PCR 7", CHECK_OK, "non-zero; Secure Boot state measured");
            }
        }
    }

    {
        static const char *const pcr0_argv[] = {"tpm2_pcrread", "sha256:0", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!tpm_present) {
            EMIT_SKIP_HW("TPM PCR 0", "TPM");
        } else if (!bythos_command_exists("tpm2_pcrread")) {
            EMIT_SKIP_TOOL_INSTALL("TPM PCR 0", "tpm2-tools");
        } else if (!bythos_capture_argv_status(pcr0_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            EMIT_SKIP_EXEC("TPM PCR 0", "tpm2_pcrread");
        } else {
            int z = bythos_pcr_zero_check(buf, 0);
            if (z < 0) {
                EMIT_SKIP_FIELD("TPM PCR 0", "PCR", "tpm2_pcrread");
            } else if (z == 1) {
                EMIT("TPM PCR 0", CHECK_WARN, "zero; firmware not measured at boot");
            } else {
                EMIT("TPM PCR 0", CHECK_OK, "non-zero; firmware measured at boot");
            }
        }
    }

    {
        const char *evlog_bin = "/sys/kernel/security/tpm0/binary_bios_measurements";
        const char *evlog_ascii = "/sys/kernel/security/tpm0/ascii_bios_measurements";

        if (!tpm_present) {
            EMIT_SKIP_HW("TPM event log", "TPM");
            EMIT_SKIP_HW("TPM event log ASCII", "TPM");
        } else if (!bythos_file_exists(evlog_bin)) {
            EMIT_SKIP("TPM event log", SKIP_FEATURE_ABSENT, "not exposed by firmware");
            EMIT_SKIP("TPM event log ASCII", SKIP_FEATURE_ABSENT, "binary log absent");
        } else {
            EMIT("TPM event log", CHECK_OK, "binary log present");

            FILE *f = fopen(evlog_ascii, "r");
            if (f == NULL) {
                EMIT_SKIP("TPM event log ASCII", SKIP_FEATURE_ABSENT, "kernel parser unavailable");
            } else {
                char line[512];
                bool found = false;
                while (fgets(line, sizeof(line), f) != NULL) {
                    if (strstr(line, "S-CRTM Version") != NULL) {
                        found = true;
                        break;
                    }
                }
                fclose(f);
                if (found) {
                    EMIT("TPM event log ASCII", CHECK_OK, "CRTM version event present");
                } else {
                    EMIT("TPM event log ASCII", CHECK_WARN, "S-CRTM Version event absent");
                }
            }
        }
    }

    return used;
}
