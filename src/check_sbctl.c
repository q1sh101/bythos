#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "firmware_parsers.h"
#include "runtime.h"

size_t bythos_check_sbctl(check_result_t *results, size_t max_results) {
    size_t used = 0;
    static const char *const sbctl_status_argv[] = {"sbctl", "status", NULL};

    {
        char buffer[2048] = {0};
        int status = -1;
        bythos_sbctl_status_t sbctl_status = {0};

        if (!bythos_command_exists("sbctl")) {
            EMIT_SKIP_TOOL_OR_UNTRUSTED("Secure Boot key management", "sbctl", "sbctl");
        } else if (!bythos_capture_argv_status(sbctl_status_argv, buffer, sizeof(buffer), &status)) {
            EMIT_SKIP_PROBE("Secure Boot key management", "sbctl");
        } else if (status != 0) {
            EMIT_SKIP("Secure Boot key management", SKIP_NOT_CONFIGURED,
                "sbctl not configured; platform keys still in use");
        } else if (!bythos_parse_sbctl_status(buffer, &sbctl_status)) {
            EMIT_SKIP_PROBE("Secure Boot key management", "sbctl");
        } else if (!sbctl_status.installed_known) {
            EMIT_SKIP_PROBE("Secure Boot key management", "sbctl");
        } else if (!sbctl_status.installed) {
            EMIT_SKIP("Secure Boot key management", SKIP_NOT_CONFIGURED,
                "sbctl not configured; platform keys still in use");
        } else if (!sbctl_status.owner_guid_present) {
            EMIT_SKIP_FIELD("Secure Boot key management", "GUID", "sbctl");
        } else {
            char detail[192];
            if (sbctl_status.vendor_keys_present) {
                snprintf(
                    detail,
                    sizeof(detail),
                    "initialized; owner GUID present; vendor keys %.64s",
                    sbctl_status.vendor_keys
                );
            } else {
                snprintf(detail, sizeof(detail), "%s", "initialized; owner GUID present");
            }
            EMIT("Secure Boot key management", CHECK_OK, detail);
        }
    }

    return used;
}
