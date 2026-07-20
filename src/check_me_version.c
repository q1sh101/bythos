#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

#define ME_FW_VERSION_PATH "/sys/class/mei/mei0/fw_version"

size_t bythos_check_me_version(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) return used;

    if (bythos_cpu_vendor() != BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_SKIP_VENDOR("Intel ME version", "Intel-only check");
        return used;
    }

    if (!bythos_file_exists(ME_FW_VERSION_PATH)) {
        EMIT_SKIP_FEATURE("Intel ME version", "Intel ME");
        return used;
    }

    char buf[64] = {0};
    if (!bythos_read_file_text(ME_FW_VERSION_PATH, buf, sizeof(buf))) {
        EMIT_SKIP_EXEC("Intel ME version", "ME version");
        return used;
    }

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }

    char version[64] = {0};
    if (!bythos_parse_me_version(buf, version, sizeof(version))) {
        EMIT_SKIP_PARSE("Intel ME version", "ME version");
        return used;
    }

    char detail[BYTHOS_DETAIL_MAX];
    snprintf(detail, sizeof(detail), "%s; compare against Intel SA advisories", version);
    results[used++] = make_result("Intel ME version", CHECK_OK, detail);

    return used;
}
