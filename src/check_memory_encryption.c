#include <stddef.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_memory_encryption(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    bythos_cpu_vendor_t vendor = bythos_cpu_vendor();

    if (vendor == BYTHOS_CPU_VENDOR_UNKNOWN) {
        EMIT_SKIP_VENDOR("memory encryption", "CPU vendor undetermined");
        return used;
    }
    if (vendor != BYTHOS_CPU_VENDOR_AMD && vendor != BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_SKIP_VENDOR("memory encryption", "vendor not supported (non-Intel/AMD)");
        return used;
    }

    char flags_line[4096] = {0};
    if (!bythos_first_line_with_prefix("/proc/cpuinfo", "flags", flags_line, sizeof(flags_line))) {
        EMIT_SKIP_EXEC("memory encryption", "cpuinfo");
        return used;
    }

    bythos_mem_enc_flags_t flags;
    bythos_parse_memory_encryption_flags(flags_line, &flags);

    if (vendor == BYTHOS_CPU_VENDOR_AMD) {
        if (!flags.amd_sme) {
            EMIT_SKIP("memory encryption", SKIP_FEATURE_ABSENT,
                "CPU encryption flags not detected");
        } else {
            EMIT("memory encryption", CHECK_OK,
                "AMD SME capability present; activation not verified");
        }
    } else {
        if (!flags.intel_tme) {
            EMIT_SKIP("memory encryption", SKIP_FEATURE_ABSENT,
                "CPU encryption flags not detected");
        } else {
            EMIT("memory encryption", CHECK_OK,
                "Intel TME capability present; activation not verified");
        }
    }

    return used;
}
