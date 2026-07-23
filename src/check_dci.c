#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

#define MSR_IA32_DEBUG_INTERFACE 0xC80ULL
#define DCI_ENABLE_BIT  (UINT64_C(1) << 0)
#define DCI_LOCK_BIT    (UINT64_C(1) << 30)

size_t bythos_check_dci(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) {
        return used;
    }

    bythos_cpu_vendor_t vendor = bythos_cpu_vendor();

    if (vendor == BYTHOS_CPU_VENDOR_AMD) {
        if (bythos_file_exists("/sys/module/ccp")) {
            results[used++] = make_result("AMD PSP visibility", CHECK_OK,
                "AMD PSP driver visible");
        } else {
            results[used++] = make_result("AMD PSP visibility", CHECK_WARN,
                "AMD PSP driver not loaded");
        }
        return used;
    }

    if (vendor != BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_SKIP_VENDOR("Intel DCI", "Intel-only check");
        return used;
    }

    static const char *const MSR_PATH = "/dev/cpu/0/msr";

    if (!bythos_file_exists(MSR_PATH)) {
        EMIT_SKIP_FEATURE("Intel DCI", "MSR device");
        return used;
    }

    int fd = open(MSR_PATH, O_RDONLY);
    if (fd < 0) {
        if (errno == EACCES) {
            EMIT_SKIP_EXEC_ROOT("Intel DCI", "MSR");
        } else {
            EMIT_SKIP_EXEC("Intel DCI", "MSR");
        }
        return used;
    }

    uint64_t val = 0;
    ssize_t n = pread(fd, &val, sizeof(val), (off_t)MSR_IA32_DEBUG_INTERFACE);
    close(fd);

    if (n != (ssize_t)sizeof(val)) {
        EMIT_SKIP_EXEC("Intel DCI", "MSR");
        return used;
    }

    bool enabled = (val & DCI_ENABLE_BIT) != 0;
    bool locked  = (val & DCI_LOCK_BIT)  != 0;

    if (enabled) {
        results[used++] = make_result("Intel DCI", CHECK_FAIL,
            locked ? "DCI enabled and locked (cannot be disabled without reboot)"
                   : "DCI enabled - USB-C debug access possible");
    } else if (locked) {
        results[used++] = make_result("Intel DCI", CHECK_OK, "DCI disabled and locked");
    } else {
        results[used++] = make_result("Intel DCI", CHECK_WARN, "DCI disabled but not locked");
    }

    return used;
}

size_t bythos_check_chipsec(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (bythos_command_exists("chipsec_main") || bythos_command_exists("chipsec")) {
        EMIT_SKIP("platform firmware deep audit", SKIP_NOT_CONFIGURED,
            "chipsec available; run manually for a deep audit");
    } else {
        EMIT_SKIP_TOOL_INSTALL("platform firmware deep audit", "chipsec");
    }

    return used;
}
