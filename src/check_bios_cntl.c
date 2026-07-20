#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

#define INTEL_SPI_CONFIG "/sys/bus/pci/devices/0000:00:1f.5/config"
#define INTEL_LPC_CONFIG "/sys/bus/pci/devices/0000:00:1f.0/config"
#define BIOS_CNTL_OFFSET ((off_t)0xDC)

/* Skylake+ PCH moved BIOS_CNTL to the SPI controller (1f.5); older PCH keeps it on LPC (1f.0). */
static const char *bios_cntl_config_path(void) {
    if (bythos_file_exists(INTEL_SPI_CONFIG)) {
        return INTEL_SPI_CONFIG;
    }
    if (bythos_file_exists(INTEL_LPC_CONFIG)) {
        return INTEL_LPC_CONFIG;
    }
    return NULL;
}

size_t bythos_check_bios_cntl(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) return used;

    if (bythos_cpu_vendor() != BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_SKIP_VENDOR("Intel BIOS write protection", "Intel-only check");
        return used;
    }

    const char *config_path = bios_cntl_config_path();
    if (config_path == NULL) {
        EMIT_SKIP_HW("Intel BIOS write protection", "Intel PCH");
        return used;
    }

    int fd = open(config_path, O_RDONLY);
    if (fd < 0) {
        EMIT_SKIP_EXEC_ROOT("Intel BIOS write protection", "PCI config");
        return used;
    }

    uint8_t byte = 0;
    ssize_t n = pread(fd, &byte, 1, BIOS_CNTL_OFFSET);
    close(fd);

    if (n != 1) {
        EMIT_SKIP_EXEC("Intel BIOS write protection", "BIOS_CNTL");
        return used;
    }

    unsigned int bioswe  = (unsigned int)(byte & 0x01u);
    unsigned int ble     = (unsigned int)((byte >> 1) & 0x01u);
    unsigned int smm_bwp = (unsigned int)((byte >> 5) & 0x01u);

    if (bioswe) {
        results[used++] = make_result("Intel BIOS write protection", CHECK_WARN,
            "BIOSWE set: BIOS region write enabled");
    } else if (!ble) {
        results[used++] = make_result("Intel BIOS write protection", CHECK_WARN,
            "BLE not set: BIOS lock enable missing");
    } else if (!smm_bwp) {
        results[used++] = make_result("Intel BIOS write protection", CHECK_WARN,
            "SMM_BWP not set: SMM-only write not enforced");
    } else {
        results[used++] = make_result("Intel BIOS write protection", CHECK_OK,
            "BLE and SMM_BWP set; BIOS region protected");
    }

    return used;
}
