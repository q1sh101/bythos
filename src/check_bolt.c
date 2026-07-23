#include <dirent.h>
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"

static const char *const BOLT_SYSFS_BASE = "/sys/bus/thunderbolt/devices";

typedef enum {
    TB_DMA_UNREADABLE,
    TB_DMA_ALL_ON,
    TB_DMA_SOME_OFF,
} tb_dma_state_t;

static tb_dma_state_t read_tb_dma_state(void) {
    DIR *dir = opendir(BOLT_SYSFS_BASE);
    if (dir == NULL) return TB_DMA_UNREADABLE;

    size_t readable = 0, unprotected = 0;
    struct dirent *entry;
    while ((entry = bythos_readdir_safe(dir, NULL)) != NULL) {
        if (strncmp(entry->d_name, "domain", 6) != 0) continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s/iommu_dma_protection",
                     BOLT_SYSFS_BASE, entry->d_name) >= (int)sizeof(path)) continue;

        char val[8] = {0};
        if (!bythos_read_file_text(path, val, sizeof(val))) continue;
        readable++;
        if (strcmp(bythos_trim(val), "1") != 0) unprotected++;
    }

    closedir(dir);
    if (readable == 0) return TB_DMA_UNREADABLE;
    return unprotected > 0 ? TB_DMA_SOME_OFF : TB_DMA_ALL_ON;
}

static bool tb_controller_present(void) {
    DIR *dir = opendir(BOLT_SYSFS_BASE);
    if (dir == NULL) return false;

    bool found = false;
    struct dirent *entry;
    while ((entry = bythos_readdir_safe(dir, NULL)) != NULL) {
        if (strncmp(entry->d_name, "domain", 6) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

size_t bythos_check_bolt_dma(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (!tb_controller_present()) {
        EMIT_SKIP_HW("Thunderbolt DMA protection", "Thunderbolt");
        return used;
    }

    switch (read_tb_dma_state()) {
    case TB_DMA_UNREADABLE:
        EMIT_SKIP_FEATURE("Thunderbolt DMA protection", "iommu_dma_protection");
        break;
    case TB_DMA_ALL_ON:
        EMIT("Thunderbolt DMA protection", CHECK_OK, "pre-boot DMA active");
        break;
    case TB_DMA_SOME_OFF:
        EMIT("Thunderbolt DMA protection", CHECK_WARN, "pre-boot DMA inactive on at least one domain");
        break;
    }

    return used;
}
