#ifndef BYTHOS_SILICON_PARSERS_H
#define BYTHOS_SILICON_PARSERS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool iommu_disabled;
    bool vendor_iommu_on;
    bool passthrough_on;
    bool passthrough_off;
    bool strict_on;
    bool strict_off;
} bythos_iommu_cmdline_t;

typedef enum {
    BYTHOS_CPU_VENDOR_UNKNOWN = 0,
    BYTHOS_CPU_VENDOR_AMD,
    BYTHOS_CPU_VENDOR_INTEL,
} bythos_cpu_vendor_t;

typedef struct {
    bool amd_sme;
    bool amd_sme_active;
    bool intel_tme;
} bythos_mem_enc_flags_t;

void bythos_parse_iommu_cmdline(const char *text, bythos_iommu_cmdline_t *cmdline);
bool bythos_extract_microcode_revision(const char *text, char *buffer, size_t size);
bool bythos_parse_me_version(const char *text, char *out, size_t size);
bythos_cpu_vendor_t bythos_cpu_vendor(void);
/* returns: 1 = all zeros, 0 = non-zero, -1 = not found */
int bythos_pcr_zero_check(const char *buf, unsigned int pcr_num);
void bythos_parse_memory_encryption_flags(const char *cpuinfo,
                                              bythos_mem_enc_flags_t *flags);

#endif
