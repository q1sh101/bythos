#include <stddef.h>

#include "checks.h"
#include "checks_internal.h"
#include "output.h"

#define SUBGROUP_REMAINING(sg) \
    (BYTHOS_MAX_SUBGROUP_RESULTS - (sg)->result_count)
#define SUBGROUP_TAIL(sg) \
    ((sg)->results + (sg)->result_count)

#define BYTHOS_SUBGROUP_MAX_FNS 6

typedef size_t (*subgroup_check_fn)(check_result_t *, size_t);

typedef struct {
    const char *name;
    subgroup_check_fn fns[BYTHOS_SUBGROUP_MAX_FNS];
} subgroup_def_t;

static void subgroup_init(check_subgroup_t *sg, const char *name) {
    sg->name = name;
    sg->result_count = 0;
    sg->truncated = false;
    sg->summary = (posture_summary_t){0};
}

static void subgroup_finalize(check_subgroup_t *sg) {
    for (size_t i = 0; i < sg->result_count; i++) {
        bythos_summary_add(&sg->summary, &sg->results[i]);
    }
}

static size_t run_subgroups(const subgroup_def_t *defs,
                            check_subgroup_t *subgroups,
                            size_t max_subgroups) {
    if (subgroups == NULL || max_subgroups == 0) return 0;
    size_t used = 0;
    for (size_t i = 0; defs[i].name != NULL && used < max_subgroups; i++) {
        check_subgroup_t *sg = &subgroups[used++];
        subgroup_init(sg, defs[i].name);
        for (size_t j = 0; j < BYTHOS_SUBGROUP_MAX_FNS && defs[i].fns[j] != NULL; j++) {
            if (sg->result_count >= BYTHOS_MAX_SUBGROUP_RESULTS) {
                sg->truncated = true;
                break;
            }
            size_t remaining = SUBGROUP_REMAINING(sg);
            size_t produced = defs[i].fns[j](SUBGROUP_TAIL(sg), remaining + 1);
            if (produced > remaining) {
                sg->truncated = true;
                produced = remaining;
            }
            sg->result_count += produced;
        }
        subgroup_finalize(sg);
    }
    return used;
}

static const subgroup_def_t firmware_subgroups[] = {
    {"efi",               {bythos_check_efi, NULL}},
    {"secure boot",       {bythos_check_secureboot, bythos_check_sbctl, NULL}},
    {"boot chain",        {bythos_check_bios_boot, bythos_check_boot_chain, NULL}},
    {"esp",               {bythos_check_esp_posture, NULL}},
    {"tpm",               {bythos_check_tpm, NULL}},
    {"luks",              {bythos_check_luks, NULL}},
    {"platform firmware", {bythos_check_bios_cntl, bythos_check_me_version, bythos_check_dci, bythos_check_chipsec, NULL}},
    {"platform dma",      {bythos_check_iommu, bythos_check_bolt_dma, NULL}},
    {"cpu",               {bythos_check_microcode, bythos_check_memory_encryption, NULL}},
    {"fwupd",             {bythos_check_fwupd, NULL}},
    {NULL, {NULL}},
};

size_t bythos_check_firmware(check_subgroup_t *subgroups, size_t max_subgroups) {
    return run_subgroups(firmware_subgroups, subgroups, max_subgroups);
}
