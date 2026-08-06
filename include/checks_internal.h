#ifndef BYTHOS_CHECKS_INTERNAL_H
#define BYTHOS_CHECKS_INTERNAL_H

#include <stddef.h>

#include "runtime.h"
#include "types.h"

size_t bythos_check_iommu(check_result_t *results, size_t max_results);
size_t bythos_check_dci(check_result_t *results, size_t max_results);
size_t bythos_check_chipsec(check_result_t *results, size_t max_results);
size_t bythos_check_bolt_dma(check_result_t *results, size_t max_results);
size_t bythos_check_efi(check_result_t *results, size_t max_results);
size_t bythos_check_tpm(check_result_t *results, size_t max_results);
size_t bythos_check_microcode(check_result_t *results, size_t max_results);
size_t bythos_check_memory_encryption(check_result_t *results, size_t max_results);
size_t bythos_check_luks(check_result_t *results, size_t max_results);
size_t bythos_check_fwupd(check_result_t *results, size_t max_results);
size_t bythos_check_sbctl(check_result_t *results, size_t max_results);
size_t bythos_check_secureboot(check_result_t *results, size_t max_results);
size_t bythos_check_bios_boot(check_result_t *results, size_t max_results);
size_t bythos_check_boot_chain(check_result_t *results, size_t max_results);
size_t bythos_check_esp_posture(check_result_t *results, size_t max_results);
size_t bythos_check_bios_cntl(check_result_t *results, size_t max_results);
size_t bythos_check_me_version(check_result_t *results, size_t max_results);

#define EMIT_SKIP_TOOL_OR_UNTRUSTED(name_, binary_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = bythos_command_untrusted(binary_) \
                ? make_result((name_), CHECK_WARN, \
                    binary_ " on PATH is not root-owned; refusing to run it as root") \
                : make_skip_actionable((name_), SKIP_TOOL_ABSENT, "requires " tool_); \
        } \
    } while (0)

#endif
