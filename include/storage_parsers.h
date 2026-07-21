#ifndef BYTHOS_STORAGE_PARSERS_H
#define BYTHOS_STORAGE_PARSERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t luks_count;
    size_t crypt_count;
    size_t crypt_swap_count;
} bythos_lsblk_posture_t;

void bythos_parse_lsblk_posture(const char *text, bythos_lsblk_posture_t *posture);

/* raw hash-policy PCRs ("tpm2-hash-pcrs"); ignores the signed-policy pubkey line */
bool bythos_parse_luks_pcr_mask(const char *text, uint32_t *mask_out);

/* signed-policy PCRs ("tpm2-pubkey-pcrs"); true only when a pubkey binding exists */
bool bythos_luks_signed_policy_pcr_mask(const char *text, uint32_t *mask_out);

/*
 * Returns 1 or 2 for LUKS1/LUKS2, or 0 if version cannot be determined.
 * Reads the "Version:" line from cryptsetup luksDump output.
 */
int bythos_parse_luks_version(const char *text);

/*
 * Returns true if the LUKS data segment has dm-integrity configured.
 * Detects the "integrity:" field in cryptsetup luksDump output.
 */
bool bythos_parse_luks_integrity(const char *text);

#endif
