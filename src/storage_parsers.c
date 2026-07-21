#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "storage_parsers.h"

#define BYTHOS_LUKS_PCR_WINDOW_BYTES 512

void bythos_parse_lsblk_posture(const char *text, bythos_lsblk_posture_t *posture) {
    if (posture == NULL) {
        return;
    }

    *posture = (bythos_lsblk_posture_t){0};

    if (text == NULL || *text == '\0') {
        return;
    }

    const char *cursor = text;
    while (*cursor != '\0') {
        size_t raw_len = strcspn(cursor, "\r\n");
        char line[512];
        bool is_luks = false;
        bool is_crypt = false;
        bool is_swap = false;

        if (raw_len > 0) {
            size_t copy_len = raw_len;
            if (copy_len >= sizeof(line)) {
                copy_len = sizeof(line) - 1;
            }

            memcpy(line, cursor, copy_len);
            line[copy_len] = '\0';

            if (strstr(line, "FSTYPE=\"crypto_LUKS\"") != NULL) {
                is_luks = true;
            }
            if (strstr(line, "TYPE=\"crypt\"") != NULL) {
                is_crypt = true;
            }
            if (strstr(line, "FSTYPE=\"swap\"") != NULL) {
                is_swap = true;
            }
        }

        if (is_luks) {
            posture->luks_count++;
        }
        if (is_crypt) {
            posture->crypt_count++;
            if (is_swap) {
                posture->crypt_swap_count++;
            }
        }

        cursor += raw_len;
        while (*cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
    }
}

int bythos_parse_luks_version(const char *text) {
    if (text == NULL) return 0;
    const char *key = strstr(text, "Version:");
    if (key == NULL) return 0;
    const char *p = key + strlen("Version:");
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '1') return 1;
    if (*p == '2') return 2;
    return 0;
}

bool bythos_parse_luks_integrity(const char *text) {
    if (text == NULL) return false;
    return strstr(text, "integrity:") != NULL;
}

static bool luks_scan_pcrs(const char *text, bool pubkey_line, uint32_t *mask_out) {
    *mask_out = 0;

    const char *pos = strstr(text, "systemd-tpm2");
    if (pos == NULL) return false;

    size_t window = strlen(pos);
    if (window > BYTHOS_LUKS_PCR_WINDOW_BYTES) window = BYTHOS_LUKS_PCR_WINDOW_BYTES;
    const char *end = pos + window;

    const char *line = pos;
    while (line < end) {
        const char *eol = line;
        while (eol < end && *eol != '\n' && *eol != '\r') eol++;

        bool has_pubkey = false;
        for (const char *s = line; s + 6 <= eol; s++) {
            if (strncmp(s, "pubkey", 6) == 0) { has_pubkey = true; break; }
        }

        if (has_pubkey == pubkey_line) {
            const char *p = line;
            while (p + 4 <= eol) {
                if (strncmp(p, "pcrs", 4) == 0 && p[4] != '-') {
                    const char *colon = p + 4;
                    while (colon < eol && *colon != ':') colon++;
                    if (colon >= eol) break;

                    const char *q = colon + 1;
                    bool found = false;
                    while (q < eol) {
                        if (*q >= '0' && *q <= '9') {
                            unsigned int n = 0;
                            unsigned int n_digits = 0;
                            while (q < eol && *q >= '0' && *q <= '9') {
                                if (n_digits < 3) {
                                    n = n * 10 + (unsigned int)(*q - '0');
                                    n_digits++;
                                }
                                q++;
                            }
                            if (n < 32) {
                                *mask_out |= (1u << n);
                                found = true;
                            }
                        } else {
                            q++;
                        }
                    }
                    if (found) return true;
                    break;
                }
                p++;
            }
        }

        line = (eol < end) ? eol + 1 : end;
    }

    return false;
}

bool bythos_parse_luks_pcr_mask(const char *text, uint32_t *mask_out) {
    if (text == NULL || mask_out == NULL) return false;
    return luks_scan_pcrs(text, false, mask_out);
}

bool bythos_luks_signed_policy_pcr_mask(const char *text, uint32_t *mask_out) {
    if (text == NULL || mask_out == NULL) return false;
    return luks_scan_pcrs(text, true, mask_out);
}
