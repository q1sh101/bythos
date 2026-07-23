#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "storage_parsers.h"

#define PCR_BIT(n) (1u << (unsigned int)(n))

static void pcr_mask_to_str(uint32_t mask, char *out, size_t size) {
    size_t pos = 0;
    bool first = true;
    for (unsigned int i = 0; i < 32u && pos + 6 < size; i++) {
        if (mask & PCR_BIT(i)) {
            if (!first) out[pos++] = ' ';
            pos += (size_t)snprintf(out + pos, size - pos, "%u", i);
            first = false;
        }
    }
    if (pos == 0 && size > 0) out[0] = '\0';
}

size_t bythos_check_luks(check_result_t *results, size_t max_results) {
    size_t used = 0;
    static const char *const lsblk_argv[] = {"lsblk", "-P", "-o", "NAME,TYPE,FSTYPE", NULL};

    {
        char buffer[8192] = {0};
        int status = -1;
        bool truncated = false;
        bythos_lsblk_posture_t posture = {0};

        if (!bythos_command_exists("lsblk")) {
            EMIT_SKIP_TOOL_INSTALL("LUKS block devices", "util-linux");
        } else if (!bythos_capture_argv_status_ex(lsblk_argv, buffer, sizeof(buffer), &status, &truncated)) {
            EMIT("LUKS block devices", CHECK_WARN, "unable to inspect block devices");
        } else if (status != 0) {
            EMIT("LUKS block devices", CHECK_WARN, "lsblk inspection failed");
        } else if (truncated) {
            EMIT("LUKS block devices", CHECK_WARN, "lsblk output truncated; device list incomplete");
        } else {
            bythos_parse_lsblk_posture(buffer, &posture);
            if (posture.luks_count > 0) {
                char detail[224];
                snprintf(
                    detail,
                    sizeof(detail),
                    "%zu LUKS-encrypted %s visible",
                    posture.luks_count,
                    bythos_pl(posture.luks_count, "volume", "volumes")
                );
                EMIT("LUKS block devices", CHECK_OK, detail);
            } else if (posture.crypt_count > 0 && posture.crypt_count == posture.crypt_swap_count) {
                char detail[224];
                snprintf(
                    detail,
                    sizeof(detail),
                    "%zu encrypted swap %s visible; %s",
                    posture.crypt_swap_count,
                    bythos_pl(posture.crypt_swap_count, "device", "devices"),
                    "no LUKS-encrypted persistent volumes detected"
                );
                EMIT("LUKS block devices", CHECK_WARN, detail);
            } else if (posture.crypt_count > 0) {
                char detail[224];
                snprintf(
                    detail,
                    sizeof(detail),
                    "%zu encrypted mapper %s visible; %s",
                    posture.crypt_count,
                    bythos_pl(posture.crypt_count, "device", "devices"),
                    "no LUKS signature detected"
                );
                EMIT("LUKS block devices", CHECK_WARN, detail);
            } else {
                EMIT("LUKS block devices", CHECK_WARN, "no LUKS-encrypted volumes detected");
            }
        }
    }

    {
        static const char *const lsblk_fstype_argv[] = {
            "lsblk", "-P", "-o", "PATH,FSTYPE", NULL
        };
        char lsblk_buf[4096] = {0};
        int lsblk_status = -1;
        bool lsblk_truncated = false;
        bool tpm_present = bythos_file_exists("/sys/class/tpm/tpm0");

        if (!bythos_command_exists("lsblk")) {
            EMIT_SKIP_TOOL_INSTALL("LUKS version", "util-linux");
            EMIT_SKIP_TOOL_INSTALL("LUKS dm-integrity", "util-linux");
            EMIT_SKIP_TOOL_INSTALL("LUKS TPM binding", "util-linux");
            EMIT_SKIP_TOOL_INSTALL("LUKS Secure Boot binding", "util-linux");
            EMIT_SKIP_TOOL_INSTALL("LUKS boot chain binding", "util-linux");
        } else if (!bythos_command_exists("cryptsetup")) {
            EMIT_SKIP_TOOL_INSTALL("LUKS version", "cryptsetup");
            EMIT_SKIP_TOOL_INSTALL("LUKS dm-integrity", "cryptsetup");
            EMIT_SKIP_TOOL_INSTALL("LUKS TPM binding", "cryptsetup");
            EMIT_SKIP_TOOL_INSTALL("LUKS Secure Boot binding", "cryptsetup");
            EMIT_SKIP_TOOL_INSTALL("LUKS boot chain binding", "cryptsetup");
        } else if (!bythos_capture_argv_status_ex(lsblk_fstype_argv, lsblk_buf,
                                                    sizeof(lsblk_buf), &lsblk_status, &lsblk_truncated) ||
                   lsblk_status != 0) {
            EMIT_SKIP_EXEC("LUKS version", "lsblk");
            EMIT_SKIP_EXEC("LUKS dm-integrity", "lsblk");
            EMIT_SKIP_EXEC("LUKS TPM binding", "lsblk");
            EMIT_SKIP_EXEC("LUKS Secure Boot binding", "lsblk");
            EMIT_SKIP_EXEC("LUKS boot chain binding", "lsblk");
        } else if (lsblk_truncated) {
            EMIT_SKIP("LUKS version", SKIP_OUTPUT_UNPARSEABLE, "lsblk output truncated");
            EMIT_SKIP("LUKS dm-integrity", SKIP_OUTPUT_UNPARSEABLE, "lsblk output truncated");
            EMIT_SKIP("LUKS TPM binding", SKIP_OUTPUT_UNPARSEABLE, "lsblk output truncated");
            EMIT_SKIP("LUKS Secure Boot binding", SKIP_OUTPUT_UNPARSEABLE, "lsblk output truncated");
            EMIT_SKIP("LUKS boot chain binding", SKIP_OUTPUT_UNPARSEABLE, "lsblk output truncated");
        } else {
            size_t luks_found = 0;
            size_t luks_no_token = 0;
            size_t luks_token_noparsed = 0;
            size_t dump_ok = 0;
            size_t dump_failed = 0;
            size_t luks2_count = 0;
            size_t luks1_count = 0;
            size_t version_unknown_count = 0;
            size_t integrity_count = 0;
            uint32_t weakest_mask = 0xFFFFFFFFu;
            unsigned int weakest_popcount = 32u;
            uint32_t signed_weakest_mask = 0xFFFFFFFFu;
            unsigned int signed_weakest_popcount = 32u;
            size_t signed_policy_count = 0;
            size_t clevis_count = 0;
            bool any_token = false;
            char *line = lsblk_buf;

            while (*line != '\0') {
                char *eol = strchr(line, '\n');
                size_t line_len = eol != NULL ? (size_t)(eol - line) : strlen(line);

                /* lsblk -P line: PATH="/dev/..." FSTYPE="crypto_LUKS" */
                char row[512];
                size_t copy = line_len < sizeof(row) ? line_len : sizeof(row) - 1;
                memcpy(row, line, copy);
                row[copy] = '\0';

                char device_path[128] = {0};
                const char *ps = strstr(row, "PATH=\"");
                if (strstr(row, "FSTYPE=\"crypto_LUKS\"") != NULL && ps != NULL) {
                    ps += strlen("PATH=\"");
                    const char *pe = strchr(ps, '"');
                    if (pe != NULL && pe > ps && (size_t)(pe - ps) < sizeof(device_path)) {
                        snprintf(device_path, sizeof(device_path), "%.*s", (int)(pe - ps), ps);
                    }
                }

                if (device_path[0] != '\0') {
                    const char *dump_argv[] = {
                        "cryptsetup", "luksDump", device_path, NULL
                    };
                    char dump_buf[16384] = {0};
                    int dump_status = -1;
                    luks_found++;
                    if (bythos_capture_argv_status(
                            (const char *const *)dump_argv,
                            dump_buf, sizeof(dump_buf), &dump_status) &&
                        dump_status == 0) {
                        dump_ok++;

                        int version = bythos_parse_luks_version(dump_buf);
                        if (version == 2) luks2_count++;
                        else if (version == 1) luks1_count++;
                        else version_unknown_count++;

                        if (bythos_parse_luks_integrity(dump_buf)) {
                            integrity_count++;
                        }

                        if (strstr(dump_buf, "systemd-tpm2") != NULL) {
                            any_token = true;
                            uint32_t mask = 0;
                            if (bythos_parse_luks_pcr_mask(dump_buf, &mask)) {
                                uint32_t tmp = mask;
                                unsigned int pc = 0;
                                while (tmp) { pc += tmp & 1u; tmp >>= 1; }
                                if (pc < weakest_popcount) {
                                    weakest_popcount = pc;
                                    weakest_mask = mask;
                                }
                            } else if (bythos_luks_signed_policy_pcr_mask(dump_buf, &mask)) {
                                signed_policy_count++;
                                uint32_t tmp = mask;
                                unsigned int pc = 0;
                                while (tmp) { pc += tmp & 1u; tmp >>= 1; }
                                if (pc < signed_weakest_popcount) {
                                    signed_weakest_popcount = pc;
                                    signed_weakest_mask = mask;
                                }
                            } else {
                                luks_token_noparsed++;
                            }
                        } else if (strstr(dump_buf, "clevis") != NULL) {
                            clevis_count++;
                        } else {
                            luks_no_token++;
                        }
                    } else {
                        dump_failed++;
                    }
                }

                line = eol != NULL ? eol + 1 : line + line_len;
            }

            if (luks_found == 0) {
                EMIT_SKIP_SUBJECT("LUKS version", "LUKS volumes");
                EMIT_SKIP_SUBJECT("LUKS dm-integrity", "LUKS volumes");
                EMIT_SKIP_SUBJECT("LUKS TPM binding", "LUKS volumes");
                EMIT_SKIP_SUBJECT("LUKS Secure Boot binding", "LUKS volumes");
                EMIT_SKIP_SUBJECT("LUKS boot chain binding", "LUKS volumes");
            } else if (dump_ok == 0) {
                EMIT_SKIP_EXEC_ROOT("LUKS version", "cryptsetup");
                EMIT_SKIP_EXEC_ROOT("LUKS dm-integrity", "cryptsetup");
                EMIT_SKIP_EXEC_ROOT("LUKS TPM binding", "cryptsetup");
                EMIT_SKIP_EXEC_ROOT("LUKS Secure Boot binding", "cryptsetup");
                EMIT_SKIP_EXEC_ROOT("LUKS boot chain binding", "cryptsetup");
            } else {
                char detail[BYTHOS_DETAIL_MAX];

                if (dump_failed > 0) {
                    snprintf(detail, sizeof(detail),
                        "%zu of %zu %s unreadable by cryptsetup",
                        dump_failed, luks_found,
                        bythos_pl(luks_found, "volume", "volumes"));
                    EMIT_SKIP("LUKS version", SKIP_EXEC_FAILED, detail);
                } else if (version_unknown_count > 0) {
                    snprintf(detail, sizeof(detail),
                        "%zu %s with unparseable version",
                        version_unknown_count,
                        bythos_pl(version_unknown_count, "volume", "volumes"));
                    EMIT_SKIP("LUKS version", SKIP_OUTPUT_UNPARSEABLE, detail);
                } else if (luks1_count > 0) {
                    snprintf(detail, sizeof(detail),
                        "%zu LUKS1 %s; legacy format, no token support",
                        luks1_count,
                        bythos_pl(luks1_count, "volume", "volumes"));
                    EMIT("LUKS version", CHECK_WARN, detail);
                } else {
                    snprintf(detail, sizeof(detail),
                        "all %zu %s LUKS2",
                        luks2_count,
                        bythos_pl(luks2_count, "volume", "volumes"));
                    EMIT("LUKS version", CHECK_OK, detail);
                }

                if (dump_failed > 0) {
                    snprintf(detail, sizeof(detail),
                        "%zu of %zu %s unreadable by cryptsetup",
                        dump_failed, luks_found,
                        bythos_pl(luks_found, "volume", "volumes"));
                    EMIT_SKIP("LUKS dm-integrity", SKIP_EXEC_FAILED, detail);
                } else if (integrity_count == 0) {
                    EMIT_SKIP_NOT_CONF("LUKS dm-integrity", "dm-integrity");
                } else if (integrity_count == dump_ok) {
                    snprintf(detail, sizeof(detail),
                        "enabled on all %zu %s",
                        integrity_count,
                        bythos_pl(integrity_count, "volume", "volumes"));
                    EMIT("LUKS dm-integrity", CHECK_OK, detail);
                } else {
                    snprintf(detail, sizeof(detail),
                        "enabled on %zu of %zu %s",
                        integrity_count, dump_ok,
                        bythos_pl(dump_ok, "volume", "volumes"));
                    EMIT("LUKS dm-integrity", CHECK_WARN, detail);
                }

                if (!tpm_present) {
                    EMIT_SKIP_HW("LUKS TPM binding", "TPM");
                    EMIT_SKIP_HW("LUKS Secure Boot binding", "TPM");
                    EMIT_SKIP_HW("LUKS boot chain binding", "TPM");
                } else {
                    if (!any_token && clevis_count == 0) {
                        EMIT("LUKS TPM binding", CHECK_WARN, "no LUKS device has TPM2 token");
                    } else if (!any_token) {
                        EMIT_SKIP("LUKS TPM binding", SKIP_PROBE_INDETERMINATE,
                            "clevis token present; pin not inspectable via luksDump");
                    } else if (dump_failed > 0) {
                        snprintf(detail, sizeof(detail),
                            "TPM2 token found, but %zu of %zu %s unreadable",
                            dump_failed, luks_found,
                            bythos_pl(luks_found, "device", "devices"));
                        EMIT("LUKS TPM binding", CHECK_WARN, detail);
                    } else if (luks_no_token > 0 || clevis_count > 0) {
                        EMIT("LUKS TPM binding", CHECK_WARN, "at least one LUKS device without a systemd-tpm2 token");
                    } else {
                        snprintf(detail, sizeof(detail),
                            "TPM2 token on %zu %s",
                            luks_found, bythos_pl(luks_found, "device", "devices"));
                        EMIT("LUKS TPM binding", CHECK_OK, detail);
                    }

                    if (!any_token && clevis_count == 0) {
                        EMIT_SKIP("LUKS Secure Boot binding", SKIP_SUBJECT_ABSENT, "no TPM2 token to evaluate");
                        EMIT_SKIP("LUKS boot chain binding", SKIP_SUBJECT_ABSENT, "no TPM2 token to evaluate");
                    } else if (!any_token) {
                        EMIT_SKIP("LUKS Secure Boot binding", SKIP_PROBE_INDETERMINATE, "clevis binding; PCR policy not inspectable");
                        EMIT_SKIP("LUKS boot chain binding", SKIP_PROBE_INDETERMINATE, "clevis binding; PCR policy not inspectable");
                    } else if (dump_failed > 0) {
                        snprintf(detail, sizeof(detail),
                            "%zu of %zu %s unreadable by cryptsetup",
                            dump_failed, luks_found,
                            bythos_pl(luks_found, "device", "devices"));
                        EMIT_SKIP("LUKS Secure Boot binding", SKIP_EXEC_FAILED, detail);
                        EMIT_SKIP("LUKS boot chain binding", SKIP_EXEC_FAILED, detail);
                    } else if (weakest_mask == 0xFFFFFFFFu || weakest_mask == 0) {
                        if (signed_policy_count > 0) {
                            char pcr_str[64] = {0};
                            pcr_mask_to_str(signed_weakest_mask, pcr_str, sizeof(pcr_str));
                            snprintf(detail, sizeof(detail),
                                "signed policy (pubkey); PCRs: %s", pcr_str);
                            EMIT("LUKS Secure Boot binding", CHECK_OK, detail);
                            if ((signed_weakest_mask & PCR_BIT(11)) != 0) {
                                EMIT("LUKS boot chain binding", CHECK_OK,
                                    "signed policy; PCR 11 (UKI) measured");
                            } else {
                                snprintf(detail, sizeof(detail),
                                    "signed policy; PCRs: %s, PCR 11 (UKI) absent", pcr_str);
                                EMIT("LUKS boot chain binding", CHECK_WARN, detail);
                            }
                        } else {
                            EMIT_SKIP("LUKS Secure Boot binding", SKIP_OUTPUT_UNPARSEABLE, "PCR mask unreadable");
                            EMIT_SKIP("LUKS boot chain binding", SKIP_OUTPUT_UNPARSEABLE, "PCR mask unreadable");
                        }
                    } else {
                        bool has7 = (weakest_mask & PCR_BIT(7)) != 0;
                        bool has4 = (weakest_mask & PCR_BIT(4)) != 0;
                        bool has9 = (weakest_mask & PCR_BIT(9)) != 0;
                        bool has0 = (weakest_mask & PCR_BIT(0)) != 0;
                        char pcr_str[64] = {0};
                        pcr_mask_to_str(weakest_mask, pcr_str, sizeof(pcr_str));

                        if (!has7) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; PCR 7 absent, Secure Boot state unmeasured", pcr_str);
                            EMIT("LUKS Secure Boot binding", CHECK_WARN, detail);
                        } else if (luks_token_noparsed > 0) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; %zu %s PCR binding unreadable",
                                pcr_str, luks_token_noparsed,
                                bythos_pl(luks_token_noparsed, "device", "devices"));
                            EMIT("LUKS Secure Boot binding", CHECK_WARN, detail);
                        } else {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; Secure Boot state measured", pcr_str);
                            EMIT("LUKS Secure Boot binding", CHECK_OK, detail);
                        }

                        if (!has4 && !has9) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s only; bootloader and initramfs unprotected", pcr_str);
                            EMIT("LUKS boot chain binding", CHECK_WARN, detail);
                        } else if (!has4) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; bootloader (PCR 4) unmeasured", pcr_str);
                            EMIT("LUKS boot chain binding", CHECK_WARN, detail);
                        } else if (!has9) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; initramfs unprotected", pcr_str);
                            EMIT("LUKS boot chain binding", CHECK_WARN, detail);
                        } else if (luks_token_noparsed > 0) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; %zu %s PCR binding unreadable",
                                pcr_str, luks_token_noparsed,
                                bythos_pl(luks_token_noparsed, "device", "devices"));
                            EMIT("LUKS boot chain binding", CHECK_WARN, detail);
                        } else if (has0) {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; firmware and full boot chain measured", pcr_str);
                            EMIT("LUKS boot chain binding", CHECK_OK, detail);
                        } else {
                            snprintf(detail, sizeof(detail),
                                "PCRs: %s; boot chain measured", pcr_str);
                            EMIT("LUKS boot chain binding", CHECK_OK, detail);
                        }
                    }
                }
            }
        }
    }

    return used;
}
