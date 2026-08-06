/* Adversarial input for every exported parser. Build under ASan+UBSan. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "efi_boot_parsers.h"
#include "esp_parsers.h"
#include "firmware_parsers.h"
#include "silicon_parsers.h"
#include "storage_parsers.h"

static uint64_t rng_state = 0x243F6A8885A308D3ull;

static uint32_t rng(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 32);
}

#define BUF_MAX 4096

static void drive_binary(const unsigned char *data, size_t len) {
    bythos_efi_boot_order_t order;
    bythos_efi_boot_entry_t entry;
    uint16_t number = 0;
    char text[512];
    unsigned char out[1024];
    size_t out_len = 0;
    bythos_sbat_entry_t sbat[BYTHOS_SBAT_MAX_COMPONENTS];

    (void)bythos_parse_efi_boot_order(data, len, &order);
    (void)bythos_parse_efi_boot_entry(data, len, 1, &entry);
    (void)bythos_parse_efi_boot_next(data, len, &number);
    (void)bythos_count_efi_sigdb_lists(data, len);
    (void)bythos_parse_sbat_level(data, len, text, sizeof(text));
    (void)bythos_extract_pe_section(data, len, ".sbat", out, sizeof(out), &out_len);
    (void)bythos_parse_sbat_csv((const char *)data, len, sbat, BYTHOS_SBAT_MAX_COMPONENTS);
}

static void drive_text(const char *text) {
    char buf[256];
    bythos_sbctl_status_t sbctl;
    bythos_hsi_attribute_t hsi;
    bythos_iommu_cmdline_t iommu;
    bythos_lsblk_posture_t lsblk;
    bythos_mem_enc_flags_t mem;
    bythos_sbat_entry_t sbat[BYTHOS_SBAT_MAX_COMPONENTS];
    uint32_t mask = 0;

    (void)bythos_count_nonempty_lines(text);
    (void)bythos_extract_short_list_name(text, buf, sizeof(buf));
    (void)bythos_join_short_list_names(text, buf, sizeof(buf), 4, 16);
    (void)bythos_parse_secure_boot_state(text);
    (void)bythos_secure_boot_setup_mode(text);
    (void)bythos_secure_boot_validation_disabled(text);
    (void)bythos_parse_fwupd_updates(text, 0);
    (void)bythos_parse_fwupd_updates(text, 2);
    (void)bythos_parse_sbctl_status(text, &sbctl);
    (void)bythos_hsi_find_attribute(text, "org.fwupd.hsi.Tpm", &hsi);
    (void)bythos_sbat_entries_present(text);
    (void)bythos_sb_has_ms_ca(text);
    (void)bythos_parse_sbat_revocation_minimums(text, sbat, BYTHOS_SBAT_MAX_COMPONENTS);
    (void)bythos_esp_is_known_vendor(text);
    (void)bythos_parse_sha256sum_line(text, buf, sizeof(buf));
    bythos_parse_iommu_cmdline(text, &iommu);
    (void)bythos_extract_microcode_revision(text, buf, sizeof(buf));
    (void)bythos_parse_me_version(text, buf, sizeof(buf));
    (void)bythos_pcr_zero_check(text, 0);
    bythos_parse_memory_encryption_flags(text, &mem);
    bythos_parse_lsblk_posture(text, &lsblk);
    (void)bythos_parse_luks_pcr_mask(text, &mask);
    (void)bythos_luks_signed_policy_pcr_mask(text, &mask);
    (void)bythos_parse_luks_version(text);
    (void)bythos_parse_luks_integrity(text);
}

static const char *const SEEDS[] = {
    "",
    "\n",
    "SecureBoot enabled",
    "SecureBoot disabled",
    "Setup Mode\tEnabled",
    "Installed:\ttrue\nSetup Mode:\tDisabled\nSecure Boot:\tEnabled\n",
    "sbat,1,SBAT Version,sbat,1,https://x\nshim,4\ngrub,3\n",
    ("{\"HostSecurityAttributes\":[{\"AppstreamId\":\"org.fwupd.hsi.Tpm\","
     "\"HsiResult\":\"valid\",\"Flags\":[\"success\"]}]}"),
    "NAME TYPE FSTYPE MOUNTPOINT\nsda disk\nsda1 part crypto_LUKS /\n",
    "Version:       \t2\nCipher:  aes-xts-plain64\nintegrity: hmac-sha256\n",
    "cpu family\t: 6\nmicrocode\t: 0xf4\nflags\t\t: fpu sme sev\n",
    "0000: 00 00 00 00 00 00 00 00\n",
    "d41d8cd98f00b204e9800998ecf8427e  /boot/efi/EFI/BOOT/BOOTX64.EFI",
    "pcrs=0+2+4+7",
    "intel_iommu=on iommu=pt amd_iommu=on efi=disable_early_pci_dma",
};

int main(void) {
    unsigned char bin[BUF_MAX];
    char text[BUF_MAX];
    const size_t seed_count = sizeof(SEEDS) / sizeof(SEEDS[0]);

    /* every seed, and every truncation of every seed */
    for (size_t s = 0; s < seed_count; s++) {
        size_t full = strlen(SEEDS[s]);
        for (size_t cut = 0; cut <= full && cut < BUF_MAX; cut++) {
            memcpy(bin, SEEDS[s], cut);
            drive_binary(bin, cut);
            memcpy(text, SEEDS[s], cut);
            text[cut] = '\0';
            drive_text(text);
        }
    }

    /* structured EFI_SIGNATURE_LIST headers with hostile length fields */
    for (uint32_t trial = 0; trial < 40000; trial++) {
        size_t len = 4 + 28 + (rng() % 64);
        if (len > BUF_MAX) len = BUF_MAX;
        memset(bin, 0, len);
        for (size_t i = 0; i < len; i++) bin[i] = (unsigned char)rng();
        uint32_t sizes[] = {0, 1, 27, 28, 29, 0x7fffffffu, 0xffffffffu,
                            (uint32_t)len, (uint32_t)(len - 4), 16, 17, 48};
        size_t n = sizeof(sizes) / sizeof(sizes[0]);
        uint32_t ls = sizes[rng() % n], hs = sizes[rng() % n], ss = sizes[rng() % n];
        if (len >= 4 + 28) {
            memcpy(bin + 4 + 16, &ls, 4);
            memcpy(bin + 4 + 20, &hs, 4);
            memcpy(bin + 4 + 24, &ss, 4);
        }
        drive_binary(bin, len);
    }

    /* random bytes, every length class */
    for (uint32_t trial = 0; trial < 40000; trial++) {
        size_t len = rng() % BUF_MAX;
        for (size_t i = 0; i < len; i++) bin[i] = (unsigned char)rng();
        drive_binary(bin, len);

        size_t tlen = rng() % (BUF_MAX - 1);
        for (size_t i = 0; i < tlen; i++) {
            unsigned char c = (unsigned char)rng();
            text[i] = (char)(c == 0 ? ' ' : c);
        }
        text[tlen] = '\0';
        drive_text(text);
    }

    /* mutated seeds: bit flips and byte injection */
    for (uint32_t trial = 0; trial < 40000; trial++) {
        const char *seed = SEEDS[rng() % seed_count];
        size_t len = strlen(seed);
        if (len == 0 || len >= BUF_MAX - 1) continue;
        memcpy(text, seed, len + 1);
        size_t flips = 1 + (rng() % 8);
        for (size_t f = 0; f < flips; f++) {
            size_t pos = rng() % len;
            unsigned char c = (unsigned char)(text[pos] ^ (1u << (rng() % 8)));
            text[pos] = (char)(c == 0 ? ' ' : c);
        }
        drive_text(text);
        memcpy(bin, text, len);
        drive_binary(bin, len);
    }

    printf("fuzz parsers ok\n");
    return 0;
}
