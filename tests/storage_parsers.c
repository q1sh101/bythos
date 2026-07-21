#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "storage_parsers.h"

int main(void) {
    bythos_lsblk_posture_t posture = {0};

    bythos_parse_lsblk_posture(
        "NAME=\"nvme0n1p7\" TYPE=\"part\" FSTYPE=\"crypto_LUKS\"\n"
        "NAME=\"cryptroot\" TYPE=\"crypt\" FSTYPE=\"ext4\"\n",
        &posture
    );
    assert_eq_sz("luks_count", posture.luks_count, 1);
    assert_eq_sz("crypt_count", posture.crypt_count, 1);
    assert_eq_sz("crypt_swap_count_when_luks_present", posture.crypt_swap_count, 0);

    bythos_parse_lsblk_posture(
        "NAME=\"cryptswap\" TYPE=\"crypt\" FSTYPE=\"swap\"\n",
        &posture
    );
    assert_eq_sz("crypt_only_luks_count", posture.luks_count, 0);
    assert_eq_sz("crypt_only_crypt_count", posture.crypt_count, 1);
    assert_eq_sz("crypt_only_swap_count", posture.crypt_swap_count, 1);

    bythos_parse_lsblk_posture(
        "NAME=\"cryptdata\" TYPE=\"crypt\" FSTYPE=\"ext4\"\n",
        &posture
    );
    assert_eq_sz("crypt_data_luks_count", posture.luks_count, 0);
    assert_eq_sz("crypt_data_crypt_count", posture.crypt_count, 1);
    assert_eq_sz("crypt_data_swap_count", posture.crypt_swap_count, 0);

    bythos_parse_lsblk_posture(
        "NAME=\"nvme0n1p1\" TYPE=\"part\" FSTYPE=\"vfat\"\n"
        "NAME=\"nvme0n1p2\" TYPE=\"part\" FSTYPE=\"ext4\"\n",
        &posture
    );
    assert_eq_sz("plain_luks_count", posture.luks_count, 0);
    assert_eq_sz("plain_crypt_count", posture.crypt_count, 0);
    assert_eq_sz("plain_crypt_swap_count", posture.crypt_swap_count, 0);

    /* long line: >512 bytes should not split into multiple logical lines */
    {
        char long_input[1024];
        memset(long_input, 'X', sizeof(long_input));
        /* Keep marker early; this isolates cursor advancement after truncation. */
        const char *marker = "NAME=\"long\" TYPE=\"part\" FSTYPE=\"crypto_LUKS\"";
        size_t mlen = strlen(marker);
        memcpy(long_input, marker, mlen);
        long_input[sizeof(long_input) - 2] = '\n';
        long_input[sizeof(long_input) - 1] = '\0';

        bythos_parse_lsblk_posture(long_input, &posture);
        assert_eq_sz("long_line_luks_count", posture.luks_count, 1);
        assert_eq_sz("long_line_crypt_count", posture.crypt_count, 0);
    }

    uint32_t mask = 0;

    assert_true("pcr_pcr7_only",
        bythos_parse_luks_pcr_mask(
            "Tokens:\n  0: systemd-tpm2\n     Keyslot: 0\n     pcrs: 7\n",
            &mask));
    assert_eq_int("pcr_pcr7_only_value", (int)mask, (int)(1u << 7));

    assert_true("pcr_multi",
        bythos_parse_luks_pcr_mask(
            "Tokens:\n  0: systemd-tpm2\n     Keyslot: 0\n     pcrs: 0 4 7 9\n",
            &mask));
    assert_eq_int("pcr_multi_value", (int)mask,
        (int)((1u << 0) | (1u << 4) | (1u << 7) | (1u << 9)));

    assert_true("pcr_json_array",
        bythos_parse_luks_pcr_mask(
            "  0: systemd-tpm2\n     \"tpm2-pcrs\": [7, 9]\n",
            &mask));
    assert_eq_int("pcr_json_array_value", (int)mask,
        (int)((1u << 7) | (1u << 9)));

    assert_false("pcr_no_tpm2_token",
        bythos_parse_luks_pcr_mask(
            "Tokens:\n  0: clevis\n     Keyslot: 0\n     pcrs: 7\n",
            &mask));

    assert_false("pcr_no_pcrs_key",
        bythos_parse_luks_pcr_mask(
            "Tokens:\n  0: systemd-tpm2\n     Keyslot: 0\n",
            &mask));

    assert_false("pcr_null", bythos_parse_luks_pcr_mask(NULL, &mask));
    assert_false("pcr_null_out", bythos_parse_luks_pcr_mask("systemd-tpm2\n", NULL));

    {
        const char *raw =
            "Tokens:\n  0: systemd-tpm2\n"
            "\ttpm2-hash-pcrs:   7\n\ttpm2-pubkey:\n\t            (null)\n"
            "\ttpm2-pubkey-pcrs: \n";
        assert_true("pcr_hash_field", bythos_parse_luks_pcr_mask(raw, &mask));
        assert_eq_int("pcr_hash_field_value", (int)mask, (int)(1u << 7));
        assert_false("pcr_no_signed_policy",
            bythos_luks_signed_policy_pcr_mask(raw, &mask));

        const char *signed_pol =
            "  0: systemd-tpm2\n"
            "\ttpm2-hash-pcrs:   \n\ttpm2-pubkey:\n\t            MIIBpub\n"
            "\ttpm2-pubkey-pcrs: 11\n";
        assert_false("pcr_hash_empty_signed",
            bythos_parse_luks_pcr_mask(signed_pol, &mask));
        assert_true("signed_policy_present",
            bythos_luks_signed_policy_pcr_mask(signed_pol, &mask));
        assert_eq_int("signed_policy_value", (int)mask, (int)(1u << 11));

        const char *both =
            "  0: systemd-tpm2\n\ttpm2-hash-pcrs: 7\n\ttpm2-pubkey-pcrs: 11\n";
        bythos_parse_luks_pcr_mask(both, &mask);
        assert_eq_int("both_raw_is_7", (int)mask, (int)(1u << 7));
        bythos_luks_signed_policy_pcr_mask(both, &mask);
        assert_eq_int("both_signed_is_11", (int)mask, (int)(1u << 11));
    }

    assert_eq_int("version_luks2",
        bythos_parse_luks_version("LUKS header information\nVersion:        2\n"), 2);
    assert_eq_int("version_luks1",
        bythos_parse_luks_version("LUKS header information\nVersion:\t1\n"), 1);
    assert_eq_int("version_missing",
        bythos_parse_luks_version("LUKS header information\nUUID: abc\n"), 0);
    assert_eq_int("version_unknown_digit",
        bythos_parse_luks_version("Version: 9\n"), 0);
    assert_eq_int("version_null", bythos_parse_luks_version(NULL), 0);

    assert_true("integrity_present",
        bythos_parse_luks_integrity(
            "Data segments:\n  0: crypt\n        cipher: aes-xts-plain64\n        integrity: aead\n"));
    assert_false("integrity_absent",
        bythos_parse_luks_integrity(
            "Data segments:\n  0: crypt\n        cipher: aes-xts-plain64\n"));
    assert_false("integrity_key_does_not_match",
        bythos_parse_luks_integrity(
            "Keyslots:\n  0: luks2\n        integrity_key: 0 bits\n"));
    assert_false("integrity_null", bythos_parse_luks_integrity(NULL));

    printf("storage parsers ok\n");
    return 0;
}
