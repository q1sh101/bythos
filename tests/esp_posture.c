#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "esp_parsers.h"

int main(void) {
    assert_true("vendor_boot",        bythos_esp_is_known_vendor("boot"));
    assert_true("vendor_BOOT",        bythos_esp_is_known_vendor("BOOT"));
    assert_true("vendor_microsoft",   bythos_esp_is_known_vendor("Microsoft"));
    assert_true("vendor_ubuntu",      bythos_esp_is_known_vendor("ubuntu"));
    assert_true("vendor_arch",        bythos_esp_is_known_vendor("Arch"));
    assert_true("vendor_nixos",       bythos_esp_is_known_vendor("nixos"));
    assert_true("vendor_redhat",      bythos_esp_is_known_vendor("redhat"));
    assert_true("vendor_dell",        bythos_esp_is_known_vendor("Dell"));
    assert_false("vendor_rhel_old",   bythos_esp_is_known_vendor("rhel"));
    assert_false("vendor_unknown",    bythos_esp_is_known_vendor("attacker"));
    assert_false("vendor_empty",      bythos_esp_is_known_vendor(""));
    assert_false("vendor_null",       bythos_esp_is_known_vendor(NULL));

    char hash[128] = {0};

    assert_true("sha256sum_valid",
        bythos_parse_sha256sum_line(
            "a3c4e6f1b2d5a8c0e3f6b9d2a5c8e1f4b7d0a3c6e9f2b5d8a1c4e7f0b3d6a9c2  /boot/efi/EFI/BOOT/BOOTX64.EFI\n",
            hash, sizeof(hash)));
    assert_true("sha256sum_valid_value",
        strcmp(hash, "a3c4e6f1b2d5a8c0e3f6b9d2a5c8e1f4b7d0a3c6e9f2b5d8a1c4e7f0b3d6a9c2") == 0);

    assert_false("sha256sum_too_short",
        bythos_parse_sha256sum_line("abc123  /file\n", hash, sizeof(hash)));
    assert_false("sha256sum_no_separator",
        bythos_parse_sha256sum_line(
            "a3c4e6f1b2d5a8c0e3f6b9d2a5c8e1f4b7d0a3c6e9f2b5d8a1c4e7f0b3d6a9c2/file\n",
            hash, sizeof(hash)));
    assert_false("sha256sum_null",
        bythos_parse_sha256sum_line(NULL, hash, sizeof(hash)));
    assert_false("sha256sum_null_out",
        bythos_parse_sha256sum_line("abc  /f\n", NULL, sizeof(hash)));

    printf("esp posture ok\n");
    return 0;
}
