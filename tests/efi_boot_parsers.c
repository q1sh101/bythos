#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "efi_boot_parsers.h"

static void assert_type(const char *name, bythos_efi_boot_type_t got,
                         bythos_efi_boot_type_t expected) {
    if (got != expected) {
        fprintf(stderr, "efi boot parser failure: %s (got %d, expected %d)\n",
                name, (int)got, (int)expected);
        exit(1);
    }
}

static void put_le32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

/* Minimal Boot#### fixture with a legacy BBS device path. */
static size_t build_bbs_entry(unsigned char *buf, size_t buf_size,
                              uint32_t load_attrs, const char *desc_ascii,
                              uint16_t bbs_device_type) {
    size_t off = 0;

    buf[off++] = 0x07; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;

    buf[off++] = (unsigned char)(load_attrs & 0xFF);
    buf[off++] = (unsigned char)((load_attrs >> 8) & 0xFF);
    buf[off++] = (unsigned char)((load_attrs >> 16) & 0xFF);
    buf[off++] = (unsigned char)((load_attrs >> 24) & 0xFF);

    uint16_t fp_list_len = 8 + 4;
    buf[off++] = (unsigned char)(fp_list_len & 0xFF);
    buf[off++] = (unsigned char)((fp_list_len >> 8) & 0xFF);

    for (size_t i = 0; desc_ascii[i] != '\0' && off + 2 < buf_size; i++) {
        buf[off++] = (unsigned char)desc_ascii[i];
        buf[off++] = 0x00;
    }

    if (off + 14 > buf_size) {
        return off;
    }

    buf[off++] = 0x00; buf[off++] = 0x00;

    buf[off++] = 0x05;
    buf[off++] = 0x01;
    buf[off++] = 0x08;
    buf[off++] = 0x00;
    buf[off++] = (unsigned char)(bbs_device_type & 0xFF);
    buf[off++] = (unsigned char)((bbs_device_type >> 8) & 0xFF);
    buf[off++] = 0x00;
    buf[off++] = 0x00;

    buf[off++] = 0x7F;
    buf[off++] = 0xFF;
    buf[off++] = 0x04;
    buf[off++] = 0x00;

    return off;
}

/* Minimal Boot#### fixture with one typed device-path node. */
static size_t build_dp_entry(unsigned char *buf, size_t buf_size,
                             uint32_t load_attrs, const char *desc_ascii,
                             unsigned char dp_type, unsigned char dp_subtype) {
    size_t off = 0;

    buf[off++] = 0x07; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;

    buf[off++] = (unsigned char)(load_attrs & 0xFF);
    buf[off++] = (unsigned char)((load_attrs >> 8) & 0xFF);
    buf[off++] = (unsigned char)((load_attrs >> 16) & 0xFF);
    buf[off++] = (unsigned char)((load_attrs >> 24) & 0xFF);

    uint16_t fp_list_len = 4 + 4;
    buf[off++] = (unsigned char)(fp_list_len & 0xFF);
    buf[off++] = (unsigned char)((fp_list_len >> 8) & 0xFF);

    for (size_t i = 0; desc_ascii[i] != '\0' && off + 2 < buf_size; i++) {
        buf[off++] = (unsigned char)desc_ascii[i];
        buf[off++] = 0x00;
    }

    if (off + 10 > buf_size) {
        return off;
    }

    buf[off++] = 0x00; buf[off++] = 0x00;

    buf[off++] = dp_type;
    buf[off++] = dp_subtype;
    buf[off++] = 0x04;
    buf[off++] = 0x00;

    buf[off++] = 0x7F;
    buf[off++] = 0xFF;
    buf[off++] = 0x04;
    buf[off++] = 0x00;

    return off;
}

/* Boot#### fixture with a Media FilePath node carrying a UTF-16 path. */
static size_t build_filepath_entry(unsigned char *buf, size_t buf_size,
                                   const char *desc_ascii, const char *path_ascii) {
    size_t off = 0;
    size_t path_units = strlen(path_ascii) + 1;
    uint16_t node_len = (uint16_t)(4 + path_units * 2);
    uint16_t fp_list_len = (uint16_t)(node_len + 4);

    if (12 + strlen(desc_ascii) * 2 + node_len + 4 > buf_size) {
        return 0;
    }

    buf[off++] = 0x07; buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x01; buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = (unsigned char)(fp_list_len & 0xFF);
    buf[off++] = (unsigned char)((fp_list_len >> 8) & 0xFF);

    for (size_t i = 0; desc_ascii[i] != '\0'; i++) {
        buf[off++] = (unsigned char)desc_ascii[i];
        buf[off++] = 0x00;
    }
    buf[off++] = 0x00; buf[off++] = 0x00;

    buf[off++] = 0x04; buf[off++] = 0x04;
    buf[off++] = (unsigned char)(node_len & 0xFF);
    buf[off++] = (unsigned char)((node_len >> 8) & 0xFF);
    for (size_t i = 0; i < path_units; i++) {
        buf[off++] = (unsigned char)path_ascii[i];
        buf[off++] = 0x00;
    }

    buf[off++] = 0x7F; buf[off++] = 0xFF; buf[off++] = 0x04; buf[off++] = 0x00;
    return off;
}

static size_t append_filepath_node(unsigned char *buf, size_t off,
                                   const char *seg, int with_null) {
    size_t units = strlen(seg) + (with_null ? 1 : 0);
    uint16_t node_len = (uint16_t)(4 + units * 2);
    buf[off++] = 0x04; buf[off++] = 0x04;
    buf[off++] = (unsigned char)(node_len & 0xFF);
    buf[off++] = (unsigned char)((node_len >> 8) & 0xFF);
    for (size_t i = 0; seg[i] != '\0'; i++) {
        buf[off++] = (unsigned char)seg[i]; buf[off++] = 0x00;
    }
    if (with_null) { buf[off++] = 0x00; buf[off++] = 0x00; }
    return off;
}

int main(void) {
    bythos_efi_boot_order_t order = {0};
    bythos_efi_boot_entry_t entry = {0};
    unsigned char buf[512];
    size_t len;

    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x02, 0x00,
            0x00, 0x00,
            0x05, 0x00,
        };
        assert_true("boot_order_parse", bythos_parse_efi_boot_order(data, sizeof(data), &order));
        assert_eq_sz("boot_order_count", order.order_count, 3);
        assert_eq_u16("boot_order_0", order.order[0], 0x0002);
        assert_eq_u16("boot_order_1", order.order[1], 0x0000);
        assert_eq_u16("boot_order_2", order.order[2], 0x0005);
    }

    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x03, 0x00,
        };
        assert_true("boot_order_single", bythos_parse_efi_boot_order(data, sizeof(data), &order));
        assert_eq_sz("boot_order_single_count", order.order_count, 1);
    }

    {
        unsigned char data[] = {0x07, 0x00, 0x00, 0x00};
        assert_false("boot_order_empty", bythos_parse_efi_boot_order(data, sizeof(data), &order));
    }

    {
        unsigned char data[] = {0x07, 0x00};
        assert_false("boot_order_short", bythos_parse_efi_boot_order(data, sizeof(data), &order));
    }

    /* partition-based entry, how grub-install registers itself */
    len = build_dp_entry(buf, sizeof(buf), 0x01, "arch", 0x04, 0x01);
    assert_true("dp_hd_parse", bythos_parse_efi_boot_entry(buf, len, 0x0002, &entry));
    assert_type("dp_hd_type", entry.type, BYTHOS_EFI_BOOT_TYPE_DISK);
    assert_true("dp_hd_active", entry.active);

    /* BEV = CSM bootstrap entry vector, how removable USB appears with CSM on */
    len = build_bbs_entry(buf, sizeof(buf), 0x01, "UEFI:Removable Device", 0x80);
    assert_true("bbs_usb_parse", bythos_parse_efi_boot_entry(buf, len, 0x0004, &entry));
    assert_type("bbs_usb_type", entry.type, BYTHOS_EFI_BOOT_TYPE_USB);

    /* legacy PXE via BBS - load_attrs=0 means disabled in boot order */
    len = build_bbs_entry(buf, sizeof(buf), 0x00, "UEFI:Network Device", 0x06);
    assert_true("bbs_net_parse", bythos_parse_efi_boot_entry(buf, len, 0x0005, &entry));
    assert_type("bbs_net_type", entry.type, BYTHOS_EFI_BOOT_TYPE_NETWORK);
    assert_false("bbs_net_inactive", entry.active);

    /* UEFI-native USB messaging path, distinct from legacy BBS */
    len = build_dp_entry(buf, sizeof(buf), 0x01, "Some USB", 0x03, 0x05);
    assert_true("dp_usb_parse", bythos_parse_efi_boot_entry(buf, len, 0x0010, &entry));
    assert_type("dp_usb_type", entry.type, BYTHOS_EFI_BOOT_TYPE_USB);

    /* FilePath entries: shimx64.efi, bootmgfw.efi both register as this */
    len = build_dp_entry(buf, sizeof(buf), 0x01, "Windows Boot Manager", 0x04, 0x04);
    assert_true("dp_filepath_parse", bythos_parse_efi_boot_entry(buf, len, 0x0016, &entry));
    assert_type("dp_filepath_type", entry.type, BYTHOS_EFI_BOOT_TYPE_DISK);

    /* FilePath extraction: the booted binary path is recovered from the device path */
    len = build_filepath_entry(buf, sizeof(buf), "Arch", "\\EFI\\arch\\shimx64.efi");
    assert_true("filepath_parse", bythos_parse_efi_boot_entry(buf, len, 0x0002, &entry));
    assert_true("filepath_value",
        strcmp(entry.filepath, "\\EFI\\arch\\shimx64.efi") == 0);

    {
        unsigned char b2[512];
        size_t o = 0;
        b2[o++] = 0x07; b2[o++] = 0x00; b2[o++] = 0x00; b2[o++] = 0x00;
        b2[o++] = 0x01; b2[o++] = 0x00; b2[o++] = 0x00; b2[o++] = 0x00;
        size_t n1 = 4 + strlen("\\EFI\\arch\\") * 2;
        size_t n2 = 4 + (strlen("shimx64.efi") + 1) * 2;
        uint16_t fpl = (uint16_t)(n1 + n2 + 4);
        b2[o++] = (unsigned char)(fpl & 0xFF); b2[o++] = (unsigned char)((fpl >> 8) & 0xFF);
        b2[o++] = 'X'; b2[o++] = 0x00; b2[o++] = 0x00; b2[o++] = 0x00;
        o = append_filepath_node(b2, o, "\\EFI\\arch\\", 0);
        o = append_filepath_node(b2, o, "shimx64.efi", 1);
        b2[o++] = 0x7F; b2[o++] = 0xFF; b2[o++] = 0x04; b2[o++] = 0x00;
        assert_true("filepath_multinode_parse",
            bythos_parse_efi_boot_entry(b2, o, 0x0003, &entry));
        assert_true("filepath_multinode_value",
            strcmp(entry.filepath, "\\EFI\\arch\\shimx64.efi") == 0);
    }

    /* UEFI PXE over IPv4 - separate code path from BBS network */
    len = build_dp_entry(buf, sizeof(buf), 0x01, "PXE Boot", 0x03, 0x0C);
    assert_true("dp_ipv4_parse", bythos_parse_efi_boot_entry(buf, len, 0x0012, &entry));
    assert_type("dp_ipv4_type", entry.type, BYTHOS_EFI_BOOT_TYPE_NETWORK);

    /* unrecognized dp type - parser should fall back to description keywords */
    len = build_dp_entry(buf, sizeof(buf), 0x01, "USB Flash Drive", 0x01, 0x01);
    assert_true("desc_usb_parse", bythos_parse_efi_boot_entry(buf, len, 0x0020, &entry));
    assert_type("desc_usb_type", entry.type, BYTHOS_EFI_BOOT_TYPE_USB);

    {
        unsigned char short_data[] = {0x07, 0x00, 0x00, 0x00, 0x01, 0x00};
        assert_false("entry_short", bythos_parse_efi_boot_entry(short_data, sizeof(short_data), 0, &entry));
    }
    assert_false("entry_null_output", bythos_parse_efi_boot_entry(buf, len, 0, NULL));

    /* Non-ASCII UTF-16 should degrade to '?' without corrupting ASCII around it. */
    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x04, 0x00,
            0x41, 0x00,              /* 'A' */
            0x00, 0x01,              /* non-ASCII */
            0x42, 0x00,              /* 'B' */
            0x00, 0x00,
            0x7F, 0xFF, 0x04, 0x00,
        };
        assert_true("nonascii_parse", bythos_parse_efi_boot_entry(data, sizeof(data), 0x0040, &entry));
        assert_true("nonascii_desc_a", entry.description[0] == 'A');
        assert_true("nonascii_desc_q", entry.description[1] == '?');
        assert_true("nonascii_desc_b", entry.description[2] == 'B');
    }

    /* Empty text should still allow BBS classification from the device path. */
    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x08, 0x00,
            0x00, 0x00,
            0x05, 0x01, 0x08, 0x00,
            0x80, 0x00, 0x00, 0x00,
            0x7F, 0xFF, 0x04, 0x00,
        };
        assert_true("empty_desc_parse", bythos_parse_efi_boot_entry(data, sizeof(data), 0x0050, &entry));
        assert_true("empty_desc_str", entry.description[0] == '\0');
        assert_type("empty_desc_type", entry.type, BYTHOS_EFI_BOOT_TYPE_USB);
    }

    /* No device path at all; classifier should fall back to description. */
    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0x4E, 0x00, 0x65, 0x00, 0x74, 0x00,
            0x77, 0x00, 0x6F, 0x00, 0x72, 0x00,
            0x6B, 0x00,
            0x00, 0x00,
        };
        assert_true("no_dp_parse", bythos_parse_efi_boot_entry(data, sizeof(data), 0x0051, &entry));
        assert_type("no_dp_type", entry.type, BYTHOS_EFI_BOOT_TYPE_NETWORK);
    }

    /* trailing odd byte in BootOrder payload gets ignored */
    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x02, 0x00,
            0x00, 0x00,
            0xFF,        /* trailing odd byte */
        };
        assert_true("odd_order_parse", bythos_parse_efi_boot_order(data, sizeof(data), &order));
        assert_eq_sz("odd_order_count", order.order_count, 2);
    }

    /* Malformed dp node with length < 4 should not loop forever. */
    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x06, 0x00,
            0x58, 0x00, 0x00, 0x00,
            0x03, 0x0C, 0x02, 0x00,  /* len=2, below minimum */
            0x7F, 0xFF, 0x04, 0x00,
        };
        assert_true("malformed_dp_parse", bythos_parse_efi_boot_entry(data, sizeof(data), 0x0052, &entry));
        assert_type("malformed_dp_type", entry.type, BYTHOS_EFI_BOOT_TYPE_UNKNOWN);
    }

    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x07, 0x00,
        };
        uint16_t next_num = 0;
        assert_true("bootnext_parse", bythos_parse_efi_boot_next(data, sizeof(data), &next_num));
        assert_eq_u16("bootnext_value", next_num, 0x0007);
    }

    {
        unsigned char data[] = {0x07, 0x00, 0x00, 0x00, 0x03};
        uint16_t next_num = 0;
        assert_false("bootnext_short", bythos_parse_efi_boot_next(data, sizeof(data), &next_num));
    }

    {
        unsigned char data[] = {
            0x07, 0x00, 0x00, 0x00,
            0x00, 0x00,
        };
        uint16_t next_num = 0xFFFF;
        assert_true("bootnext_zero", bythos_parse_efi_boot_next(data, sizeof(data), &next_num));
        assert_eq_u16("bootnext_zero_value", next_num, 0x0000);
    }

    {
        unsigned char data[80] = {0x07, 0x00, 0x00, 0x00};
        size_t off = 4;
        for (size_t i = 0; i < 16; i++) data[off + i] = (unsigned char)i;
        put_le32(data + off + 16, 76);
        put_le32(data + off + 20, 0);
        put_le32(data + off + 24, 48);
        assert_eq_sz("sigdb_valid_one_list", bythos_count_efi_sigdb_lists(data, sizeof(data)), 1);
    }

    {
        unsigned char data[81] = {0x07, 0x00, 0x00, 0x00};
        size_t off = 4;
        for (size_t i = 0; i < 16; i++) data[off + i] = (unsigned char)i;
        put_le32(data + off + 16, 76);
        put_le32(data + off + 20, 0);
        put_le32(data + off + 24, 48);
        assert_eq_sz("sigdb_trailing_junk", bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);
    }

    {
        unsigned char data[32] = {0x07, 0x00, 0x00, 0x00};
        size_t off = 4;
        put_le32(data + off + 16, 28);
        put_le32(data + off + 20, 0);
        put_le32(data + off + 24, 48);
        assert_eq_sz("sigdb_zero_entry_list", bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);
    }

    {
        unsigned char data[] = {0x07, 0x00, 0x00, 0x00};
        assert_eq_sz("sigdb_empty", bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);
    }

    {
        bool value = true;
        unsigned char enabled[5] = {0x06, 0x00, 0x00, 0x00, 0x01};
        assert_true("efi_bool_enabled",
            bythos_parse_efi_bool_var(enabled, sizeof(enabled), &value) && value);

        unsigned char disabled[5] = {0x06, 0x00, 0x00, 0x00, 0x00};
        assert_true("efi_bool_disabled",
            bythos_parse_efi_bool_var(disabled, sizeof(disabled), &value) && !value);

        unsigned char attr_only[4] = {0x06, 0x00, 0x00, 0x00};
        assert_true("efi_bool_attr_only_refused",
            !bythos_parse_efi_bool_var(attr_only, sizeof(attr_only), &value));

        unsigned char too_long[6] = {0x06, 0x00, 0x00, 0x00, 0x01, 0x01};
        assert_true("efi_bool_oversized_refused",
            !bythos_parse_efi_bool_var(too_long, sizeof(too_long), &value));

        unsigned char out_of_range[5] = {0x06, 0x00, 0x00, 0x00, 0x02};
        assert_true("efi_bool_non_boolean_refused",
            !bythos_parse_efi_bool_var(out_of_range, sizeof(out_of_range), &value));

        assert_true("efi_bool_null_refused",
            !bythos_parse_efi_bool_var(NULL, 5, &value) &&
            !bythos_parse_efi_bool_var(enabled, sizeof(enabled), NULL));
    }

    {
        unsigned char data[4 + 28 + 48] = {0x07, 0x00, 0x00, 0x00};
        size_t off = 4;
        put_le32(data + off + 16, 27);
        put_le32(data + off + 20, 0);
        put_le32(data + off + 24, 48);
        assert_eq_sz("sigdb_list_size_below_header",
            bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);

        put_le32(data + off + 16, 28 + 48);
        put_le32(data + off + 20, 49);
        assert_eq_sz("sigdb_header_larger_than_body",
            bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);

        put_le32(data + off + 20, 0);
        put_le32(data + off + 24, 16);
        assert_eq_sz("sigdb_signature_size_at_guid_floor",
            bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);
    }

    {
        unsigned char data[4 + 60] = {0x07, 0x00, 0x00, 0x00};
        size_t off = 4;
        put_le32(data + off + 16, 60);
        put_le32(data + off + 20, 64);
        put_le32(data + off + 24, 32);
        assert_eq_sz("sigdb_header_past_body_is_not_a_key_list",
            bythos_count_efi_sigdb_lists(data, sizeof(data)), 0);
    }

    {
        unsigned char data[4 + 2 * (BYTHOS_EFI_BOOT_MAX_ENTRIES + 8)] = {0x07, 0x00, 0x00, 0x00};
        bythos_efi_boot_order_t order;
        assert_true("boot_order_capped_at_max_entries",
            bythos_parse_efi_boot_order(data, sizeof(data), &order) &&
            order.order_count == BYTHOS_EFI_BOOT_MAX_ENTRIES);
        assert_true("boot_order_reports_the_cap", order.truncated);

        unsigned char short_data[4 + 2 * 4] = {0x07, 0x00, 0x00, 0x00};
        assert_true("short_boot_order_is_not_truncated",
            bythos_parse_efi_boot_order(short_data, sizeof(short_data), &order) &&
            order.order_count == 4 && !order.truncated);

        unsigned char exact[4 + 2 * BYTHOS_EFI_BOOT_MAX_ENTRIES] = {0x07, 0x00, 0x00, 0x00};
        assert_true("exact_boot_order_is_not_truncated",
            bythos_parse_efi_boot_order(exact, sizeof(exact), &order) &&
            order.order_count == BYTHOS_EFI_BOOT_MAX_ENTRIES && !order.truncated);
    }

    {
        /* A device path node type the classifier does not know must stay
           UNKNOWN so the caller reports it instead of assuming it is safe. */
        static const unsigned char DP_NODES[][2] = {
            {0x03, 0x0A}, {0x03, 0x12}, {0x03, 0x17}, {0x03, 0x1A},
            {0x03, 0x1B}, {0x03, 0x1C}, {0x04, 0x09}, {0x01, 0x99},
        };
        for (size_t i = 0; i < sizeof(DP_NODES) / sizeof(DP_NODES[0]); i++) {
            unsigned char data[64] = {0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
            size_t o = 8;
            size_t fp_at = o;
            o += 2;
            const char *desc = "Recovery";
            for (const char *c = desc; *c != '\0'; c++) {
                data[o++] = (unsigned char)*c;
                data[o++] = 0;
            }
            data[o++] = 0;
            data[o++] = 0;
            size_t dp_start = o;
            data[o++] = DP_NODES[i][0];
            data[o++] = DP_NODES[i][1];
            data[o++] = 10;
            data[o++] = 0;
            o += 6;
            data[o++] = 0x7F;
            data[o++] = 0xFF;
            data[o++] = 4;
            data[o++] = 0;
            data[fp_at] = (unsigned char)(o - dp_start);

            bythos_efi_boot_entry_t entry;
            assert_true("unclassified_node_parses",
                bythos_parse_efi_boot_entry(data, o, 1, &entry));
            assert_true("unclassified_node_is_not_called_disk",
                entry.type == BYTHOS_EFI_BOOT_TYPE_UNKNOWN);
        }
    }

    printf("efi boot parser: all tests passed\n");
    return 0;
}
