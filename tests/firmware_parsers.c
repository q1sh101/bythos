#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "assert_helpers.h"
#include "firmware_parsers.h"

static void emit_u16_le(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
}

static void emit_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
    p[2] = (unsigned char)((v >> 16) & 0xFFu);
    p[3] = (unsigned char)((v >> 24) & 0xFFu);
}

typedef struct {
    const char *name;
    const unsigned char *data;
    size_t data_len;
} pe_section_def_t;

static size_t build_pe(unsigned char *out, size_t out_size,
                       const pe_section_def_t *sections, size_t section_count,
                       int32_t raw_data_overflow) {
    const size_t pe_offset = 64;
    const size_t section_table_offset = pe_offset + 4 + 20;
    const size_t section_table_bytes = section_count * 40;
    const size_t headers_end = section_table_offset + section_table_bytes;

    size_t cursor = headers_end;
    if (cursor > out_size) return 0;

    memset(out, 0, headers_end);
    out[0] = 'M';
    out[1] = 'Z';
    emit_u32_le(out + 0x3C, (uint32_t)pe_offset);
    out[pe_offset]     = 'P';
    out[pe_offset + 1] = 'E';
    emit_u16_le(out + pe_offset + 4 + 2, (uint16_t)section_count);
    emit_u16_le(out + pe_offset + 4 + 16, 0);

    for (size_t i = 0; i < section_count; i++) {
        unsigned char *hdr = out + section_table_offset + i * 40;
        size_t name_len = strlen(sections[i].name);
        if (name_len > 8) name_len = 8;
        memcpy(hdr, sections[i].name, name_len);

        emit_u32_le(hdr + 8, (uint32_t)sections[i].data_len);
        emit_u32_le(hdr + 16, (uint32_t)sections[i].data_len);
        emit_u32_le(hdr + 20, (uint32_t)cursor);

        if (cursor + sections[i].data_len > out_size) return 0;
        memcpy(out + cursor, sections[i].data, sections[i].data_len);
        cursor += sections[i].data_len;
    }

    if (raw_data_overflow != 0 && section_count > 0) {
        unsigned char *hdr = out + section_table_offset + (section_count - 1) * 40;
        uint32_t inflated = (uint32_t)((int64_t)sections[section_count - 1].data_len + raw_data_overflow);
        emit_u32_le(hdr + 8, inflated);
        emit_u32_le(hdr + 16, inflated);
    }

    return cursor;
}

int main(void) {
    char owner[128] = {0};
    bythos_sbctl_status_t sbctl = {0};

    assert_eq_sz("count_nonempty_lines", bythos_count_nonempty_lines("a\n\nb\r\n  \n c\n"), 3);
    assert_true(
        "extract_short_list_name",
        bythos_extract_short_list_name("abcd123456 Example Platform Certificate\n", owner, sizeof(owner))
    );
    assert_true("extract_short_list_name_value", strcmp(owner, "Example Platform Certificate") == 0);
    assert_false("extract_short_list_name_null",
        bythos_extract_short_list_name(NULL, owner, sizeof(owner)));

    {
        char joined[256] = {0};

        assert_eq_sz("join_single",
            bythos_join_short_list_names("abcd123456 Microsoft Corporation UEFI CA\n",
                joined, sizeof(joined), 5, 32),
            1);
        assert_true("join_single_value",
            strcmp(joined, "Microsoft Corporation UEFI CA") == 0);

        assert_eq_sz("join_multi",
            bythos_join_short_list_names(
                "aaaa1111 Microsoft\n"
                "bbbb2222 Razer\n"
                "cccc3333 Ubuntu Shim\n",
                joined, sizeof(joined), 5, 32),
            3);
        assert_true("join_multi_value",
            strcmp(joined, "Microsoft, Razer, Ubuntu Shim") == 0);

        assert_eq_sz("join_truncate_count",
            bythos_join_short_list_names(
                "aaaa Name1\n"
                "bbbb Name2\n"
                "cccc Name3\n"
                "dddd Name4\n"
                "eeee Name5\n"
                "ffff Name6\n"
                "gggg Name7\n",
                joined, sizeof(joined), 3, 32),
            7);
        assert_true("join_truncate_value",
            strcmp(joined, "Name1, Name2, Name3 (and 4 more)") == 0);

        assert_eq_sz("join_empty",
            bythos_join_short_list_names("", joined, sizeof(joined), 5, 32),
            0);
        assert_true("join_empty_value", joined[0] == '\0');

        assert_eq_sz("join_per_name_truncate",
            bythos_join_short_list_names(
                "aaaa ThisNameIsExactlyThirtyTwoCharsLongPlus\n",
                joined, sizeof(joined), 5, 16),
            1);
        assert_true("join_per_name_truncate_value",
            strcmp(joined, "ThisNameIsExactl") == 0);

        assert_eq_sz("join_no_space",
            bythos_join_short_list_names("nospaceonline\n", joined, sizeof(joined), 5, 32),
            0);
    }

    assert_eq_int(
        "secure_boot_enabled",
        bythos_parse_secure_boot_state("SecureBoot enabled\n"),
        BYTHOS_SECURE_BOOT_ENABLED
    );
    assert_eq_int(
        "secure_boot_disabled",
        bythos_parse_secure_boot_state("SecureBoot disabled\n"),
        BYTHOS_SECURE_BOOT_DISABLED
    );
    assert_eq_int(
        "secure_boot_unknown",
        bythos_parse_secure_boot_state("something odd\n"),
        BYTHOS_SECURE_BOOT_UNKNOWN
    );
    assert_eq_int(
        "secure_boot_null",
        bythos_parse_secure_boot_state(NULL),
        BYTHOS_SECURE_BOOT_UNKNOWN
    );
    assert_true(
        "secure_boot_setup_mode_true",
        bythos_secure_boot_setup_mode("SecureBoot enabled\nPlatform is in Setup Mode\n")
    );
    assert_true(
        "secure_boot_setup_mode_false",
        !bythos_secure_boot_setup_mode("SecureBoot enabled\n")
    );
    assert_false("secure_boot_setup_mode_null",
        bythos_secure_boot_setup_mode(NULL));
    assert_true(
        "secure_boot_validation_disabled_true",
        bythos_secure_boot_validation_disabled(
            "SecureBoot enabled\nSecureBoot validation is disabled in shim\n")
    );
    assert_true(
        "secure_boot_validation_disabled_false",
        !bythos_secure_boot_validation_disabled("SecureBoot enabled\n")
    );
    assert_false("secure_boot_validation_disabled_null",
        bythos_secure_boot_validation_disabled(NULL));

    assert_eq_int(
        "fwupd_no_updates",
        bythos_parse_fwupd_updates("No updates available\n", 2),
        BYTHOS_FWUPD_UPDATES_NONE
    );
    assert_eq_int(
        "fwupd_updates_available",
        bythos_parse_fwupd_updates("Devices with firmware updates:\n", 0),
        BYTHOS_FWUPD_UPDATES_AVAILABLE
    );
    assert_eq_int(
        "fwupd_unknown",
        bythos_parse_fwupd_updates("Idle...\n", 1),
        BYTHOS_FWUPD_UPDATES_UNKNOWN
    );
    assert_eq_int(
        "fwupd_null",
        bythos_parse_fwupd_updates(NULL, 0),
        BYTHOS_FWUPD_UPDATES_UNKNOWN
    );

    assert_true(
        "sbctl_status_not_installed_parsed",
        bythos_parse_sbctl_status(
            "Installed:\tSbctl is not installed\n"
            "Setup Mode:\tEnabled\n"
            "Secure Boot:\tDisabled\n",
            &sbctl
        )
    );
    assert_true("sbctl_status_not_installed_known", sbctl.installed_known);
    assert_true("sbctl_status_not_installed_value", !sbctl.installed);
    assert_true("sbctl_status_setup_mode_known", sbctl.setup_mode_known);
    assert_true("sbctl_status_setup_mode_enabled", sbctl.setup_mode_enabled);
    assert_true("sbctl_status_secure_boot_known", sbctl.secure_boot_known);
    assert_true("sbctl_status_secure_boot_disabled", !sbctl.secure_boot_enabled);
    assert_true(
        "sbctl_status_installed_parsed",
        bythos_parse_sbctl_status(
            "Installed:\tSbctl is installed\n"
            "Owner GUID:\t11111111-2222-3333-4444-555555555555\n"
            "Setup Mode:\tDisabled\n"
            "Secure Boot:\tEnabled\n"
            "Vendor Keys:\tmicrosoft\n",
            &sbctl
        )
    );
    assert_true("sbctl_status_installed_value", sbctl.installed);
    assert_true("sbctl_status_owner_guid", strcmp(sbctl.owner_guid, "11111111-2222-3333-4444-555555555555") == 0);
    assert_true("sbctl_status_vendor_keys", strcmp(sbctl.vendor_keys, "microsoft") == 0);
    assert_true("sbctl_status_secure_boot_enabled", sbctl.secure_boot_enabled);

    static const char *const hsi_sample =
        "{\n"
        "  \"SecurityAttributes\" : [\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.PlatformFused\",\n"
        "      \"HsiResult\" : \"locked\",\n"
        "      \"HsiLevel\" : 3\n"
        "    },\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.Amd.SpiWriteProtection\",\n"
        "      \"HsiResult\" : \"enabled\",\n"
        "      \"HsiLevel\" : 4\n"
        "    },\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.PlatformDebugLocked\",\n"
        "      \"HsiResult\" : \"not-valid\",\n"
        "      \"HsiLevel\" : 2\n"
        "    },\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.EncryptedRam\",\n"
        "      \"HsiResult\" : \"not-supported\",\n"
        "      \"HsiLevel\" : 4\n"
        "    }\n"
        "  ]\n"
        "}\n";

    char hsi_val[64] = {0};

    assert_true("hsi_find_locked",
        bythos_hsi_find_result(hsi_sample, "org.fwupd.hsi.PlatformFused", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_locked_value", strcmp(hsi_val, "locked") == 0);

    hsi_val[0] = '\0';
    assert_true("hsi_find_enabled",
        bythos_hsi_find_result(hsi_sample, "org.fwupd.hsi.Amd.SpiWriteProtection", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_enabled_value", strcmp(hsi_val, "enabled") == 0);

    hsi_val[0] = '\0';
    assert_true("hsi_find_not_valid",
        bythos_hsi_find_result(hsi_sample, "org.fwupd.hsi.PlatformDebugLocked", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_not_valid_value", strcmp(hsi_val, "not-valid") == 0);

    hsi_val[0] = '\0';
    assert_true("hsi_find_not_supported",
        bythos_hsi_find_result(hsi_sample, "org.fwupd.hsi.EncryptedRam", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_not_supported_value", strcmp(hsi_val, "not-supported") == 0);

    hsi_val[0] = '\0';
    assert_false("hsi_find_absent",
        bythos_hsi_find_result(hsi_sample, "org.fwupd.hsi.IntelBootguard.Enabled", hsi_val, sizeof(hsi_val)));

    assert_false("hsi_null_json",
        bythos_hsi_find_result(NULL, "org.fwupd.hsi.PlatformFused", hsi_val, sizeof(hsi_val)));
    assert_false("hsi_null_id",
        bythos_hsi_find_result(hsi_sample, NULL, hsi_val, sizeof(hsi_val)));
    assert_false("hsi_null_buf",
        bythos_hsi_find_result(hsi_sample, "org.fwupd.hsi.PlatformFused", NULL, sizeof(hsi_val)));

    {
        /* Keep the target past the old read limit to catch truncation. */
        char big[24576] = {0};
        size_t off = 0;
        off += (size_t)snprintf(big + off, sizeof(big) - off,
            "{\"SecurityAttributes\":[");
        for (int i = 0; i < 60; i++) {
            off += (size_t)snprintf(big + off, sizeof(big) - off,
                "{\"AppstreamId\":\"org.fwupd.hsi.Pad%d\","
                "\"HsiResult\":\"not-supported\"},", i);
        }
        snprintf(big + off, sizeof(big) - off,
            "{\"AppstreamId\":\"org.fwupd.hsi.EncryptedRam\","
            "\"HsiResult\":\"not-supported\"}]}");

        hsi_val[0] = '\0';
        assert_true("hsi_late_attr_found",
            bythos_hsi_find_result(big, "org.fwupd.hsi.EncryptedRam", hsi_val, sizeof(hsi_val)));
        assert_true("hsi_late_attr_value", strcmp(hsi_val, "not-supported") == 0);
    }

    {
        static const char *const attr_sample =
            "{\"SecurityAttributes\":[\n"
            "  {\"AppstreamId\":\"org.fwupd.hsi.Amd.PlatformSecureBoot\","
            "   \"HsiResult\":\"not-enabled\","
            "   \"HsiResultSuccess\":\"enabled\","
            "   \"Flags\":[\"action-contact-oem\"]},\n"
            "  {\"AppstreamId\":\"org.fwupd.hsi.Uefi.SecureBoot\","
            "   \"HsiResult\":\"enabled\","
            "   \"HsiResultSuccess\":\"enabled\","
            "   \"Flags\":[\"success\"]},\n"
            "  {\"AppstreamId\":\"org.fwupd.hsi.Uefi.Db\","
            "   \"HsiResult\":\"not-valid\","
            "   \"HsiResultSuccess\":\"valid\","
            "   \"Flags\":[\"runtime-issue\",\"action-config-fw\"]},\n"
            "  {\"AppstreamId\":\"org.fwupd.hsi.Kernel.Swap\","
            "   \"HsiResult\":\"not-encrypted\","
            "   \"HsiResultSuccess\":\"encrypted\","
            "   \"Flags\":[\"action-config-os\"]}\n"
            "]}\n";

        bythos_hsi_attribute_t attr;

        assert_true("hsi_attr_oem_found",
            bythos_hsi_find_attribute(attr_sample, "org.fwupd.hsi.Amd.PlatformSecureBoot", &attr));
        assert_true("hsi_attr_oem_result",   strcmp(attr.result,  "not-enabled") == 0);
        assert_true("hsi_attr_oem_success",  strcmp(attr.success, "enabled")     == 0);
        assert_eq_int("hsi_attr_oem_action", (int)attr.action, (int)BYTHOS_HSI_ACTION_OEM);

        assert_true("hsi_attr_success_found",
            bythos_hsi_find_attribute(attr_sample, "org.fwupd.hsi.Uefi.SecureBoot", &attr));
        assert_eq_int("hsi_attr_success_action", (int)attr.action, (int)BYTHOS_HSI_ACTION_NONE);

        assert_true("hsi_attr_fw_found",
            bythos_hsi_find_attribute(attr_sample, "org.fwupd.hsi.Uefi.Db", &attr));
        assert_eq_int("hsi_attr_fw_action", (int)attr.action, (int)BYTHOS_HSI_ACTION_FIRMWARE);

        assert_true("hsi_attr_os_found",
            bythos_hsi_find_attribute(attr_sample, "org.fwupd.hsi.Kernel.Swap", &attr));
        assert_eq_int("hsi_attr_os_action", (int)attr.action, (int)BYTHOS_HSI_ACTION_OS);

        assert_false("hsi_attr_absent",
            bythos_hsi_find_attribute(attr_sample, "org.fwupd.hsi.Missing", &attr));
        assert_false("hsi_attr_null_json",
            bythos_hsi_find_attribute(NULL, "org.fwupd.hsi.Uefi.Db", &attr));
    }

    {
        /* SbatLevel efivar: 4-byte attr header + "sbat,1,2021030218\nshim,2\n" */
        unsigned char sbat_buf[32] = {0x07, 0x00, 0x00, 0x00,
            's','b','a','t',',','1',',','2','0','2','1','0','3','0','2','1','8','\n',
            's','h','i','m',',','2','\n'};
        char sbat_line[64] = {0};
        assert_true("sbat_parse_ok",
            bythos_parse_sbat_level(sbat_buf, 28, sbat_line, sizeof(sbat_line)));
        assert_true("sbat_parse_value", strcmp(sbat_line, "sbat,1,2021030218") == 0);

        assert_false("sbat_parse_too_short",
            bythos_parse_sbat_level(sbat_buf, 4, sbat_line, sizeof(sbat_line)));
        assert_false("sbat_parse_null",
            bythos_parse_sbat_level(NULL, 28, sbat_line, sizeof(sbat_line)));
        assert_false("sbat_parse_null_out",
            bythos_parse_sbat_level(sbat_buf, 28, NULL, sizeof(sbat_line)));

        /* exactly 5 bytes: 4-byte header + one content byte (no newline) */
        unsigned char sbat_min[5] = {0x07, 0x00, 0x00, 0x00, 'x'};
        assert_true("sbat_parse_no_newline",
            bythos_parse_sbat_level(sbat_min, 5, sbat_line, sizeof(sbat_line)));
        assert_true("sbat_parse_no_newline_value", strcmp(sbat_line, "x") == 0);
    }

    assert_true("sbat_entries_present",
        bythos_sbat_entries_present("sbat,1,2021030218\nshim,2\n"));
    assert_false("sbat_entries_empty",
        bythos_sbat_entries_present(""));
    assert_false("sbat_entries_whitespace",
        bythos_sbat_entries_present("  \n  "));
    assert_false("sbat_entries_no_sbat",
        bythos_sbat_entries_present("No SBAT data found.\n"));
    assert_false("sbat_entries_null",
        bythos_sbat_entries_present(NULL));

    assert_true("sb_has_ms_ca_2011",
        bythos_sb_has_ms_ca("CN=Microsoft Corporation UEFI CA 2011\n"));
    assert_true("sb_has_ms_ca_2023",
        bythos_sb_has_ms_ca("CN=Microsoft UEFI CA 2023\n"));
    assert_false("sb_no_ms_ca",
        bythos_sb_has_ms_ca("CN=My Custom CA\n"));
    assert_false("sb_ms_ca_null",
        bythos_sb_has_ms_ca(NULL));

    {
        static const char sbat_csv[] =
            "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"
            "shim,4,UEFI shim,shim,15.7-1,https://example\n"
            "grub,3,Free Software Foundation,grub,2.06,https://example\n"
            "grub.debian,4,Debian,grub2,2.06-13,https://example\n";

        unsigned char pe_buf[1024];
        pe_section_def_t single[] = {
            {".sbat", (const unsigned char *)sbat_csv, sizeof(sbat_csv) - 1}
        };
        size_t pe_len = build_pe(pe_buf, sizeof(pe_buf), single, 1, 0);
        assert_true("pe_build_minimal", pe_len > 0);

        unsigned char section_out[BYTHOS_SBAT_SECTION_MAX_BYTES];
        size_t section_out_len = 0;
        assert_true("pe_extract_sbat",
            bythos_extract_pe_section(pe_buf, pe_len, ".sbat",
                section_out, sizeof(section_out), &section_out_len));
        assert_eq_sz("pe_extract_sbat_len", section_out_len, sizeof(sbat_csv) - 1);
        assert_true("pe_extract_sbat_payload",
            memcmp(section_out, sbat_csv, sizeof(sbat_csv) - 1) == 0);

        bythos_sbat_entry_t entries[BYTHOS_SBAT_MAX_COMPONENTS];
        size_t parsed = bythos_parse_sbat_csv((const char *)section_out, section_out_len,
            entries, BYTHOS_SBAT_MAX_COMPONENTS);
        assert_eq_sz("csv_parse_count", parsed, 4);
        assert_true("csv_parse_sbat_name", strcmp(entries[0].component, "sbat") == 0);
        assert_true("csv_parse_sbat_gen", entries[0].generation == 1);
        assert_true("csv_parse_shim_name", strcmp(entries[1].component, "shim") == 0);
        assert_true("csv_parse_shim_gen", entries[1].generation == 4);
        assert_true("csv_parse_grub_name", strcmp(entries[2].component, "grub") == 0);
        assert_true("csv_parse_grub_gen", entries[2].generation == 3);
        assert_true("csv_parse_grub_debian_name",
            strcmp(entries[3].component, "grub.debian") == 0);
        assert_true("csv_parse_grub_debian_gen", entries[3].generation == 4);
    }

    {
        static const char malformed_csv[] =
            "shim,4,UEFI shim,shim,15.7,url\n"
            "grub,not_a_number,FSF,grub,2.06,url\n"
            "grub.debian,5,Debian,grub2,2.06-13,url\n";

        bythos_sbat_entry_t entries[BYTHOS_SBAT_MAX_COMPONENTS];
        size_t parsed = bythos_parse_sbat_csv(malformed_csv, sizeof(malformed_csv) - 1,
            entries, BYTHOS_SBAT_MAX_COMPONENTS);
        assert_eq_sz("csv_malformed_count", parsed, 2);
        assert_true("csv_malformed_first", strcmp(entries[0].component, "shim") == 0);
        assert_true("csv_malformed_second",
            strcmp(entries[1].component, "grub.debian") == 0);
        assert_true("csv_malformed_skipped_gen", entries[1].generation == 5);
    }

    {
        static const char rev_text[] =
            "sbat,1,2024010100\n"
            "shim,4\n"
            "grub,3\n"
            "grub.debian,4\n";

        bythos_sbat_entry_t entries[BYTHOS_SBAT_MAX_COMPONENTS];
        size_t parsed = bythos_parse_sbat_revocation_minimums(rev_text,
            entries, BYTHOS_SBAT_MAX_COMPONENTS);
        assert_eq_sz("rev_parse_count", parsed, 4);
        assert_true("rev_parse_sbat", strcmp(entries[0].component, "sbat") == 0);
        assert_true("rev_parse_sbat_gen", entries[0].generation == 1);
        assert_true("rev_parse_shim_gen", entries[1].generation == 4);
        assert_true("rev_parse_grub_gen", entries[2].generation == 3);
        assert_true("rev_parse_grub_debian_gen", entries[3].generation == 4);
    }

    {
        bythos_sbat_entry_t installed[3] = {
            {"shim", 4u, },
            {"grub", 3u, },
            {"grub.debian", 4u, },
        };
        bythos_sbat_entry_t revoked[2] = {
            {"shim", 4u, },
            {"grub.debian", 4u, },
        };

        bool any_violation = false;
        for (size_t i = 0; i < 3 && !any_violation; i++) {
            for (size_t j = 0; j < 2; j++) {
                if (strcmp(installed[i].component, revoked[j].component) != 0) continue;
                if (installed[i].generation < revoked[j].generation) {
                    any_violation = true;
                }
                break;
            }
        }
        assert_false("compare_ok_no_violation", any_violation);
    }

    {
        bythos_sbat_entry_t installed[2] = {
            {"shim", 4u, },
            {"grub.debian", 3u, },
        };
        bythos_sbat_entry_t revoked[2] = {
            {"shim", 4u, },
            {"grub.debian", 4u, },
        };

        bool any_violation = false;
        const char *failed_component = NULL;
        for (size_t i = 0; i < 2 && !any_violation; i++) {
            for (size_t j = 0; j < 2; j++) {
                if (strcmp(installed[i].component, revoked[j].component) != 0) continue;
                if (installed[i].generation < revoked[j].generation) {
                    any_violation = true;
                    failed_component = installed[i].component;
                }
                break;
            }
        }
        assert_true("compare_warn_violation_detected", any_violation);
        assert_true("compare_warn_failed_component",
            failed_component != NULL && strcmp(failed_component, "grub.debian") == 0);
    }

    {
        unsigned char pe_buf[512];
        pe_section_def_t no_sbat[] = {
            {".text", (const unsigned char *)"abcd", 4}
        };
        size_t pe_len = build_pe(pe_buf, sizeof(pe_buf), no_sbat, 1, 0);
        assert_true("pe_build_no_sbat", pe_len > 0);

        unsigned char section_out[BYTHOS_SBAT_SECTION_MAX_BYTES];
        size_t section_out_len = 0;
        assert_false("pe_extract_missing_sbat",
            bythos_extract_pe_section(pe_buf, pe_len, ".sbat",
                section_out, sizeof(section_out), &section_out_len));
        assert_eq_sz("pe_extract_missing_len_zero", section_out_len, 0);
    }

    {
        static const char sbat_csv[] = "shim,4,UEFI shim,shim,15.7,url\n";
        unsigned char pe_buf[1024];
        pe_section_def_t multi[] = {
            {".text", (const unsigned char *)"AAAA", 4},
            {".sbat", (const unsigned char *)sbat_csv, sizeof(sbat_csv) - 1},
            {".data", (const unsigned char *)"BBBB", 4},
        };
        size_t pe_len = build_pe(pe_buf, sizeof(pe_buf), multi, 3, 0);
        assert_true("pe_build_multi", pe_len > 0);

        unsigned char section_out[BYTHOS_SBAT_SECTION_MAX_BYTES];
        size_t section_out_len = 0;
        assert_true("pe_extract_multi_sbat_middle",
            bythos_extract_pe_section(pe_buf, pe_len, ".sbat",
                section_out, sizeof(section_out), &section_out_len));
        assert_eq_sz("pe_extract_multi_sbat_len", section_out_len, sizeof(sbat_csv) - 1);
        assert_true("pe_extract_multi_sbat_payload",
            memcmp(section_out, sbat_csv, sizeof(sbat_csv) - 1) == 0);
    }

    {
        static const char sbat_csv[] = "shim,4,UEFI shim,shim,15.7,url\n";
        unsigned char pe_buf[1024];
        pe_section_def_t single[] = {
            {".sbat", (const unsigned char *)sbat_csv, sizeof(sbat_csv) - 1}
        };
        size_t pe_len = build_pe(pe_buf, sizeof(pe_buf), single, 1, 4096);
        assert_true("pe_build_truncated", pe_len > 0);

        unsigned char section_out[BYTHOS_SBAT_SECTION_MAX_BYTES];
        size_t section_out_len = 0;
        assert_false("pe_extract_truncated_rejected",
            bythos_extract_pe_section(pe_buf, pe_len, ".sbat",
                section_out, sizeof(section_out), &section_out_len));
    }

    {
        unsigned char oversized_payload[BYTHOS_SBAT_SECTION_MAX_BYTES + 64];
        memset(oversized_payload, 'A', sizeof(oversized_payload));

        unsigned char pe_buf[BYTHOS_SBAT_SECTION_MAX_BYTES + 256];
        pe_section_def_t single[] = {
            {".sbat", oversized_payload, sizeof(oversized_payload)}
        };
        size_t pe_len = build_pe(pe_buf, sizeof(pe_buf), single, 1, 0);
        assert_true("pe_build_oversized", pe_len > 0);

        unsigned char section_out[BYTHOS_SBAT_SECTION_MAX_BYTES];
        size_t section_out_len = 999;
        assert_false("pe_extract_oversized_rejected",
            bythos_extract_pe_section(pe_buf, pe_len, ".sbat",
                section_out, sizeof(section_out), &section_out_len));
        assert_eq_sz("pe_extract_oversized_outsize_zero", section_out_len, 0);
    }

    {
        bythos_sbat_entry_t installed[3] = {
            {"shim", 4u, },
            {"grub", 2u, },
            {"grub.debian", 4u, },
        };
        bythos_sbat_entry_t revoked[2] = {
            {"shim", 4u, },
            {"grub", 3u, },
        };

        size_t failed_index = (size_t)-1;
        for (size_t i = 0; i < 3 && failed_index == (size_t)-1; i++) {
            unsigned int worst = 0;
            bool any_match = false;
            for (size_t j = 0; j < 2; j++) {
                if (strcmp(installed[i].component, revoked[j].component) != 0) continue;
                any_match = true;
                if (revoked[j].generation > worst) worst = revoked[j].generation;
            }
            if (any_match && installed[i].generation < worst) {
                failed_index = i;
            }
        }
        assert_true("compare_multi_failed_index", failed_index == 1);
        assert_true("compare_multi_failed_component",
            strcmp(installed[failed_index].component, "grub") == 0);
    }

    {
        bythos_sbat_entry_t installed[1] = { {"shim", 5u, } };
        bythos_sbat_entry_t revoked[3] = {
            {"shim", 4u, },
            {"grub", 9u, },
            {"shim", 6u, },
        };

        unsigned int worst = 0;
        bool any_match = false;
        for (size_t j = 0; j < 3; j++) {
            if (strcmp(installed[0].component, revoked[j].component) != 0) continue;
            any_match = true;
            if (revoked[j].generation > worst) worst = revoked[j].generation;
        }
        assert_true("compare_dup_any_match", any_match);
        assert_true("compare_dup_max_picked", worst == 6u);
        assert_true("compare_dup_violation_detected",
            installed[0].generation < worst);
    }

    printf("firmware parsers ok\n");
    return 0;
}
