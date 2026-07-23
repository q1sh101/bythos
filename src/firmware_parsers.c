#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firmware_parsers.h"

#define BYTHOS_PE_MAX_SECTIONS 96
#define BYTHOS_PE_DOS_HEADER_BYTES 64
#define BYTHOS_PE_LFANEW_OFFSET 0x3C
#define BYTHOS_PE_COFF_HEADER_BYTES 20
#define BYTHOS_PE_SECTION_HEADER_BYTES 40
#define BYTHOS_PE_SECTION_NAME_BYTES 8
#define BYTHOS_HSI_FLAGS_BUFFER_BYTES 256

static const char *const SECURE_BOOT_ENABLED_TEXT = "enabled";
static const char *const SECURE_BOOT_DISABLED_TEXT = "disabled";
static const char *const SECURE_BOOT_SETUP_MODE_TEXT = "Setup Mode";
static const char *const SECURE_BOOT_VALIDATION_DISABLED_TEXT = "validation is disabled";
static const char *const FWUPD_NO_UPDATES_TEXT = "No updates available";
static const char *const SBCTL_INSTALLED_LABEL = "Installed:";
static const char *const SBCTL_SETUP_MODE_LABEL = "Setup Mode:";
static const char *const SBCTL_SECURE_BOOT_LABEL = "Secure Boot:";
static const char *const SBCTL_OWNER_GUID_LABEL = "Owner GUID:";
static const char *const SBCTL_VENDOR_KEYS_LABEL = "Vendor Keys:";
static const char *const SBCTL_NOT_INSTALLED_TEXT = "not installed";
static const char *const SBCTL_INSTALLED_TEXT = "installed";
static const char *const SBCTL_ENABLED_TEXT = "Enabled";
static const char *const SBCTL_DISABLED_TEXT = "Disabled";

static char *skip_label_value(char *text) {
    char *sep = strchr(text, ':');
    if (sep == NULL) {
        return NULL;
    }

    sep++;
    while (*sep != '\0' && isspace((unsigned char)*sep)) {
        sep++;
    }

    return *sep == '\0' ? NULL : sep;
}

static void trim_trailing(char *text) {
    size_t len = strlen(text);
    while (len > 0 && isspace((unsigned char)text[len - 1])) {
        text[len - 1] = '\0';
        len--;
    }
}

size_t bythos_count_nonempty_lines(const char *text) {
    if (text == NULL) {
        return 0;
    }

    size_t count = 0;
    bool in_line = false;

    for (const char *p = text; *p != '\0'; p++) {
        if (*p == '\n' || *p == '\r') {
            if (in_line) {
                count++;
                in_line = false;
            }
            continue;
        }

        if (*p != ' ' && *p != '\t') {
            in_line = true;
        }
    }

    if (in_line) {
        count++;
    }

    return count;
}

#define BYTHOS_JOIN_TRACK_MAX 16
#define BYTHOS_JOIN_TRACK_NAME 64
#define BYTHOS_JOIN_HASH_CHARS 8

size_t bythos_join_short_list_names(const char *text, char *buffer, size_t size,
                                       size_t max_names, size_t max_name_chars) {
    if (text == NULL || buffer == NULL || size == 0 || max_names == 0 || max_name_chars == 0) {
        return 0;
    }
    buffer[0] = '\0';

    if (max_names > BYTHOS_JOIN_TRACK_MAX) {
        max_names = BYTHOS_JOIN_TRACK_MAX;
    }

    const size_t tail_reserve = 32;
    if (size <= tail_reserve) {
        return 0;
    }
    const size_t emit_limit = size - tail_reserve;

    char emitted_names[BYTHOS_JOIN_TRACK_MAX][BYTHOS_JOIN_TRACK_NAME + 1];

    size_t emitted = 0;
    size_t total_seen = 0;
    size_t buf_used = 0;
    const char *cursor = text;

    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");

        const char *line_end = cursor + line_len;
        const char *p = cursor;
        while (p < line_end && (*p == ' ' || *p == '\t')) p++;

        const char *hash_start = p;
        const char *space = NULL;
        for (const char *q = p; q < line_end; q++) {
            if (*q == ' ' || *q == '\t') { space = q; break; }
        }

        if (p < line_end && space != NULL) {
            size_t hash_len = (size_t)(space - hash_start);
            const char *name = space;
            while (name < line_end && (*name == ' ' || *name == '\t')) name++;
            if (name < line_end) {
                size_t name_len = (size_t)(line_end - name);
                while (name_len > 0 &&
                       (name[name_len - 1] == ' ' || name[name_len - 1] == '\t' ||
                        name[name_len - 1] == '\r')) {
                    name_len--;
                }
                if (name_len > 0) {
                    total_seen++;
                    if (emitted < max_names) {
                        size_t copy = name_len < max_name_chars ? name_len : max_name_chars;
                        size_t track_copy = copy < BYTHOS_JOIN_TRACK_NAME ? copy : BYTHOS_JOIN_TRACK_NAME;

                        bool collision = false;
                        for (size_t e = 0; e < emitted; e++) {
                            if (strncmp(emitted_names[e], name, track_copy) == 0 &&
                                emitted_names[e][track_copy] == '\0') {
                                collision = true;
                                break;
                            }
                        }

                        char suffix[BYTHOS_JOIN_HASH_CHARS + 4] = {0};
                        size_t suffix_len = 0;
                        if (collision && hash_len > 0) {
                            size_t hash_copy = hash_len < BYTHOS_JOIN_HASH_CHARS
                                ? hash_len : BYTHOS_JOIN_HASH_CHARS;
                            int n = snprintf(suffix, sizeof(suffix), " [%.*s]",
                                             (int)hash_copy, hash_start);
                            if (n > 0 && (size_t)n < sizeof(suffix)) {
                                suffix_len = (size_t)n;
                            }
                        }

                        size_t sep_len = emitted > 0 ? 2 : 0;
                        if (buf_used + sep_len + copy + suffix_len + 1 < emit_limit) {
                            if (sep_len > 0) {
                                buffer[buf_used++] = ',';
                                buffer[buf_used++] = ' ';
                            }
                            memcpy(buffer + buf_used, name, copy);
                            buf_used += copy;
                            if (suffix_len > 0) {
                                memcpy(buffer + buf_used, suffix, suffix_len);
                                buf_used += suffix_len;
                            }
                            buffer[buf_used] = '\0';

                            memcpy(emitted_names[emitted], name, track_copy);
                            emitted_names[emitted][track_copy] = '\0';
                            emitted++;
                        }
                    }
                }
            }
        }

        cursor = line_end;
        while (*cursor == '\r' || *cursor == '\n') cursor++;
    }

    if (total_seen > emitted) {
        char tail[48];
        int n;
        if (emitted > 0) {
            n = snprintf(tail, sizeof(tail), " (and %zu more)", total_seen - emitted);
        } else {
            n = snprintf(tail, sizeof(tail), "%zu %s, none fit",
                         total_seen, total_seen == 1 ? "item" : "items");
        }
        if (n > 0 && (size_t)n < sizeof(tail) && buf_used + (size_t)n + 1 < size) {
            memcpy(buffer + buf_used, tail, (size_t)n);
            buf_used += (size_t)n;
            buffer[buf_used] = '\0';
        }
    }

    return total_seen;
}

bool bythos_extract_short_list_name(const char *text, char *buffer, size_t size) {
    if (text == NULL || buffer == NULL || size == 0) {
        return false;
    }

    buffer[0] = '\0';

    const char *line_end = strpbrk(text, "\r\n");
    size_t line_len = line_end == NULL ? strlen(text) : (size_t)(line_end - text);

    if (line_len == 0) {
        return false;
    }

    char line[512];
    if (line_len >= sizeof(line)) {
        line_len = sizeof(line) - 1;
    }

    memcpy(line, text, line_len);
    line[line_len] = '\0';

    char *name = strchr(line, ' ');
    if (name == NULL) {
        return false;
    }

    while (*name == ' ') {
        name++;
    }
    if (*name == '\0') {
        return false;
    }

    snprintf(buffer, size, "%s", name);
    return true;
}

bythos_secure_boot_status_t bythos_parse_secure_boot_state(const char *text) {
    if (text == NULL) {
        return BYTHOS_SECURE_BOOT_UNKNOWN;
    }

    if (strstr(text, SECURE_BOOT_ENABLED_TEXT) != NULL) {
        return BYTHOS_SECURE_BOOT_ENABLED;
    }
    if (strstr(text, SECURE_BOOT_DISABLED_TEXT) != NULL) {
        return BYTHOS_SECURE_BOOT_DISABLED;
    }
    return BYTHOS_SECURE_BOOT_UNKNOWN;
}

bool bythos_secure_boot_setup_mode(const char *text) {
    if (text == NULL) {
        return false;
    }

    return strstr(text, SECURE_BOOT_SETUP_MODE_TEXT) != NULL;
}

bool bythos_secure_boot_validation_disabled(const char *text) {
    if (text == NULL) {
        return false;
    }

    return strstr(text, SECURE_BOOT_VALIDATION_DISABLED_TEXT) != NULL;
}

bythos_fwupd_updates_status_t bythos_parse_fwupd_updates(const char *text, int exit_status) {
    if (text == NULL) {
        return BYTHOS_FWUPD_UPDATES_UNKNOWN;
    }

    if (strstr(text, FWUPD_NO_UPDATES_TEXT) != NULL) {
        return BYTHOS_FWUPD_UPDATES_NONE;
    }
    if (exit_status == 0) {
        return BYTHOS_FWUPD_UPDATES_AVAILABLE;
    }
    return BYTHOS_FWUPD_UPDATES_UNKNOWN;
}

static bool extract_quoted_value(const char *key_pos, size_t key_len,
                                 const char *bound,
                                 char *out, size_t out_size) {
    const char *colon = strchr(key_pos + key_len, ':');
    if (colon == NULL || colon >= bound) return false;
    const char *q1 = strchr(colon + 1, '"');
    if (q1 == NULL || q1 >= bound) return false;
    q1++;
    const char *q2 = strchr(q1, '"');
    if (q2 == NULL || q2 >= bound) return false;
    size_t vlen = (size_t)(q2 - q1);
    if (vlen >= out_size) vlen = out_size - 1;
    memcpy(out, q1, vlen);
    out[vlen] = '\0';
    return true;
}

bool bythos_hsi_find_attribute(const char *json, const char *appstream_id,
                                   bythos_hsi_attribute_t *out) {
    static const char APPSTREAM_ID_KEY[] = "\"AppstreamId\"";
    static const char HSI_RESULT_KEY[]   = "\"HsiResult\"";
    static const char HSI_SUCCESS_KEY[]  = "\"HsiResultSuccess\"";
    static const char FLAGS_KEY[]        = "\"Flags\"";

    if (json == NULL || appstream_id == NULL || out == NULL) {
        return false;
    }
    *out = (bythos_hsi_attribute_t){0};

    const char *cursor = json;
    while (*cursor != '\0') {
        const char *id_key = strstr(cursor, APPSTREAM_ID_KEY);
        if (id_key == NULL) break;

        const char *colon = strchr(id_key + sizeof(APPSTREAM_ID_KEY) - 1, ':');
        if (colon == NULL) break;
        const char *q1 = strchr(colon + 1, '"');
        if (q1 == NULL) break;
        q1++;
        const char *q2 = strchr(q1, '"');
        if (q2 == NULL) break;

        size_t id_len     = (size_t)(q2 - q1);
        size_t target_len = strlen(appstream_id);

        if (id_len == target_len && memcmp(q1, appstream_id, id_len) == 0) {
            const char *next_id = strstr(q2 + 1, APPSTREAM_ID_KEY);
            const char *bound = next_id != NULL ? next_id : q2 + strlen(q2);

            const char *hsi_key = strstr(q2 + 1, HSI_RESULT_KEY);
            if (hsi_key == NULL || hsi_key >= bound) return false;
            if (!extract_quoted_value(hsi_key, sizeof(HSI_RESULT_KEY) - 1,
                                       bound, out->result, sizeof(out->result))) {
                return false;
            }

            const char *succ_key = strstr(q2 + 1, HSI_SUCCESS_KEY);
            if (succ_key != NULL && succ_key < bound) {
                extract_quoted_value(succ_key, sizeof(HSI_SUCCESS_KEY) - 1,
                                     bound, out->success, sizeof(out->success));
            }

            const char *flags_key = strstr(q2 + 1, FLAGS_KEY);
            if (flags_key != NULL && flags_key < bound) {
                const char *open  = strchr(flags_key + sizeof(FLAGS_KEY) - 1, '[');
                const char *close = open != NULL ? strchr(open, ']') : NULL;
                if (open != NULL && close != NULL && close < bound) {
                    char arr[BYTHOS_HSI_FLAGS_BUFFER_BYTES];
                    size_t alen = (size_t)(close - open);
                    if (alen >= sizeof(arr)) alen = sizeof(arr) - 1;
                    memcpy(arr, open, alen);
                    arr[alen] = '\0';
                    if (strstr(arr, "action-contact-oem") != NULL) {
                        out->action = BYTHOS_HSI_ACTION_OEM;
                    } else if (strstr(arr, "action-config-fw") != NULL) {
                        out->action = BYTHOS_HSI_ACTION_FIRMWARE;
                    } else if (strstr(arr, "action-config-os") != NULL) {
                        out->action = BYTHOS_HSI_ACTION_OS;
                    }
                }
            }

            return true;
        }

        cursor = q2 + 1;
    }

    return false;
}

bool bythos_parse_sbctl_status(const char *text, bythos_sbctl_status_t *status) {
    if (text == NULL || status == NULL) {
        return false;
    }

    memset(status, 0, sizeof(*status));

    char line[256];
    const char *cursor = text;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }

        memcpy(line, cursor, line_len);
        line[line_len] = '\0';
        trim_trailing(line);

        char *value = skip_label_value(line);
        if (value != NULL) {
            if (strncmp(line, SBCTL_INSTALLED_LABEL, strlen(SBCTL_INSTALLED_LABEL)) == 0) {
                status->installed_known = true;
                if (strstr(value, SBCTL_NOT_INSTALLED_TEXT) != NULL) {
                    status->installed = false;
                } else if (strstr(value, SBCTL_INSTALLED_TEXT) != NULL) {
                    status->installed = true;
                } else {
                    status->installed_known = false;
                }
            } else if (strncmp(line, SBCTL_SETUP_MODE_LABEL, strlen(SBCTL_SETUP_MODE_LABEL)) == 0) {
                status->setup_mode_known = true;
                if (strstr(value, SBCTL_ENABLED_TEXT) != NULL) {
                    status->setup_mode_enabled = true;
                } else if (strstr(value, SBCTL_DISABLED_TEXT) != NULL) {
                    status->setup_mode_enabled = false;
                } else {
                    status->setup_mode_known = false;
                }
            } else if (strncmp(line, SBCTL_SECURE_BOOT_LABEL, strlen(SBCTL_SECURE_BOOT_LABEL)) == 0) {
                status->secure_boot_known = true;
                if (strstr(value, SBCTL_ENABLED_TEXT) != NULL) {
                    status->secure_boot_enabled = true;
                } else if (strstr(value, SBCTL_DISABLED_TEXT) != NULL) {
                    status->secure_boot_enabled = false;
                } else {
                    status->secure_boot_known = false;
                }
            } else if (strncmp(line, SBCTL_OWNER_GUID_LABEL, strlen(SBCTL_OWNER_GUID_LABEL)) == 0) {
                snprintf(status->owner_guid, sizeof(status->owner_guid), "%s", value);
                trim_trailing(status->owner_guid);
                status->owner_guid_present = status->owner_guid[0] != '\0';
            } else if (strncmp(line, SBCTL_VENDOR_KEYS_LABEL, strlen(SBCTL_VENDOR_KEYS_LABEL)) == 0) {
                snprintf(status->vendor_keys, sizeof(status->vendor_keys), "%s", value);
                trim_trailing(status->vendor_keys);
                status->vendor_keys_present = status->vendor_keys[0] != '\0';
            }
        }

        cursor += strcspn(cursor, "\r\n");
        while (*cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
    }

    return status->installed_known || status->setup_mode_known || status->secure_boot_known || status->owner_guid_present;
}

bool bythos_parse_sbat_level(const unsigned char *buf, size_t len,
                                 char *out, size_t out_size) {
    if (buf == NULL || out == NULL || out_size == 0 || len <= 4u) return false;
    const char *payload = (const char *)(buf + 4);
    size_t plen = len - 4u;
    size_t line_end = 0;
    while (line_end < plen && payload[line_end] != '\n' &&
           payload[line_end] != '\r' && payload[line_end] != '\0') {
        line_end++;
    }
    if (line_end == 0) return false;
    size_t copy = line_end < out_size - 1u ? line_end : out_size - 1u;
    memcpy(out, payload, copy);
    out[copy] = '\0';
    return true;
}

bool bythos_sbat_entries_present(const char *text) {
    if (text == NULL) return false;
    const char *t = text;
    while (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n') t++;
    if (*t == '\0') return false;
    if (strstr(text, "No SBAT") != NULL) return false;
    return true;
}

bool bythos_sb_has_ms_ca(const char *text) {
    if (text == NULL) return false;
    /* covers CN=Microsoft Corporation UEFI CA 2011 and CN=Microsoft UEFI CA 2023 */
    return strstr(text, "Microsoft Corporation UEFI CA") != NULL ||
           strstr(text, "Microsoft UEFI CA") != NULL;
}

static uint16_t pe_read_u16_le(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t pe_read_u32_le(const unsigned char *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

bool bythos_extract_pe_section(const unsigned char *bin, size_t bin_len,
                                  const char *section_name,
                                  unsigned char *out_buf, size_t out_buf_size,
                                  size_t *out_size) {
    if (bin == NULL || section_name == NULL || out_buf == NULL || out_buf_size == 0) {
        return false;
    }
    if (out_size != NULL) {
        *out_size = 0;
    }

    if (bin_len < BYTHOS_PE_DOS_HEADER_BYTES) return false;
    if (bin[0] != 'M' || bin[1] != 'Z') return false;

    uint32_t pe_offset = pe_read_u32_le(bin + BYTHOS_PE_LFANEW_OFFSET);
    if ((size_t)pe_offset > bin_len) return false;
    if ((size_t)pe_offset + 4u + BYTHOS_PE_COFF_HEADER_BYTES > bin_len) return false;

    const unsigned char *pe = bin + pe_offset;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) return false;

    const unsigned char *coff = pe + 4;
    uint16_t num_sections = pe_read_u16_le(coff + 2);
    uint16_t opt_size     = pe_read_u16_le(coff + 16);

    if (num_sections == 0 || num_sections > BYTHOS_PE_MAX_SECTIONS) return false;

    size_t section_table_offset = (size_t)pe_offset + 4u +
        BYTHOS_PE_COFF_HEADER_BYTES + (size_t)opt_size;
    if (section_table_offset > bin_len) return false;

    size_t section_table_bytes = (size_t)num_sections * BYTHOS_PE_SECTION_HEADER_BYTES;
    if (section_table_bytes > bin_len - section_table_offset) return false;

    size_t name_len = strlen(section_name);
    if (name_len == 0 || name_len > BYTHOS_PE_SECTION_NAME_BYTES) return false;

    for (uint16_t i = 0; i < num_sections; i++) {
        const unsigned char *hdr = bin + section_table_offset +
            (size_t)i * BYTHOS_PE_SECTION_HEADER_BYTES;

        bool match = true;
        for (size_t j = 0; j < BYTHOS_PE_SECTION_NAME_BYTES; j++) {
            char want = j < name_len ? section_name[j] : '\0';
            if ((char)hdr[j] != want) {
                match = false;
                break;
            }
        }
        if (!match) continue;

        uint32_t virtual_size     = pe_read_u32_le(hdr + 8);
        uint32_t size_of_raw_data = pe_read_u32_le(hdr + 16);
        uint32_t ptr_to_raw_data  = pe_read_u32_le(hdr + 20);

        /* VirtualSize is the meaningful payload; SizeOfRawData may include file padding. */
        uint32_t effective;
        if (virtual_size > 0 && virtual_size <= size_of_raw_data) {
            effective = virtual_size;
        } else {
            effective = size_of_raw_data;
        }
        if (effective == 0) return false;

        if ((size_t)ptr_to_raw_data > bin_len) return false;
        if ((size_t)effective > bin_len - (size_t)ptr_to_raw_data) return false;
        if ((size_t)effective > out_buf_size) return false;

        memcpy(out_buf, bin + ptr_to_raw_data, (size_t)effective);
        if (out_size != NULL) {
            *out_size = (size_t)effective;
        }
        return true;
    }
    return false;
}

size_t bythos_parse_sbat_csv(const char *text, size_t text_len,
                                bythos_sbat_entry_t *entries, size_t max_entries) {
    if (text == NULL || entries == NULL || max_entries == 0) return 0;

    size_t count = 0;
    size_t cursor = 0;
    while (cursor < text_len && count < max_entries) {
        if (text[cursor] == '\0') break;

        size_t line_start = cursor;
        size_t line_end = cursor;
        while (line_end < text_len &&
               text[line_end] != '\n' &&
               text[line_end] != '\r' &&
               text[line_end] != '\0') {
            line_end++;
        }
        cursor = line_end;
        if (cursor < text_len &&
            (text[cursor] == '\n' || text[cursor] == '\r')) {
            cursor++;
        }

        if (line_end == line_start) continue;

        size_t comma1 = line_start;
        while (comma1 < line_end && text[comma1] != ',') comma1++;
        if (comma1 == line_end) continue;

        size_t comp_len = comma1 - line_start;
        if (comp_len == 0 || comp_len >= BYTHOS_SBAT_COMPONENT_NAME_MAX) continue;

        size_t gen_start = comma1 + 1;
        size_t gen_end = gen_start;
        while (gen_end < line_end && text[gen_end] != ',') gen_end++;
        size_t gen_len = gen_end - gen_start;
        if (gen_len == 0 || gen_len > 16) continue;

        char gen_str[20];
        memcpy(gen_str, text + gen_start, gen_len);
        gen_str[gen_len] = '\0';

        if (gen_str[0] == '-' || gen_str[0] == '+') continue;

        char *endptr = NULL;
        unsigned long gen = strtoul(gen_str, &endptr, 10);
        if (endptr == NULL || *endptr != '\0') continue;
        if (gen > UINT_MAX) continue;

        memcpy(entries[count].component, text + line_start, comp_len);
        entries[count].component[comp_len] = '\0';
        entries[count].generation = (unsigned int)gen;
        count++;
    }
    return count;
}

size_t bythos_parse_sbat_revocation_minimums(const char *text,
                                                bythos_sbat_entry_t *entries,
                                                size_t max_entries) {
    if (text == NULL) return 0;
    return bythos_parse_sbat_csv(text, strlen(text), entries, max_entries);
}
