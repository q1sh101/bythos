#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "efi_boot_parsers.h"
#include "runtime.h"

#define EFI_VAR_ATTR_SIZE 4
#define EFI_DP_END_TYPE 0x7F
#define EFI_DP_END_SUBTYPE 0xFF
#define EFI_DP_MSG_TYPE 0x03
#define EFI_DP_MEDIA_TYPE 0x04
#define EFI_DP_BBS_TYPE 0x05

#define EFI_DP_MSG_USB 0x05
#define EFI_DP_MSG_USB_CLASS 0x0F
#define EFI_DP_MSG_USB_WWID 0x10
#define EFI_DP_MSG_IPV4 0x0C
#define EFI_DP_MSG_IPV6 0x0D
#define EFI_DP_MSG_INFINIBAND 0x09
#define EFI_DP_MSG_MAC 0x0B
#define EFI_DP_MSG_URI 0x18

#define EFI_DP_MEDIA_HD 0x01
#define EFI_DP_MEDIA_CDROM 0x02
#define EFI_DP_MEDIA_FILEPATH 0x04

#define EFI_DP_BBS_BBS 0x01

#define BBS_TYPE_HD 0x02
#define BBS_TYPE_CD 0x03
#define BBS_TYPE_USB 0x05
#define BBS_TYPE_NETWORK 0x06
#define BBS_TYPE_BEV 0x80

static uint16_t read_le16(const unsigned char *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t read_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void utf16le_to_ascii(const unsigned char *src, size_t src_bytes,
                             char *dst, size_t dst_size) {
    size_t di = 0;
    for (size_t si = 0; si + 1 < src_bytes && di + 1 < dst_size; si += 2) {
        uint16_t code = read_le16(src + si);
        if (code == 0) {
            break;
        }
        dst[di++] = (code < 128) ? (char)code : '?';
    }
    dst[di] = '\0';
}

static bythos_efi_boot_type_t classify_device_path(const unsigned char *dp,
                                                        size_t dp_len) {
    size_t offset = 0;

    while (offset + 4 <= dp_len) {
        unsigned char type = dp[offset];
        unsigned char subtype = dp[offset + 1];
        uint16_t node_len = read_le16(dp + offset + 2);

        if (node_len < 4) {
            break;
        }

        if (type == EFI_DP_END_TYPE && subtype == EFI_DP_END_SUBTYPE) {
            break;
        }

        if (type == EFI_DP_BBS_TYPE && subtype == EFI_DP_BBS_BBS) {
            if (offset + 6 <= dp_len) {
                uint16_t bbs_type = read_le16(dp + offset + 4);
                switch (bbs_type) {
                    case BBS_TYPE_HD:
                        return BYTHOS_EFI_BOOT_TYPE_DISK;
                    case BBS_TYPE_CD:
                        return BYTHOS_EFI_BOOT_TYPE_CD;
                    case BBS_TYPE_USB:
                    case BBS_TYPE_BEV:
                        return BYTHOS_EFI_BOOT_TYPE_USB;
                    case BBS_TYPE_NETWORK:
                        return BYTHOS_EFI_BOOT_TYPE_NETWORK;
                    default:
                        break;
                }
            }
        }

        if (type == EFI_DP_MSG_TYPE) {
            switch (subtype) {
                case EFI_DP_MSG_USB:
                case EFI_DP_MSG_USB_CLASS:
                case EFI_DP_MSG_USB_WWID:
                    return BYTHOS_EFI_BOOT_TYPE_USB;
                case EFI_DP_MSG_IPV4:
                case EFI_DP_MSG_IPV6:
                case EFI_DP_MSG_INFINIBAND:
                case EFI_DP_MSG_MAC:
                case EFI_DP_MSG_URI:
                    return BYTHOS_EFI_BOOT_TYPE_NETWORK;
                default:
                    break;
            }
        }

        if (type == EFI_DP_MEDIA_TYPE) {
            switch (subtype) {
                case EFI_DP_MEDIA_HD:
                case EFI_DP_MEDIA_FILEPATH:
                    return BYTHOS_EFI_BOOT_TYPE_DISK;
                case EFI_DP_MEDIA_CDROM:
                    return BYTHOS_EFI_BOOT_TYPE_CD;
                default:
                    break;
            }
        }

        offset += node_len;
    }

    return BYTHOS_EFI_BOOT_TYPE_UNKNOWN;
}

static void dp_extract_filepath(const unsigned char *dp, size_t dp_len,
                                char *out, size_t out_size) {
    if (out_size == 0) {
        return;
    }
    out[0] = '\0';

    size_t used = 0;
    size_t offset = 0;
    while (offset + 4 <= dp_len) {
        unsigned char type = dp[offset];
        unsigned char subtype = dp[offset + 1];
        uint16_t node_len = read_le16(dp + offset + 2);

        if (node_len < 4 || offset + node_len > dp_len) {
            break;
        }
        if (type == EFI_DP_END_TYPE && subtype == EFI_DP_END_SUBTYPE) {
            break;
        }
        if (type == EFI_DP_MEDIA_TYPE && subtype == EFI_DP_MEDIA_FILEPATH) {
            char seg[256];
            utf16le_to_ascii(dp + offset + 4, (size_t)(node_len - 4), seg, sizeof(seg));
            for (size_t i = 0; seg[i] != '\0' && used + 1 < out_size; i++) {
                out[used++] = seg[i];
            }
            out[used] = '\0';
        }

        offset += node_len;
    }
}

static bythos_efi_boot_type_t classify_description(const char *desc) {
    char lower[128];
    bythos_to_lower_ascii(desc, lower, sizeof(lower));

    if (strstr(lower, "usb") != NULL || strstr(lower, "removable") != NULL) {
        return BYTHOS_EFI_BOOT_TYPE_USB;
    }
    if (strstr(lower, "network") != NULL || strstr(lower, "pxe") != NULL ||
        strstr(lower, "ipv4") != NULL || strstr(lower, "ipv6") != NULL ||
        strstr(lower, "lan") != NULL) {
        return BYTHOS_EFI_BOOT_TYPE_NETWORK;
    }
    if (strstr(lower, "cd") != NULL || strstr(lower, "dvd") != NULL) {
        return BYTHOS_EFI_BOOT_TYPE_CD;
    }

    return BYTHOS_EFI_BOOT_TYPE_UNKNOWN;
}

bool bythos_parse_efi_boot_order(const unsigned char *data, size_t len,
                                     bythos_efi_boot_order_t *order) {
    if (order == NULL) {
        return false;
    }

    *order = (bythos_efi_boot_order_t){0};

    if (data == NULL || len < 6) {
        return false;
    }

    const unsigned char *payload = data + EFI_VAR_ATTR_SIZE;
    size_t payload_len = len - EFI_VAR_ATTR_SIZE;
    size_t count = payload_len / 2;

    if (count > BYTHOS_EFI_BOOT_MAX_ENTRIES) {
        count = BYTHOS_EFI_BOOT_MAX_ENTRIES;
        order->truncated = true;
    }

    for (size_t i = 0; i < count; i++) {
        order->order[i] = read_le16(payload + i * 2);
    }

    order->order_count = count;
    return true;
}

bool bythos_parse_efi_boot_entry(const unsigned char *data, size_t len,
                                     uint16_t number,
                                     bythos_efi_boot_entry_t *entry) {
    if (entry == NULL) {
        return false;
    }

    *entry = (bythos_efi_boot_entry_t){0};
    entry->number = number;

    /* Boot#### must contain attributes, FilePathListLength, and a UTF-16 terminator. */
    if (data == NULL || len < 12) {
        return false;
    }

    const unsigned char *p = data + EFI_VAR_ATTR_SIZE;
    size_t remaining = len - EFI_VAR_ATTR_SIZE;

    uint32_t load_attrs = read_le32(p);
    entry->active = (load_attrs & 0x01) != 0;

    uint16_t fp_list_len = read_le16(p + 4);

    /* Load option text is UTF-16LE before the device path list. */
    const unsigned char *desc_start = p + 6;
    size_t desc_bytes = remaining - 6;

    size_t desc_end = 0;
    bool desc_terminated = false;
    for (size_t i = 0; i + 1 < desc_bytes; i += 2) {
        if (desc_start[i] == 0 && desc_start[i + 1] == 0) {
            desc_end = i;
            desc_terminated = true;
            break;
        }
        desc_end = i + 2;
    }

    utf16le_to_ascii(desc_start, desc_end, entry->description,
                     sizeof(entry->description));

    if (desc_terminated && fp_list_len > 0) {
        size_t dp_offset = 6 + desc_end + 2;
        if (dp_offset < remaining) {
            size_t dp_avail = remaining - dp_offset;
            if (dp_avail > fp_list_len) {
                dp_avail = fp_list_len;
            }
            entry->type = classify_device_path(p + dp_offset, dp_avail);
            dp_extract_filepath(p + dp_offset, dp_avail,
                                entry->filepath, sizeof(entry->filepath));
        }
    }

    if (entry->type == BYTHOS_EFI_BOOT_TYPE_UNKNOWN) {
        entry->type = classify_description(entry->description);
    }

    return true;
}

bool bythos_parse_efi_boot_next(const unsigned char *data, size_t len,
                                    uint16_t *number) {
    /* BootNext is EFI attributes plus one little-endian boot entry number. */
    if (data == NULL || number == NULL || len < EFI_VAR_ATTR_SIZE + 2) {
        return false;
    }

    *number = read_le16(data + EFI_VAR_ATTR_SIZE);
    return true;
}

bool bythos_parse_efi_bool_var(const unsigned char *data, size_t len, bool *value) {
    if (data == NULL || value == NULL || len != EFI_VAR_ATTR_SIZE + 1u) {
        return false;
    }
    unsigned char payload = data[EFI_VAR_ATTR_SIZE];
    if (payload > 1u) {
        return false;
    }
    *value = payload == 1u;
    return true;
}

size_t bythos_count_efi_sigdb_lists(const unsigned char *data, size_t len) {
    if (data == NULL || len <= EFI_VAR_ATTR_SIZE) {
        return 0;
    }

    const unsigned char *p = data + EFI_VAR_ATTR_SIZE;
    size_t remaining = len - EFI_VAR_ATTR_SIZE;
    size_t count = 0;

    while (remaining > 0) {
        if (remaining < 28) {
            return 0;
        }

        size_t list_size = read_le32(p + 16);
        size_t header_size = read_le32(p + 20);
        size_t signature_size = read_le32(p + 24);
        if (list_size < 28 || list_size > remaining) {
            return 0;
        }

        size_t body_size = list_size - 28;
        if (header_size > body_size) {
            return 0;
        }

        size_t payload_size = body_size - header_size;
        if (signature_size <= 16 || payload_size < signature_size ||
            payload_size % signature_size != 0) {
            return 0;
        }

        count++;
        p += list_size;
        remaining -= list_size;
    }

    return count;
}
