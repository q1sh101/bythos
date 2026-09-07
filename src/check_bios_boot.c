#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "checks.h"
#include "checks_internal.h"
#include "efi_boot_parsers.h"
#include "runtime.h"

#define EFI_BOOT_ORDER_PATH "/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_BOOT_ENTRY_FMT  "/sys/firmware/efi/efivars/Boot%04X-8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_BOOT_NEXT_PATH  "/sys/firmware/efi/efivars/BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c"

static bool read_boot_entry(uint16_t number, bythos_efi_boot_entry_t *entry) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), EFI_BOOT_ENTRY_FMT, number) >= (int)sizeof(path)) {
        return false;
    }

    unsigned char buf[4096];
    size_t len = 0;
    bool truncated = false;
    if (!bythos_read_file_binary_ex(path, buf, sizeof(buf), &len, &truncated) || truncated) {
        return false;
    }

    return bythos_parse_efi_boot_entry(buf, len, number, entry);
}

static bool append_entry_id(char *list, size_t list_size, uint16_t id) {
    size_t used = strlen(list);
    const char *separator = used > 0 ? " " : "";
    char item[16];
    if (snprintf(item, sizeof(item), "%sBoot%04X", separator, id) >= (int)sizeof(item)) {
        return false;
    }
    size_t item_len = strlen(item);
    if (used + item_len >= list_size) {
        return false;
    }
    memcpy(list + used, item, item_len + 1);
    return true;
}

/* firmware-controlled text reaches the row unescaped: keep printable ASCII only, mark truncation */
#define BOOT_DESC_DISPLAY_MAX 40

static void display_description(const char *src, char *out, size_t out_size) {
    size_t limit = out_size - 1;
    size_t i = 0;
    for (; i < limit && src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        out[i] = (c >= 0x20 && c <= 0x7E) ? (char)c : '?';
    }
    out[i] = '\0';
    if (src[i] != '\0' && limit >= 3) {
        memcpy(out + limit - 3, "...", 4);
    }
}

static bool append_unclassified_entry(char *list, size_t list_size, uint16_t id,
                                      const char *description) {
    char desc[BOOT_DESC_DISPLAY_MAX];
    display_description(description, desc, sizeof(desc));

    size_t used = strlen(list);
    const char *separator = used > 0 ? " " : "";
    char item[24 + sizeof(desc)];
    int written = desc[0] != '\0'
        ? snprintf(item, sizeof(item), "%sBoot%04X \"%s\"", separator, id, desc)
        : snprintf(item, sizeof(item), "%sBoot%04X", separator, id);
    if (written < 0 || (size_t)written >= sizeof(item)) {
        return false;
    }
    if (used + (size_t)written >= list_size) {
        return false;
    }
    memcpy(list + used, item, (size_t)written + 1);
    return true;
}

static void append_text(char *out, size_t size, size_t *pos, const char *text) {
    if (*pos >= size) {
        return;
    }
    int written = snprintf(out + *pos, size - *pos, "%s", text);
    if (written < 0) {
        return;
    }
    *pos = ((size_t)written >= size - *pos) ? size - 1 : *pos + (size_t)written;
}

/* a cause list cut mid-claim would misstate what blocked the walk; fall back to the medium alone */
static void compose_blocked_detail(char *detail, size_t size, const char *blocked,
                                   const char *medium) {
    int written = snprintf(detail, size, "%s; %s presence unconfirmed", blocked, medium);
    if (written < 0 || (size_t)written >= size) {
        snprintf(detail, size, "boot order not fully inspected; %s presence unconfirmed",
                 medium);
    }
}

static void describe_incomplete_order(char *out, size_t size,
                                      const char *unreadable_entries, bool unreadable_all,
                                      const char *unclassified_entries, bool unclassified_all,
                                      bool capped) {
    size_t pos = 0;
    out[0] = '\0';
    append_text(out, size, &pos, "boot order not fully inspected");

    if (unreadable_entries[0] != '\0') {
        append_text(out, size, &pos, "; unreadable: ");
        append_text(out, size, &pos, unreadable_entries);
        if (!unreadable_all) {
            append_text(out, size, &pos, " and more");
        }
    }
    if (unclassified_entries[0] != '\0') {
        append_text(out, size, &pos, "; unclassified: ");
        append_text(out, size, &pos, unclassified_entries);
        if (!unclassified_all) {
            append_text(out, size, &pos, " and more");
        }
    }
    if (capped) {
        char shortened[48];
        snprintf(shortened, sizeof(shortened), "; list shortened at %d entries",
                 BYTHOS_EFI_BOOT_MAX_ENTRIES);
        append_text(out, size, &pos, shortened);
    }
}

static size_t check_efivars_boot(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (!bythos_file_exists("/sys/firmware/efi/efivars")) {
        EMIT_SKIP_FEATURE("EFI USB boot",      "EFI runtime");
        EMIT_SKIP_FEATURE("EFI network boot",  "EFI runtime");
        EMIT_SKIP_FEATURE("EFI CD/DVD boot",   "EFI runtime");
        EMIT_SKIP_FEATURE("EFI one-shot boot", "EFI runtime");
        return used;
    }

    unsigned char order_buf[256];
    size_t order_len = 0;

    if (!bythos_read_file_binary(EFI_BOOT_ORDER_PATH, order_buf,
                                     sizeof(order_buf), &order_len)) {
        EMIT_SKIP_FEATURE("EFI USB boot",      "BootOrder variable");
        EMIT_SKIP_FEATURE("EFI network boot",  "BootOrder variable");
        EMIT_SKIP_FEATURE("EFI CD/DVD boot",   "BootOrder variable");
        EMIT_SKIP_FEATURE("EFI one-shot boot", "BootOrder variable");
        return used;
    }

    bythos_efi_boot_order_t order = {0};
    if (!bythos_parse_efi_boot_order(order_buf, order_len, &order)) {
        EMIT_SKIP("EFI USB boot",      SKIP_OUTPUT_UNPARSEABLE, "BootOrder variable malformed");
        EMIT_SKIP("EFI network boot",  SKIP_OUTPUT_UNPARSEABLE, "BootOrder variable malformed");
        EMIT_SKIP("EFI CD/DVD boot",   SKIP_OUTPUT_UNPARSEABLE, "BootOrder variable malformed");
        EMIT_SKIP("EFI one-shot boot", SKIP_OUTPUT_UNPARSEABLE, "BootOrder variable malformed");
        return used;
    }

    /* Only active risky entries are a real posture signal. */
    bool usb_in_order = false;
    bool net_in_order = false;
    bool cd_in_order = false;
    char usb_entries[200] = {0};
    char net_entries[200] = {0};
    char cd_entries[200] = {0};
    bool usb_all_listed = true;
    bool net_all_listed = true;
    bool cd_all_listed = true;
    size_t unreadable = 0;
    size_t unclassified = 0;
    /* sized so both lists, "and more", the shortened clause and the medium clause fit one detail */
    char unreadable_entries[41] = {0};
    char unclassified_entries[64] = {0};
    bool unreadable_all_listed = true;
    bool unclassified_all_listed = true;
    bool order_capped = order.truncated;

    for (size_t i = 0; i < order.order_count; i++) {
        bythos_efi_boot_entry_t entry = {0};
        if (!read_boot_entry(order.order[i], &entry)) {
            unreadable++;
            if (!append_entry_id(unreadable_entries, sizeof(unreadable_entries),
                                 order.order[i])) {
                unreadable_all_listed = false;
            }
            continue;
        }

        if (!entry.active) {
            continue;
        }

        switch (entry.type) {
            case BYTHOS_EFI_BOOT_TYPE_USB:
                usb_in_order = true;
                if (!append_entry_id(usb_entries, sizeof(usb_entries), order.order[i])) {
                    usb_all_listed = false;
                }
                break;
            case BYTHOS_EFI_BOOT_TYPE_NETWORK:
                net_in_order = true;
                if (!append_entry_id(net_entries, sizeof(net_entries), order.order[i])) {
                    net_all_listed = false;
                }
                break;
            case BYTHOS_EFI_BOOT_TYPE_CD:
                cd_in_order = true;
                if (!append_entry_id(cd_entries, sizeof(cd_entries), order.order[i])) {
                    cd_all_listed = false;
                }
                break;
            case BYTHOS_EFI_BOOT_TYPE_UNKNOWN:
                unclassified++;
                if (!append_unclassified_entry(unclassified_entries,
                                               sizeof(unclassified_entries),
                                               order.order[i], entry.description)) {
                    unclassified_all_listed = false;
                }
                break;
            default:
                break;
        }
    }

    char blocked[BYTHOS_DETAIL_MAX] = {0};
    if (unreadable > 0 || order_capped || unclassified > 0) {
        describe_incomplete_order(blocked, sizeof(blocked),
                                  unreadable_entries, unreadable_all_listed,
                                  unclassified_entries, unclassified_all_listed,
                                  order_capped);
    }

    if (usb_in_order) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "active in EFI boot order: %s%s",
                 usb_entries, usb_all_listed ? "" : " and more");
        EMIT("EFI USB boot", CHECK_WARN, detail);
    } else if (blocked[0] != '\0') {
        char detail[BYTHOS_DETAIL_MAX];
        compose_blocked_detail(detail, sizeof(detail), blocked, "USB");
        EMIT_SKIP("EFI USB boot", SKIP_OUTPUT_UNPARSEABLE, detail);
    } else {
        EMIT("EFI USB boot", CHECK_OK, "no active entry in EFI boot order");
    }

    if (net_in_order) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "active in EFI boot order: %s%s",
                 net_entries, net_all_listed ? "" : " and more");
        EMIT("EFI network boot", CHECK_WARN, detail);
    } else if (blocked[0] != '\0') {
        char detail[BYTHOS_DETAIL_MAX];
        compose_blocked_detail(detail, sizeof(detail), blocked, "network");
        EMIT_SKIP("EFI network boot", SKIP_OUTPUT_UNPARSEABLE, detail);
    } else {
        EMIT("EFI network boot", CHECK_OK, "no active entry in EFI boot order");
    }

    if (cd_in_order) {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "active in EFI boot order: %s%s",
                 cd_entries, cd_all_listed ? "" : " and more");
        EMIT("EFI CD/DVD boot", CHECK_WARN, detail);
    } else if (blocked[0] != '\0') {
        char detail[BYTHOS_DETAIL_MAX];
        compose_blocked_detail(detail, sizeof(detail), blocked, "CD/DVD");
        EMIT_SKIP("EFI CD/DVD boot", SKIP_OUTPUT_UNPARSEABLE, detail);
    } else {
        EMIT("EFI CD/DVD boot", CHECK_OK, "no active entry in EFI boot order");
    }

    /* BootNext: one-shot override for the next reboot */
    {
        unsigned char next_buf[16];
        size_t next_len = 0;
        uint16_t next_number = 0;

        if (!bythos_file_exists(EFI_BOOT_NEXT_PATH)) {
            EMIT("EFI one-shot boot", CHECK_OK, "no boot override pending");
        } else if (!bythos_read_file_binary(EFI_BOOT_NEXT_PATH, next_buf,
                                                 sizeof(next_buf), &next_len) ||
                   !bythos_parse_efi_boot_next(next_buf, next_len, &next_number)) {
            EMIT("EFI one-shot boot", CHECK_WARN, "BootNext variable present but unreadable");
        } else {
            bythos_efi_boot_entry_t next_entry = {0};
            if (!read_boot_entry(next_number, &next_entry)) {
                EMIT("EFI one-shot boot", CHECK_WARN, "BootNext points to unreadable entry");
            } else if (next_entry.type == BYTHOS_EFI_BOOT_TYPE_USB) {
                EMIT("EFI one-shot boot", CHECK_WARN, "BootNext overrides to USB boot");
            } else if (next_entry.type == BYTHOS_EFI_BOOT_TYPE_NETWORK) {
                EMIT("EFI one-shot boot", CHECK_WARN, "BootNext overrides to network boot");
            } else if (next_entry.type == BYTHOS_EFI_BOOT_TYPE_CD) {
                EMIT("EFI one-shot boot", CHECK_WARN, "BootNext overrides to CD/DVD boot");
            } else {
                EMIT("EFI one-shot boot", CHECK_OK, "BootNext does not point to USB, network, or optical boot");
            }
        }
    }

    return used;
}

static bool name_matches_usb_boot(const char *name) {
    char lower[256];
    bythos_to_lower_ascii(name, lower, sizeof(lower));
    return strstr(lower, "usb") != NULL && strstr(lower, "boot") != NULL;
}

static size_t check_firmware_attrs_boot(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *base = "/sys/class/firmware-attributes";

    if (used >= max_results) {
        return used;
    }

    DIR *vendors = opendir(base);
    if (vendors == NULL) {
        EMIT_SKIP("BIOS USB boot", SKIP_FEATURE_ABSENT,
            "firmware-attributes not available; check BIOS manually");
        return used;
    }

    bool found = false;
    char value[64] = {0};
    struct dirent *vendor;

    while ((vendor = bythos_readdir_safe(vendors, NULL)) != NULL) {
        if (vendor->d_name[0] == '.') {
            continue;
        }

        char attrs_path[PATH_MAX];
        if (snprintf(attrs_path, sizeof(attrs_path), "%s/%s/attributes", base, vendor->d_name) >= (int)sizeof(attrs_path)) {
            continue;
        }

        DIR *attrs = opendir(attrs_path);
        if (attrs == NULL) {
            continue;
        }

        struct dirent *attr;
        while ((attr = bythos_readdir_safe(attrs, NULL)) != NULL) {
            if (attr->d_name[0] == '.') {
                continue;
            }

            if (!name_matches_usb_boot(attr->d_name)) {
                continue;
            }

            char val_path[PATH_MAX];
            if (snprintf(val_path, sizeof(val_path), "%s/%s/current_value", attrs_path, attr->d_name) >= (int)sizeof(val_path)) {
                continue;
            }

            if (bythos_read_file_text(val_path, value, sizeof(value))) {
                size_t vlen = strlen(value);
                while (vlen > 0 && isspace((unsigned char)value[vlen - 1])) {
                    value[--vlen] = '\0';
                }
                found = true;
                break;
            }
        }

        closedir(attrs);
        if (found) {
            break;
        }
    }

    closedir(vendors);

    if (!found) {
        EMIT_SKIP("BIOS USB boot", SKIP_FEATURE_ABSENT,
            "USB boot attribute not exposed; check BIOS manually");
        return used;
    }

    char lower_value[64];
    bythos_to_lower_ascii(value, lower_value, sizeof(lower_value));

    if (strstr(lower_value, "disable") != NULL) {
        results[used++] = make_result("BIOS USB boot", CHECK_OK, "disabled via firmware-attributes");
    } else if (strstr(lower_value, "enable") != NULL) {
        results[used++] = make_result("BIOS USB boot", CHECK_WARN, "enabled; consider disabling in BIOS");
    } else {
        char detail[BYTHOS_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "setting: %s", value);
        results[used++] = make_result("BIOS USB boot", CHECK_WARN, detail);
    }

    return used;
}

static size_t check_firmware_password(check_result_t *results, size_t max_results) {
    size_t used = 0;

    static const struct {
        const char *name;
        const char *field;
    } slots[] = {
        {"Firmware admin password",     "Administrator Password Status:"},
        {"Firmware power-on password",  "Power-On Password Status:"},
        {"Firmware keyboard password",  "Keyboard Password Status:"},
    };
    static const size_t slot_count = sizeof(slots) / sizeof(slots[0]);

    if (!bythos_command_exists("dmidecode")) {
        for (size_t i = 0; i < slot_count && used < max_results; i++) {
            EMIT_SKIP_TOOL_OR_UNTRUSTED(slots[i].name, "dmidecode", "dmidecode");
        }
        return used;
    }

    static const char *const dmidecode_argv[] = {"dmidecode", "-t", "24", NULL};
    char buf[2048] = {0};
    int exit_status = -1;

    bool captured = bythos_capture_argv_status(dmidecode_argv, buf, sizeof(buf), &exit_status);
    if (!captured || exit_status != 0) {
        bool needs_root = !captured ||
            strstr(buf, "Permission denied") != NULL ||
            strstr(buf, "must be root") != NULL ||
            strstr(buf, "requires root") != NULL;
        for (size_t i = 0; i < slot_count && used < max_results; i++) {
            if (needs_root) {
                EMIT_SKIP_EXEC_ROOT(slots[i].name, "dmidecode");
            } else {
                EMIT_SKIP_EXEC(slots[i].name, "dmidecode");
            }
        }
        return used;
    }

    bool table_present = strstr(buf, "DMI type 24") != NULL;

    for (size_t i = 0; i < slot_count && used < max_results; i++) {
        const char *pos = strstr(buf, slots[i].field);
        if (pos == NULL) {
            if (table_present) {
                EMIT_SKIP(slots[i].name, SKIP_REPORT_FIELD_ABSENT, "field not present");
            } else {
                EMIT_SKIP(slots[i].name, SKIP_FEATURE_ABSENT,
                    "DMI Type 24 not exposed by firmware; check BIOS manually");
            }
            continue;
        }
        pos += strlen(slots[i].field);
        while (*pos == ' ' || *pos == '\t') {
            pos++;
        }
        if ((size_t)((buf + sizeof(buf)) - pos) < 9) {
            EMIT_SKIP_PARSE(slots[i].name, "dmidecode");
            continue;
        }
        char term = pos[7];
        if (strncmp(pos, "Enabled", 7) == 0 &&
            (term == '\0' || term == '\n' || term == '\r' || term == ' ' || term == '\t')) {
            results[used++] = make_result(slots[i].name, CHECK_OK, "set");
        } else if (strncmp(pos, "Disabled", 8) == 0 &&
                   (pos[8] == '\0' || pos[8] == '\n' || pos[8] == '\r' ||
                    pos[8] == ' '  || pos[8] == '\t')) {
            results[used++] = make_result(slots[i].name, CHECK_WARN, "not set");
        } else {
            EMIT_SKIP_PARSE(slots[i].name, "dmidecode");
        }
    }

    return used;
}

static size_t check_efivars_immutable(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    if (!bythos_file_exists(EFI_BOOT_ORDER_PATH)) {
        EMIT_SKIP_FEATURE("EFI BootOrder immutable", "BootOrder variable");
        return used;
    }

    int fd = open(EFI_BOOT_ORDER_PATH, O_RDONLY);
    if (fd < 0) {
        EMIT_SKIP_EXEC("EFI BootOrder immutable", "BootOrder variable");
        return used;
    }

    unsigned int flags = 0;
    int ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
    close(fd);

    if (ret < 0) {
        EMIT_SKIP_EXEC("EFI BootOrder immutable", "immutable flag");
        return used;
    }

    if (flags & (unsigned int)FS_IMMUTABLE_FL) {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_OK,
            "flag set; the kernel refuses BootOrder writes while it holds");
    } else {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_WARN,
            "flag not set; the kernel does not refuse BootOrder writes; "
            "the flag would refuse them all, intended ones included");
    }
    return used;
}

size_t bythos_check_bios_boot(check_result_t *results, size_t max_results) {
    size_t used = 0;

    used += check_efivars_boot(results + used, used < max_results ? max_results - used : 0);
    used += check_efivars_immutable(results + used, used < max_results ? max_results - used : 0);
    used += check_firmware_attrs_boot(results + used, used < max_results ? max_results - used : 0);
    used += check_firmware_password(results + used, used < max_results ? max_results - used : 0);

    return used;
}
