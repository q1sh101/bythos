/* EFI boot-order rows: what a skip says when the walk cannot finish.
   Runtime stubs below feed constructed BootOrder/Boot#### variables to the real parsers. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "checks.h"
#include "checks_internal.h"
#include "efi_boot_parsers.h"
#include "runtime.h"

/* room for an order longer than the program inspects, plus the entries that
   block the walk */
#define MAX_FAKE_ENTRIES 48

typedef struct {
    uint16_t id;
    bool readable;
    unsigned char buf[512];
    size_t len;
} fake_entry_t;

static fake_entry_t g_entries[MAX_FAKE_ENTRIES];
static size_t g_entry_count = 0;
static unsigned char g_order[4 + 2 * MAX_FAKE_ENTRIES];
static size_t g_order_len = 0;

bool bythos_command_exists(const char *name) { (void)name; return false; }
bool bythos_command_untrusted(const char *name) { (void)name; return false; }
bool bythos_capture_argv_status(const char *const argv[], char *buffer, size_t size,
                                int *exit_status) {
    (void)argv; (void)buffer; (void)size; *exit_status = 1; return false;
}
bool bythos_read_file_text(const char *path, char *buffer, size_t size) {
    (void)path; (void)buffer; (void)size; return false;
}
struct dirent *bythos_readdir_safe(DIR *dir, int *err_out) {
    (void)dir;
    if (err_out != NULL) *err_out = 0;
    return NULL;
}
void bythos_to_lower_ascii(const char *src, char *dst, size_t dst_size) {
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; i++) {
        char c = src[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    dst[i] = '\0';
}

bool bythos_file_exists(const char *path) {
    return strcmp(path, "/sys/firmware/efi/efivars") == 0;
}

bool bythos_read_file_binary(const char *path, unsigned char *buffer, size_t size,
                             size_t *bytes_read) {
    if (strstr(path, "BootOrder-") == NULL || g_order_len > size) {
        return false;
    }
    memcpy(buffer, g_order, g_order_len);
    *bytes_read = g_order_len;
    return true;
}

bool bythos_read_file_binary_ex(const char *path, unsigned char *buffer, size_t size,
                                size_t *bytes_read, bool *truncated) {
    *truncated = false;
    const char *name = strstr(path, "/Boot");
    unsigned int id = 0;
    if (name == NULL || sscanf(name, "/Boot%04X-", &id) != 1) {
        return false;
    }
    for (size_t i = 0; i < g_entry_count; i++) {
        if (g_entries[i].id != (uint16_t)id) {
            continue;
        }
        if (!g_entries[i].readable || g_entries[i].len > size) {
            return false;
        }
        memcpy(buffer, g_entries[i].buf, g_entries[i].len);
        *bytes_read = g_entries[i].len;
        return true;
    }
    return false;
}

static void reset_fixture(void) {
    memset(g_entries, 0, sizeof(g_entries));
    g_entry_count = 0;
    memset(g_order, 0, sizeof(g_order));
    g_order[0] = 0x07;
    g_order_len = 4;
}

static void order_push(uint16_t id) {
    if (g_order_len + 2 > sizeof(g_order)) {
        return;
    }
    g_order[g_order_len++] = (unsigned char)(id & 0xFF);
    g_order[g_order_len++] = (unsigned char)((id >> 8) & 0xFF);
}

/* EFI_LOAD_OPTION behind a 4-byte efivar attribute header: attributes, one
   device-path node of the given type, and a UTF-16LE description. */
static void add_entry(uint16_t id, bool active, const char *description,
                      unsigned char dp_type, unsigned char dp_subtype,
                      const uint16_t *desc_units, size_t desc_unit_count) {
    assert_true("fixture_entry_capacity", g_entry_count < MAX_FAKE_ENTRIES);
    fake_entry_t *e = &g_entries[g_entry_count++];
    size_t off = 0;
    e->id = id;
    e->readable = true;

    e->buf[off++] = 0x07; e->buf[off++] = 0x00; e->buf[off++] = 0x00; e->buf[off++] = 0x00;

    uint32_t attrs = active ? 1u : 0u;
    e->buf[off++] = (unsigned char)(attrs & 0xFF);
    e->buf[off++] = (unsigned char)((attrs >> 8) & 0xFF);
    e->buf[off++] = (unsigned char)((attrs >> 16) & 0xFF);
    e->buf[off++] = (unsigned char)((attrs >> 24) & 0xFF);

    uint16_t fp_list_len = 4 + 4;
    e->buf[off++] = (unsigned char)(fp_list_len & 0xFF);
    e->buf[off++] = (unsigned char)((fp_list_len >> 8) & 0xFF);

    if (desc_units != NULL) {
        for (size_t i = 0; i < desc_unit_count; i++) {
            e->buf[off++] = (unsigned char)(desc_units[i] & 0xFF);
            e->buf[off++] = (unsigned char)((desc_units[i] >> 8) & 0xFF);
        }
    } else {
        for (size_t i = 0; description[i] != '\0'; i++) {
            e->buf[off++] = (unsigned char)description[i];
            e->buf[off++] = 0x00;
        }
    }
    e->buf[off++] = 0x00; e->buf[off++] = 0x00;

    e->buf[off++] = dp_type;
    e->buf[off++] = dp_subtype;
    e->buf[off++] = 0x04;
    e->buf[off++] = 0x00;

    e->buf[off++] = 0x7F; e->buf[off++] = 0xFF;
    e->buf[off++] = 0x04; e->buf[off++] = 0x00;

    e->len = off;
    order_push(id);
}

/* device-path nodes: Media/HD classifies as disk, Messaging/USB as USB, and an
   unassigned Hardware node leaves the entry unclassified */
static void add_disk_entry(uint16_t id) { add_entry(id, true, "Linux", 0x04, 0x01, NULL, 0); }
static void add_usb_entry(uint16_t id)  { add_entry(id, true, "Removable", 0x03, 0x05, NULL, 0); }
static void add_unknown_entry(uint16_t id, const char *description) {
    add_entry(id, true, description, 0x02, 0x01, NULL, 0);
}
static void add_unreadable_entry(uint16_t id) {
    assert_true("fixture_entry_capacity", g_entry_count < MAX_FAKE_ENTRIES);
    g_entries[g_entry_count++].id = id;   /* readable stays false */
    order_push(id);
}

static const check_result_t *find_row(const check_result_t *results, size_t used,
                                      const char *name) {
    for (size_t i = 0; i < used; i++) {
        if (strcmp(results[i].name, name) == 0) {
            return &results[i];
        }
    }
    return NULL;
}

static void assert_row(const char *label, const char *name, check_state_t state,
                       skip_reason_t reason, const char *detail) {
    check_result_t results[32] = {0};
    size_t used = bythos_check_bios_boot(results, 32);
    const check_result_t *r = find_row(results, used, name);

    assert_true(label, r != NULL);
    if (r->state != state || r->skip_reason != reason || strcmp(r->detail, detail) != 0) {
        fprintf(stderr, "test failure: %s\n  got  state=%d skip=%d <%s>\n"
                        "  want state=%d skip=%d <%s>\n",
                label, (int)r->state, (int)r->skip_reason, r->detail,
                (int)state, (int)reason, detail);
        exit(1);
    }
    /* a skip carries a typed reason, a non-skip carries none */
    assert_true(label, (r->state == CHECK_SKIP) == (r->skip_reason != SKIP_NONE));
}

static void assert_row_shape(const char *label, const char *name) {
    check_result_t results[32] = {0};
    size_t used = bythos_check_bios_boot(results, 32);
    const check_result_t *r = find_row(results, used, name);

    assert_true(label, r != NULL);
    for (const char *p = r->detail; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c > 0x7E) {
            fprintf(stderr, "test failure: %s (byte 0x%02X in <%s>)\n", label, c, r->detail);
            exit(1);
        }
    }
    assert_true(label, strlen(r->detail) < BYTHOS_DETAIL_MAX);
}

int main(void) {
    /* a clean order still concludes */
    reset_fixture();
    add_disk_entry(0x0001);
    assert_row("clean_usb", "EFI USB boot", CHECK_OK, SKIP_NONE,
        "no active entry in EFI boot order");
    assert_row("clean_net", "EFI network boot", CHECK_OK, SKIP_NONE,
        "no active entry in EFI boot order");
    assert_row("clean_cd", "EFI CD/DVD boot", CHECK_OK, SKIP_NONE,
        "no active entry in EFI boot order");

    /* a risky active entry still warns with its entry list */
    reset_fixture();
    add_usb_entry(0x0003);
    assert_row("usb_warn", "EFI USB boot", CHECK_WARN, SKIP_NONE,
        "active in EFI boot order: Boot0003");

    /* an entry that defeated classification is named, with its description */
    reset_fixture();
    add_disk_entry(0x0001);
    add_unknown_entry(0x0000, "Windows Boot Manager");
    assert_row("unclassified_usb", "EFI USB boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; unclassified: Boot0000 \"Windows Boot Manager\"; "
        "USB presence unconfirmed");
    assert_row("unclassified_net", "EFI network boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; unclassified: Boot0000 \"Windows Boot Manager\"; "
        "network presence unconfirmed");
    assert_row("unclassified_cd", "EFI CD/DVD boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; unclassified: Boot0000 \"Windows Boot Manager\"; "
        "CD/DVD presence unconfirmed");

    /* an entry with no description at all is still named */
    reset_fixture();
    add_unknown_entry(0x000A, "");
    assert_row("unclassified_no_desc", "EFI USB boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; unclassified: Boot000A; USB presence unconfirmed");

    /* an unreadable entry reads differently from an unclassified one */
    reset_fixture();
    add_disk_entry(0x0001);
    add_unreadable_entry(0x0002);
    assert_row("unreadable_usb", "EFI USB boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; unreadable: Boot0002; USB presence unconfirmed");

    /* a shortened order blames no entry */
    reset_fixture();
    for (uint16_t i = 0; i < BYTHOS_EFI_BOOT_MAX_ENTRIES + 1; i++) {
        add_disk_entry((uint16_t)(0x0010 + i));
    }
    assert_row("capped_cd", "EFI CD/DVD boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; list shortened at 32 entries; "
        "CD/DVD presence unconfirmed");

    /* every cause at once, and a list too long to publish whole */
    reset_fixture();
    for (uint16_t i = 0; i < 6; i++) {
        add_unreadable_entry((uint16_t)(0x0020 + i));
    }
    add_unknown_entry(0x0000, "Windows Boot Manager");
    add_unknown_entry(0x0001, "Another Unclassifiable Entry");
    add_unknown_entry(0x0002, "Third Unclassifiable Entry");
    for (uint16_t i = 0; i < BYTHOS_EFI_BOOT_MAX_ENTRIES; i++) {
        add_disk_entry((uint16_t)(0x0100 + i));
    }
    assert_row("combined_usb", "EFI USB boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
        "boot order not fully inspected; "
        "unreadable: Boot0020 Boot0021 Boot0022 Boot0023 and more; "
        "unclassified: Boot0000 \"Windows Boot Manager\" and more; "
        "list shortened at 32 entries; USB presence unconfirmed");
    assert_row_shape("combined_shape", "EFI USB boot");

    /* firmware text cannot reshape the report */
    {
        static const uint16_t hostile[] = {
            'A', 0x000A, 0x000D, 0x001B, '[', '3', '1', 'm', 0x007F, 0x0001,
            '"', '\\', 0x00E9, 0x4E2D, 'B',
        };
        reset_fixture();
        add_entry(0x0004, true, NULL, 0x02, 0x01, hostile,
                  sizeof(hostile) / sizeof(hostile[0]));
        assert_row("hostile_desc", "EFI USB boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
            "boot order not fully inspected; "
            "unclassified: Boot0004 \"A???[31m??\"\\??B\"; USB presence unconfirmed");
        assert_row_shape("hostile_shape", "EFI USB boot");
    }

    /* an over-long description says it was shortened */
    {
        static const char long_desc[] =
            "0123456789012345678901234567890123456789012345678901234567890123456789";
        reset_fixture();
        add_unknown_entry(0x0005, long_desc);
        assert_row("long_desc", "EFI USB boot", CHECK_SKIP, SKIP_OUTPUT_UNPARSEABLE,
            "boot order not fully inspected; "
            "unclassified: Boot0005 \"012345678901234567890123456789012345...\"; "
            "USB presence unconfirmed");
        assert_row_shape("long_desc_shape", "EFI USB boot");
    }

    printf("bios boot ok\n");
    return 0;
}
