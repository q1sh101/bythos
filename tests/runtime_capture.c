#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "assert_helpers.h"
#include "test_harness.h"
#include "runtime.h"

static void assert_state(const char *name, bythos_service_state_t want, bythos_service_state_t got) {
    if (want != got) {
        fprintf(stderr, "runtime capture failure: %s expected state %d, got %d\n", name, (int)want, (int)got);
        exit(1);
    }
}

static void assert_service_probe_with_script(
    const char *name,
    const char *script,
    bythos_service_state_t expected
) {
    char template[] = "./tmp-bythos-runtime-XXXXXX";
    char script_path[PATH_MAX];
    char *dir = mkdtemp(template);
    if (dir == NULL) {
        fprintf(stderr, "runtime capture failure: could not create temp dir for %s\n", name);
        exit(1);
    }

    snprintf(script_path, sizeof(script_path), "%s/systemctl", dir);
    write_executable(script_path, script);

    const char *path = getenv("BYTHOS_PATH");
    char *saved_path = path == NULL ? NULL : strdup(path);
    if (path != NULL && saved_path == NULL) {
        fprintf(stderr, "runtime capture failure: could not save BYTHOS_PATH\n");
        exit(1);
    }

    if (setenv("BYTHOS_PATH", dir, 1) != 0) {
        fprintf(stderr, "runtime capture failure: could not override BYTHOS_PATH\n");
        free(saved_path);
        exit(1);
    }

    bythos_service_state_t got = bythos_probe_systemd_service("mock.service");
    restore_env("BYTHOS_PATH", saved_path);

    unlink(script_path);
    rmdir(dir);

    assert_state(name, expected, got);
}

int main(void) {
    static char payload[131072];
    char buffer[64] = {0};
    char value[64] = {0};
    int exit_status = -1;

    memset(payload, 'A', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';

    const char *const argv[] = {"/usr/bin/printf", "%s", payload, NULL};

    assert_true(
        "capture_large_output",
        bythos_capture_argv_status(argv, buffer, sizeof(buffer), &exit_status)
    );
    assert_eq_int("capture_large_output_exit_status", exit_status, 0);
    assert_eq_int("capture_large_output_truncated_length", (int)strlen(buffer), (int)sizeof(buffer) - 1);

    for (size_t i = 0; i < sizeof(buffer) - 1; i++) {
        if (buffer[i] != 'A') {
            fprintf(stderr, "runtime capture failure: unexpected byte at %zu\n", i);
            return 1;
        }
    }

    assert_true(
        "read_key_value_quoted_false",
        bythos_read_key_value("tests/fixtures/runtime/key_values.conf", "usb-protection", value, sizeof(value))
    );
    assert_true("read_key_value_quoted_false_value", strcmp(value, "false") == 0);

    assert_true(
        "read_key_value_single_quoted_true",
        bythos_read_key_value("tests/fixtures/runtime/key_values.conf", "autorun-never", value, sizeof(value))
    );
    assert_true("read_key_value_single_quoted_true_value", strcmp(value, "true") == 0);

    assert_true(
        "read_key_value_plain_true",
        bythos_read_key_value("tests/fixtures/runtime/key_values.conf", "Enabled", value, sizeof(value))
    );
    assert_true("read_key_value_plain_true_value", strcmp(value, "true") == 0);

    /* reject a NULL path before fopen() gets a chance to crash */
    assert_false("read_file_text_null",
        bythos_read_file_text(NULL, buffer, sizeof(buffer)));
    assert_true("trim_null", bythos_trim(NULL) == NULL);

    {
        char dst[16];
        memset(dst, 'X', sizeof(dst));
        bythos_to_lower_ascii("ABCdef", dst, sizeof(dst));
        assert_true("to_lower_basic", strcmp(dst, "abcdef") == 0);

        memset(dst, 'X', sizeof(dst));
        bythos_to_lower_ascii("HELLO WORLD!", dst, 6);
        assert_true("to_lower_truncate", strcmp(dst, "hello") == 0);

        memset(dst, 'X', sizeof(dst));
        bythos_to_lower_ascii("", dst, sizeof(dst));
        assert_true("to_lower_empty", dst[0] == '\0');

        bythos_to_lower_ascii(NULL, dst, sizeof(dst));
        bythos_to_lower_ascii("X", NULL, 4);
        bythos_to_lower_ascii("X", dst, 0);
    }

    {
        char template[] = "./tmp-bythos-runtime-empty-XXXXXX";
        char *dir = mkdtemp(template);
        if (dir == NULL) {
            fprintf(stderr, "runtime capture failure: could not create temp dir for empty BYTHOS_PATH\n");
            return 1;
        }

        const char *path = getenv("BYTHOS_PATH");
        char *saved_path = path == NULL ? NULL : strdup(path);
        if (path != NULL && saved_path == NULL) {
            fprintf(stderr, "runtime capture failure: could not save BYTHOS_PATH for empty test\n");
            return 1;
        }

        if (setenv("BYTHOS_PATH", dir, 1) != 0) {
            fprintf(stderr, "runtime capture failure: could not set empty BYTHOS_PATH dir\n");
            free(saved_path);
            return 1;
        }

        assert_state(
            "service_probe_systemctl_unavailable",
            BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE,
            bythos_probe_systemd_service("mock.service")
        );

        restore_env("BYTHOS_PATH", saved_path);
        rmdir(dir);
    }

    assert_service_probe_with_script(
        "service_probe_active",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"is-active\" ]; then exit 0; fi\n"
        "if [ \"$1\" = \"show\" ]; then printf 'loaded\\n'; exit 0; fi\n"
        "exit 2\n",
        BYTHOS_SERVICE_STATE_ACTIVE
    );
    assert_service_probe_with_script(
        "service_probe_inactive",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"is-active\" ]; then exit 3; fi\n"
        "if [ \"$1\" = \"show\" ]; then printf 'loaded\\n'; exit 0; fi\n"
        "exit 2\n",
        BYTHOS_SERVICE_STATE_INACTIVE
    );
    assert_service_probe_with_script(
        "service_probe_missing",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"is-active\" ]; then exit 3; fi\n"
        "if [ \"$1\" = \"show\" ]; then printf 'not-found\\n'; exit 0; fi\n"
        "exit 2\n",
        BYTHOS_SERVICE_STATE_MISSING
    );
    assert_service_probe_with_script(
        "service_probe_unknown",
        "#!/bin/sh\n"
        "kill -9 $$\n",
        BYTHOS_SERVICE_STATE_UNKNOWN
    );

    {
        const char *path = "/tmp/bythos_test_truncation.bin";
        FILE *f = fopen(path, "wb");
        assert_true("truncation_fixture_created", f != NULL);
        for (int i = 0; i < 200; i++) {
            fputc(i & 0xFF, f);
        }
        fclose(f);

        unsigned char small[100];
        size_t n = 0;
        bool truncated = false;
        assert_true("short_buffer_reads",
            bythos_read_file_binary_ex(path, small, sizeof(small), &n, &truncated));
        assert_true("short_buffer_reports_truncation", truncated && n == sizeof(small));

        unsigned char roomy[400];
        n = 0;
        truncated = false;
        assert_true("roomy_buffer_reads",
            bythos_read_file_binary_ex(path, roomy, sizeof(roomy), &n, &truncated));
        assert_true("roomy_buffer_reports_no_truncation", !truncated && n == 200);

        unsigned char exact[200];
        n = 0;
        truncated = false;
        assert_true("exact_buffer_reads",
            bythos_read_file_binary_ex(path, exact, sizeof(exact), &n, &truncated));
        assert_true("exact_fit_is_not_truncation", !truncated && n == sizeof(exact));

        truncated = true;
        assert_false("missing_file_clears_the_flag",
            bythos_read_file_binary_ex("/tmp/bythos_absent_probe", exact,
                                       sizeof(exact), &n, &truncated));
        assert_false("missing_file_leaves_flag_false", truncated);

        char text_small[100];
        truncated = false;
        assert_true("text_short_buffer_reads",
            bythos_read_file_text_ex(path, text_small, sizeof(text_small), &truncated));
        assert_true("text_short_buffer_reports_truncation", truncated);

        char text_roomy[400];
        truncated = false;
        assert_true("text_roomy_buffer_reads",
            bythos_read_file_text_ex(path, text_roomy, sizeof(text_roomy), &truncated));
        assert_false("text_roomy_buffer_reports_no_truncation", truncated);

        char text_exact[201];
        truncated = false;
        assert_true("text_exact_buffer_reads",
            bythos_read_file_text_ex(path, text_exact, sizeof(text_exact), &truncated));
        assert_false("text_exact_fit_is_not_truncation", truncated);

        remove(path);
    }

    {
        static const char OVERMOUNTED[] =
            "/dev/sda1 /boot ext4 rw,relatime 0 0\n"
            "/dev/sdb1 /boot vfat rw,uid=1000 0 0\n";
        char fstype[64] = {0};
        char opts[128] = {0};

        assert_true("overmount_is_found",
            bythos_find_mount_entry(OVERMOUNTED, "/boot", fstype, sizeof(fstype),
                                    opts, sizeof(opts)));
        assert_true("effective_mount_is_the_last_one", strcmp(fstype, "vfat") == 0);
        assert_true("effective_options_come_from_the_last_one",
            strcmp(opts, "rw,uid=1000") == 0);

        static const char DECOY_FIRST[] =
            "efivarfs /mnt/decoy efivarfs ro,relatime 0 0\n"
            "efivarfs /sys/firmware/efi/efivars efivarfs rw,relatime 0 0\n";
        opts[0] = '\0';
        assert_true("decoy_does_not_answer_for_another_mount_point",
            bythos_find_mount_entry(DECOY_FIRST, "/sys/firmware/efi/efivars",
                                    NULL, 0, opts, sizeof(opts)));
        assert_true("real_mount_point_keeps_its_own_options",
            strcmp(opts, "rw,relatime") == 0);

        static const char DECOY_LAST[] =
            "efivarfs /sys/firmware/efi/efivars efivarfs rw,relatime 0 0\n"
            "efivarfs /mnt/decoy efivarfs ro,relatime 0 0\n";
        opts[0] = '\0';
        assert_true("trailing_decoy_is_ignored_too",
            bythos_find_mount_entry(DECOY_LAST, "/sys/firmware/efi/efivars",
                                    NULL, 0, opts, sizeof(opts)));
        assert_true("trailing_decoy_does_not_change_options",
            strcmp(opts, "rw,relatime") == 0);

        assert_false("absent_mount_point_is_reported_absent",
            bythos_find_mount_entry(OVERMOUNTED, "/srv", fstype, sizeof(fstype),
                                    NULL, 0));

        char narrow[3] = {0};
        assert_false("fstype_too_long_for_the_buffer_is_refused",
            bythos_find_mount_entry(OVERMOUNTED, "/boot", narrow, sizeof(narrow),
                                    NULL, 0));

        static const char PREFIX_ONLY[] = "/dev/sda1 /boots ext4 rw 0 0\n";
        assert_false("a_longer_mount_point_is_not_a_match",
            bythos_find_mount_entry(PREFIX_ONLY, "/boot", fstype, sizeof(fstype),
                                    NULL, 0));

        static const char TRUNCATED_LINE[] = "/dev/sda1 \n";
        assert_false("an_empty_mount_point_never_matches",
            bythos_find_mount_entry(TRUNCATED_LINE, "", NULL, 0, NULL, 0));

        char keep[64];
        memcpy(keep, "untouched", sizeof("untouched"));
        char tiny[3] = {0};
        assert_false("a_refused_lookup_writes_neither_output",
            bythos_find_mount_entry(OVERMOUNTED, "/boot", keep, sizeof(keep),
                                    tiny, sizeof(tiny)));
        assert_true("the_fstype_buffer_is_left_alone",
            strcmp(keep, "untouched") == 0);
    }

    printf("runtime capture ok\n");
    return 0;
}
