#ifndef BYTHOS_RUNTIME_H
#define BYTHOS_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <dirent.h>

typedef enum {
    BYTHOS_SERVICE_STATE_UNKNOWN = 0,
    BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE,
    BYTHOS_SERVICE_STATE_ACTIVE,
    BYTHOS_SERVICE_STATE_INACTIVE,
    BYTHOS_SERVICE_STATE_MISSING,
} bythos_service_state_t;

char *bythos_trim(char *text);
void bythos_to_lower_ascii(const char *src, char *dst, size_t dst_size);
bool bythos_command_exists(const char *name);
bool bythos_command_untrusted(const char *name);
bool bythos_file_exists(const char *path);
bool bythos_read_file_text(const char *path, char *buffer, size_t size);
bool bythos_read_file_text_ex(const char *path, char *buffer, size_t size,
                              bool *truncated);
bool bythos_read_file_binary(const char *path, unsigned char *buffer, size_t size, size_t *bytes_read);
bool bythos_read_file_binary_ex(const char *path, unsigned char *buffer, size_t size,
                                size_t *bytes_read, bool *truncated);
bool bythos_first_line_with_prefix(const char *path, const char *prefix, char *buffer, size_t size);
bool bythos_find_mount_entry(const char *mounts, const char *mount_point,
                             char *fstype_out, size_t fstype_size,
                             char *opts_out, size_t opts_size);
bool bythos_count_child_dirs(const char *path, size_t *count);
struct dirent *bythos_readdir_safe(DIR *dir, int *err_out);
bool bythos_read_key_value(const char *path, const char *key, char *buffer, size_t size);
bool bythos_capture_argv_status(const char *const argv[], char *buffer, size_t size, int *exit_status);
bool bythos_capture_argv_status_ex(const char *const argv[], char *buffer, size_t size, int *exit_status, bool *truncated);
int bythos_run_argv_quiet(const char *const argv[]);
bythos_service_state_t bythos_probe_systemd_service(const char *unit);
const char *bythos_esp_efi_base(void);

#endif
