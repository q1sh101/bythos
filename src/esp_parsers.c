#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "esp_parsers.h"

static bool name_lower_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

bool bythos_esp_is_known_vendor(const char *name) {
    if (name == NULL) return false;
    static const char *const known[] = {
        "boot", "microsoft",
        "ubuntu", "debian", "fedora", "arch", "manjaro", "gentoo",
        "systemd", "opensuse", "suse", "void", "centos", "redhat",
        "rocky", "alma", "almalinux", "linuxmint", "pop", "elementary",
        "nixos", "steamos", "garuda", "endeavouros", "artix", "cachyos",
        "dell", "hp", "lenovo", "refind", "tools", "grub", "kali", "qubes", "alpine",
        NULL
    };
    for (size_t i = 0; known[i] != NULL; i++) {
        if (name_lower_eq(name, known[i])) return true;
    }
    return false;
}

bool bythos_parse_sha256sum_line(const char *line, char *hash_out, size_t size) {
    if (line == NULL || hash_out == NULL || size == 0) return false;
    /* sha256sum output: "64-char-hex  filename\n" */
    const char *p = line;
    size_t n = 0;
    while (n < 64 && *p &&
           ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) {
        p++; n++;
    }
    if (n != 64) return false;
    if (*p != ' ' && *p != '\t') return false;
    size_t copy = 64 < size - 1u ? 64 : size - 1u;
    memcpy(hash_out, line, copy);
    hash_out[copy] = '\0';
    return true;
}
