#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "runtime.h"
#include "silicon_parsers.h"

static bool token_present(const char *text, const char *needle) {
    size_t needle_len = strlen(needle);
    const char *cursor = text;

    while (*cursor != '\0') {
        while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        size_t token_len = strcspn(cursor, " \t\r\n");
        if (token_len == needle_len && strncmp(cursor, needle, needle_len) == 0) {
            return true;
        }

        cursor += token_len;
    }

    return false;
}

void bythos_parse_iommu_cmdline(const char *text, bythos_iommu_cmdline_t *cmdline) {
    if (cmdline == NULL) {
        return;
    }

    *cmdline = (bythos_iommu_cmdline_t){0};

    if (text == NULL || *text == '\0') {
        return;
    }

    cmdline->iommu_disabled =
        token_present(text, "iommu=off") ||
        token_present(text, "intel_iommu=off") ||
        token_present(text, "amd_iommu=off");

    cmdline->vendor_iommu_on =
        token_present(text, "intel_iommu=on") ||
        token_present(text, "amd_iommu=on");

    cmdline->passthrough_on =
        token_present(text, "iommu=pt") ||
        token_present(text, "iommu.passthrough=1");

    cmdline->passthrough_off = token_present(text, "iommu.passthrough=0");
    cmdline->strict_on = token_present(text, "iommu.strict=1");
    cmdline->strict_off = token_present(text, "iommu.strict=0");
}

int bythos_pcr_zero_check(const char *buf, unsigned int pcr_num) {
    if (buf == NULL) return -1;

    char prefix[8];
    snprintf(prefix, sizeof(prefix), "%u", pcr_num);
    size_t plen = strlen(prefix);

    const char *line = buf;
    while (*line != '\0') {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, prefix, plen) == 0 &&
            (p[plen] == ' ' || p[plen] == ':' || p[plen] == '\t')) {
            const char *eol = p;
            while (*eol && *eol != '\n') eol++;
            const char *ox = p;
            while (ox + 1 < eol) {
                if (ox[0] == '0' && ox[1] == 'x') {
                    const char *hex = ox + 2;
                    bool zeros = true;
                    size_t n = 0;
                    while (hex[n] && hex[n] != '\n' && hex[n] != '\r' && hex[n] != ' ') {
                        if (hex[n] != '0') zeros = false;
                        n++;
                    }
                    return n == 0 ? -1 : (zeros ? 1 : 0);
                }
                ox++;
            }
            return -1;
        }

        while (*line && *line != '\n') line++;
        if (*line == '\n') line++;
    }
    return -1;
}

bythos_cpu_vendor_t bythos_cpu_vendor(void) {
    char buf[4096] = {0};
    if (!bythos_read_file_text("/proc/cpuinfo", buf, sizeof(buf))) {
        return BYTHOS_CPU_VENDOR_UNKNOWN;
    }

    const char *cursor = buf;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len > 10 && strncmp(cursor, "vendor_id", 9) == 0) {
            const char *colon = memchr(cursor, ':', line_len);
            if (colon != NULL) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                if (strncmp(colon, "AuthenticAMD", 12) == 0) return BYTHOS_CPU_VENDOR_AMD;
                if (strncmp(colon, "GenuineIntel", 12) == 0) return BYTHOS_CPU_VENDOR_INTEL;
            }
            break;
        }
        cursor += line_len;
        while (*cursor == '\r' || *cursor == '\n') cursor++;
    }

    return BYTHOS_CPU_VENDOR_UNKNOWN;
}

static bool extract_cpuinfo_flags_line(const char *cpuinfo,
                                       char *out, size_t out_size) {
    if (cpuinfo == NULL || out == NULL || out_size == 0) {
        return false;
    }

    const char *cursor = cpuinfo;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len > 5 && strncmp(cursor, "flags", 5) == 0 &&
            (cursor[5] == '\t' || cursor[5] == ' ' || cursor[5] == ':')) {
            const char *colon = memchr(cursor, ':', line_len);
            if (colon != NULL) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                size_t value_len = (size_t)(cursor + line_len - colon);
                if (value_len >= out_size) value_len = out_size - 1;
                memcpy(out, colon, value_len);
                out[value_len] = '\0';
                return true;
            }
        }
        cursor += line_len;
        while (*cursor == '\r' || *cursor == '\n') cursor++;
    }
    return false;
}

void bythos_parse_memory_encryption_flags(const char *cpuinfo,
                                              bythos_mem_enc_flags_t *flags) {
    if (flags == NULL) {
        return;
    }
    *flags = (bythos_mem_enc_flags_t){0};
    if (cpuinfo == NULL) {
        return;
    }

    char flags_line[2048];
    if (!extract_cpuinfo_flags_line(cpuinfo, flags_line, sizeof(flags_line))) {
        return;
    }

    flags->amd_sme   = token_present(flags_line, "sme");
    flags->intel_tme = token_present(flags_line, "tme");
}

bool bythos_extract_microcode_revision(const char *text, char *buffer, size_t size) {
    if (text == NULL || buffer == NULL || size == 0) {
        return false;
    }

    buffer[0] = '\0';

    char line[512];
    const char *cursor = text;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }

        memcpy(line, cursor, line_len);
        line[line_len] = '\0';

        char *lhs = bythos_trim(line);
        if (strncmp(lhs, "microcode", 9) == 0) {
            char *sep = strchr(lhs, ':');
            if (sep != NULL) {
                char *rhs = bythos_trim(sep + 1);
                if (*rhs != '\0') {
                    snprintf(buffer, size, "%s", rhs);
                    return true;
                }
            }
        }

        cursor += strcspn(cursor, "\r\n");
        while (*cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
    }

    return false;
}

bool bythos_parse_me_version(const char *text, char *out, size_t size) {
    if (text == NULL || out == NULL || size == 0) {
        return false;
    }

    unsigned int platform, major, minor, hotfix, build;

    /* mei sysfs fw_version is <platform>:<major>.<minor>.<hotfix>.<build> */
    if (sscanf(text, "%u:%u.%u.%u.%u", &platform, &major, &minor, &hotfix, &build) == 5) {
        snprintf(out, size, "%u.%u.%u.%u", major, minor, hotfix, build);
        return true;
    }

    /* tolerate a bare version without the platform prefix */
    if (sscanf(text, "%u.%u.%u.%u", &major, &minor, &hotfix, &build) == 4) {
        snprintf(out, size, "%u.%u.%u.%u", major, minor, hotfix, build);
        return true;
    }

    return false;
}
