#include <dirent.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_microcode(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *cpuinfo_path = "/proc/cpuinfo";

    {
        char microcode_line[256] = {0};
        char revision[128] = {0};

        if (!bythos_first_line_with_prefix(cpuinfo_path, "microcode", microcode_line, sizeof(microcode_line))) {
            EMIT("CPU microcode", CHECK_WARN, "revision not visible");
        } else if (bythos_extract_microcode_revision(microcode_line, revision, sizeof(revision))) {
            char detail[160];
            snprintf(detail, sizeof(detail), "loaded revision %s", revision);
            EMIT("CPU microcode", CHECK_OK, detail);
        } else {
            EMIT("CPU microcode", CHECK_WARN, "revision not visible");
        }
    }

    {
        const char *vuln_dir = "/sys/devices/system/cpu/vulnerabilities";
        DIR *d = opendir(vuln_dir);
        if (d == NULL) {
            EMIT_SKIP("CPU vulnerabilities", SKIP_FEATURE_ABSENT,
                "kernel vulnerabilities sysfs not exposed");
        } else {
            size_t total = 0, vulnerable = 0;
            char first_vuln[64] = {0};
            struct dirent *entry;
            while ((entry = bythos_readdir_safe(d, NULL)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                char path[PATH_MAX];
                if (snprintf(path, sizeof(path), "%s/%s", vuln_dir, entry->d_name) >=
                    (int)sizeof(path)) continue;
                char content[256] = {0};
                if (!bythos_read_file_text(path, content, sizeof(content))) continue;
                total++;
                char lower[256];
                bythos_to_lower_ascii(content, lower, sizeof(lower));
                if (strstr(lower, "vulnerable") != NULL) {
                    vulnerable++;
                    if (first_vuln[0] == '\0') {
                        snprintf(first_vuln, sizeof(first_vuln), "%.60s", entry->d_name);
                    }
                }
            }
            closedir(d);
            if (total == 0) {
                EMIT_SKIP("CPU vulnerabilities", SKIP_FEATURE_ABSENT,
                    "no vulnerability entries");
            } else if (vulnerable > 0) {
                char detail[BYTHOS_DETAIL_MAX];
                snprintf(detail, sizeof(detail), "%zu of %zu vulnerable (e.g. %s)",
                    vulnerable, total, first_vuln);
                EMIT("CPU vulnerabilities", CHECK_WARN, detail);
            } else {
                char detail[BYTHOS_DETAIL_MAX];
                snprintf(detail, sizeof(detail), "%zu checks; all mitigated or not affected",
                    total);
                EMIT("CPU vulnerabilities", CHECK_OK, detail);
            }
        }
    }

    if (bythos_command_exists("spectre-meltdown-checker")) {
        EMIT("CPU vulnerability scan", CHECK_OK, "available: spectre-meltdown-checker");
    } else {
        EMIT_SKIP_TOOL_INSTALL("CPU vulnerability scan", "spectre-meltdown-checker");
    }

    return used;
}
