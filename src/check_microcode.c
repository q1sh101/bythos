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
        bythos_cpu_vendor_t vendor = bythos_cpu_vendor();
        char microcode_line[256] = {0};
        char revision[128] = {0};

        if (vendor != BYTHOS_CPU_VENDOR_INTEL && vendor != BYTHOS_CPU_VENDOR_AMD) {
            EMIT_SKIP_VENDOR("CPU microcode", "x86-only check");
        } else if (!bythos_first_line_with_prefix(cpuinfo_path, "microcode", microcode_line, sizeof(microcode_line))) {
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
            size_t total = 0, vulnerable = 0, unknown = 0;
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
                } else if (strncmp(lower, "unknown", 7) == 0) {
                    unknown++;
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
            } else if (unknown > 0) {
                char detail[BYTHOS_DETAIL_MAX];
                snprintf(detail, sizeof(detail),
                    "%zu of %zu indeterminate (kernel reports unknown)", unknown, total);
                EMIT("CPU vulnerabilities", CHECK_WARN, detail);
            } else {
                char detail[BYTHOS_DETAIL_MAX];
                snprintf(detail, sizeof(detail), "%zu %s; all mitigated or not affected",
                    total, bythos_pl(total, "check", "checks"));
                EMIT("CPU vulnerabilities", CHECK_OK, detail);
            }
        }
    }

    if (bythos_command_exists("spectre-meltdown-checker")) {
        EMIT_SKIP("CPU vulnerability scan", SKIP_NOT_CONFIGURED,
            "spectre-meltdown-checker available; run manually for a deep scan");
    } else {
        EMIT_SKIP_TOOL_OR_UNTRUSTED("CPU vulnerability scan", "spectre-meltdown-checker", "spectre-meltdown-checker");
    }

    return used;
}
