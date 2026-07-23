#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "output.h"

static bool use_color(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *no_color = getenv("NO_COLOR");
        const char *term = getenv("TERM");
        cached = (no_color == NULL || *no_color == '\0')
                 && isatty(fileno(stdout)) != 0
                 && term != NULL
                 && strcmp(term, "dumb") != 0
                 && strcmp(term, "linux") != 0;
    }
    return cached != 0;
}

static const char *c_reset(void) { return use_color() ? "\033[0m" : ""; }
static const char *c_brand(void) { return use_color() ? "\033[1;38;5;220m" : ""; }
static const char *c_accent(void) { return use_color() ? "\033[38;5;123m" : ""; }
static const char *c_green(void) { return use_color() ? "\033[38;5;82m" : ""; }
static const char *c_yellow(void) { return use_color() ? "\033[38;5;214m" : ""; }
static const char *c_red(void) { return use_color() ? "\033[38;5;160m" : ""; }
static const char *c_dim(void) { return use_color() ? "\033[38;5;248m" : ""; }

static const char *state_color(check_state_t state) {
    switch (state) {
    case CHECK_OK:
        return c_green();
    case CHECK_WARN:
        return c_yellow();
    case CHECK_FAIL:
        return c_red();
    case CHECK_SKIP:
        return c_dim();
    }
    return "";
}

static void vprint_prefixed(FILE *stream, const char *color, const char *label, const char *fmt, va_list args) {
    fprintf(stream, "  %s%s%s ", color, label, c_reset());
    vfprintf(stream, fmt, args);
    fputc('\n', stream);
}

static void bythos_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprint_prefixed(stdout, c_brand(), "[bythos]", fmt, args);
    va_end(args);
}

const char *bythos_state_name(check_state_t state) {
    switch (state) {
    case CHECK_OK:
        return "OK";
    case CHECK_WARN:
        return "WARN";
    case CHECK_FAIL:
        return "FAIL";
    case CHECK_SKIP:
        return "SKIP";
    }
    return "UNKNOWN";
}

const char *bythos_skip_reason_name(skip_reason_t reason) {
    switch (reason) {
    case SKIP_NONE:
        return "NONE";
    case SKIP_TOOL_ABSENT:
        return "TOOL_ABSENT";
    case SKIP_FEATURE_ABSENT:
        return "FEATURE_ABSENT";
    case SKIP_EXEC_FAILED:
        return "EXEC_FAILED";
    case SKIP_PROBE_INDETERMINATE:
        return "PROBE_INDETERMINATE";
    case SKIP_REPORT_FIELD_ABSENT:
        return "REPORT_FIELD_ABSENT";
    case SKIP_OUTPUT_UNPARSEABLE:
        return "OUTPUT_UNPARSEABLE";
    case SKIP_NOT_CONFIGURED:
        return "NOT_CONFIGURED";
    case SKIP_SUBJECT_ABSENT:
        return "SUBJECT_ABSENT";
    case SKIP_HW_ABSENT:
        return "HW_ABSENT";
    case SKIP_VENDOR_SCOPE:
        return "VENDOR_SCOPE";
    }
    return "UNKNOWN";
}

static const char *strip_subgroup_prefix(const char *name, const char *subgroup_name) {
    size_t prefix_len = strlen(subgroup_name);
    if (strlen(name) <= prefix_len) return name;
    for (size_t i = 0; i < prefix_len; i++) {
        if (tolower((unsigned char)name[i]) != tolower((unsigned char)subgroup_name[i]))
            return name;
    }
    if (name[prefix_len] != ' ') return name;
    return name + prefix_len + 1;
}

static void print_result_line(const char *display_name, const check_result_t *result) {
    static const char *state_labels[] = {"ok  ", "warn", "fail", "skip"};
    const char *label = (unsigned)result->state < 4
        ? state_labels[result->state] : "????";
    fprintf(stdout, "    %s%s%s  %s",
        state_color(result->state), label, c_reset(),
        display_name);
    if (result->detail[0] != '\0') {
        fprintf(stdout, "  %s", result->detail);
    }
    if (result->requires_root) {
        fprintf(stdout, "  (requires root)");
    }
    fputc('\n', stdout);
}

static void bythos_print_result_in_subgroup(const check_result_t *result,
                                             const char *subgroup_name) {
    print_result_line(strip_subgroup_prefix(result->name, subgroup_name), result);
}

void bythos_summary_add(posture_summary_t *summary, const check_result_t *result) {
    switch (result->state) {
    case CHECK_OK:
        summary->ok_count++;
        break;
    case CHECK_WARN:
        summary->warn_count++;
        break;
    case CHECK_FAIL:
        summary->fail_count++;
        break;
    case CHECK_SKIP:
        summary->skip_count++;
        break;
    }
}

check_state_t bythos_summary_state(const posture_summary_t *summary) {
    if (summary->fail_count > 0) {
        return CHECK_FAIL;
    }
    if (summary->warn_count > 0) {
        return CHECK_WARN;
    }
    if (summary->ok_count > 0) {
        return CHECK_OK;
    }
    return CHECK_SKIP;
}

/* length 2..4 of a well-formed UTF-8 sequence at p (Unicode 3.9, Table 3-7), else 0 */
static int utf8_valid_len(const unsigned char *p) {
    unsigned char c = p[0];
    if (c >= 0xC2 && c <= 0xDF) {
        return (p[1] >= 0x80 && p[1] <= 0xBF) ? 2 : 0;
    }
    if (c == 0xE0) {
        return (p[1] >= 0xA0 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF) ? 3 : 0;
    }
    if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) {
        return (p[1] >= 0x80 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF) ? 3 : 0;
    }
    if (c == 0xED) {
        return (p[1] >= 0x80 && p[1] <= 0x9F && p[2] >= 0x80 && p[2] <= 0xBF) ? 3 : 0;
    }
    if (c == 0xF0) {
        return (p[1] >= 0x90 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF &&
                p[3] >= 0x80 && p[3] <= 0xBF) ? 4 : 0;
    }
    if (c >= 0xF1 && c <= 0xF3) {
        return (p[1] >= 0x80 && p[1] <= 0xBF && p[2] >= 0x80 && p[2] <= 0xBF &&
                p[3] >= 0x80 && p[3] <= 0xBF) ? 4 : 0;
    }
    if (c == 0xF4) {
        return (p[1] >= 0x80 && p[1] <= 0x8F && p[2] >= 0x80 && p[2] <= 0xBF &&
                p[3] >= 0x80 && p[3] <= 0xBF) ? 4 : 0;
    }
    return 0;
}

static void print_json_string(const char *text) {
    putchar('"');
    const unsigned char *p = (const unsigned char *)text;
    while (*p != '\0') {
        unsigned char c = *p;
        if (c == '\\') { fputs("\\\\", stdout); p++; continue; }
        if (c == '"')  { fputs("\\\"", stdout); p++; continue; }
        if (c == '\n') { fputs("\\n",  stdout); p++; continue; }
        if (c == '\r') { fputs("\\r",  stdout); p++; continue; }
        if (c == '\t') { fputs("\\t",  stdout); p++; continue; }
        if (c < 0x20)  { printf("\\u%04x", c);  p++; continue; }
        if (c < 0x80)  { putchar(c);            p++; continue; }

        int seq = utf8_valid_len(p);
        if (seq == 0) {
            fputs("\xEF\xBF\xBD", stdout);
            p++;
            continue;
        }
        for (int i = 0; i < seq; i++) {
            putchar(p[i]);
        }
        p += seq;
    }
    putchar('"');
}

static void print_json_summary(const posture_summary_t *summary) {
    printf("{\"state\":");
    print_json_string(bythos_state_name(bythos_summary_state(summary)));
    printf(
        ",\"counts\":{\"ok\":%zu,\"warn\":%zu,\"fail\":%zu,\"skip\":%zu}}",
        summary->ok_count, summary->warn_count,
        summary->fail_count, summary->skip_count
    );
}

static const char *exit_meaning(int exit_code) {
    switch (exit_code) {
    case 0:
        return "no_fail";
    case 1:
        return "posture_fail";
    case 2:
        return "usage_error";
    default:
        return "unknown";
    }
}

static void bythos_print_json(
    const char *mode,
    const char *banner,
    const bythos_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
) {
    printf("{\"mode\":");
    print_json_string(mode);
    printf(",\"banner\":");
    print_json_string(banner);
    printf(",\"groups\":[");

    for (size_t i = 0; i < group_count; i++) {
        if (i > 0) {
            putchar(',');
        }
        printf("{\"name\":");
        print_json_string(groups[i].name);
        printf(",\"summary\":");
        print_json_summary(groups[i].summary);
        printf(",\"subgroups\":[");
        for (size_t s = 0; s < groups[i].subgroup_count; s++) {
            const check_subgroup_t *sg = &groups[i].subgroups[s];
            if (s > 0) {
                putchar(',');
            }
            printf("{\"name\":");
            print_json_string(sg->name);
            printf(",\"summary\":");
            print_json_summary(&sg->summary);
            printf(",\"results\":[");
            for (size_t j = 0; j < sg->result_count; j++) {
                const check_result_t *result = &sg->results[j];
                if (j > 0) {
                    putchar(',');
                }
                printf("{\"name\":");
                print_json_string(result->name);
                printf(",\"state\":");
                print_json_string(bythos_state_name(result->state));
                printf(",\"skip_reason\":");
                print_json_string(bythos_skip_reason_name(result->skip_reason));
                printf(",\"detail\":");
                print_json_string(result->detail);
                printf(",\"requires_root\":%s,\"actionable\":%s}",
                       result->requires_root ? "true" : "false",
                       result->actionable ? "true" : "false");
            }
            printf("],\"truncated\":%s}", sg->truncated ? "true" : "false");
        }
        printf("]}");
    }

    printf("],\"overall\":");
    print_json_summary(overall);
    printf(",\"exit_code\":%d,\"exit_meaning\":", exit_code);
    print_json_string(exit_meaning(exit_code));
    printf("}\n");
}

static void print_groups_hierarchy(
    const bythos_group_view_t *groups,
    size_t group_count
) {
    for (size_t g = 0; g < group_count; g++) {
        for (size_t s = 0; s < groups[g].subgroup_count; s++) {
            const check_subgroup_t *sg = &groups[g].subgroups[s];
            if (sg->result_count == 0) continue;
            printf("  %s%s:%s\n", c_accent(), sg->name, c_reset());
            for (size_t i = 0; i < sg->result_count; i++) {
                bythos_print_result_in_subgroup(&sg->results[i], sg->name);
            }
            if (sg->truncated) {
                printf("    %s(some results truncated; subgroup at capacity)%s\n",
                    c_dim(), c_reset());
            }
            putchar('\n');
        }
    }
}

static void bythos_print_plain(
    const char *banner,
    const bythos_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall
) {
    static const char *snames[] = {"ok", "warn", "fail", "skip"};
    check_state_t ost = bythos_summary_state(overall);
    putchar('\n');
    bythos_log("%s", banner);
    printf("    %s%s:%s  %s%zu ok%s  %s%zu warn%s  %s%zu fail%s  %s%zu skip%s\n\n",
        c_brand(), (unsigned)ost < 4 ? snames[ost] : "unknown", c_reset(),
        c_green(), overall->ok_count, c_reset(),
        c_yellow(), overall->warn_count, c_reset(),
        c_red(), overall->fail_count, c_reset(),
        c_dim(), overall->skip_count, c_reset());
    print_groups_hierarchy(groups, group_count);
}

void bythos_render(
    bythos_render_mode_t mode,
    const char *mode_str,
    const char *banner,
    const bythos_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
) {
    if (mode == BYTHOS_RENDER_JSON) {
        bythos_print_json(mode_str, banner, groups, group_count, overall, exit_code);
    } else {
        bythos_print_plain(banner, groups, group_count, overall);
    }
}
