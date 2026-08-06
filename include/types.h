#ifndef BYTHOS_TYPES_H
#define BYTHOS_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define BYTHOS_DETAIL_MAX 256

typedef enum {
    CHECK_OK = 0,
    CHECK_WARN = 1,
    CHECK_FAIL = 2,
    CHECK_SKIP = 3
} check_state_t;

typedef enum {
    SKIP_NONE = 0,
    SKIP_TOOL_ABSENT,
    SKIP_FEATURE_ABSENT,
    SKIP_EXEC_FAILED,
    SKIP_PROBE_INDETERMINATE,
    SKIP_REPORT_FIELD_ABSENT,
    SKIP_OUTPUT_UNPARSEABLE,
    SKIP_NOT_CONFIGURED,
    SKIP_SUBJECT_ABSENT,
    SKIP_HW_ABSENT,
    SKIP_VENDOR_SCOPE
} skip_reason_t;

typedef struct {
    const char *name;
    check_state_t state;
    skip_reason_t skip_reason;
    char detail[BYTHOS_DETAIL_MAX];
    bool requires_root;
    bool actionable;
} check_result_t;

typedef struct {
    size_t ok_count;
    size_t warn_count;
    size_t fail_count;
    size_t skip_count;
} posture_summary_t;

#define BYTHOS_MAX_SUBGROUP_RESULTS 32

typedef struct {
    const char *name;
    check_result_t results[BYTHOS_MAX_SUBGROUP_RESULTS + 1];
    size_t result_count;
    bool truncated;
    posture_summary_t summary;
} check_subgroup_t;

static inline check_result_t make_result(const char *name, check_state_t state, const char *detail) {
    check_result_t result = {
        .name = name,
        .state = state,
        .skip_reason = SKIP_NONE,
        .detail = {0},
        .requires_root = false,
        .actionable = false,
    };
    if (detail != NULL) {
        snprintf(result.detail, sizeof(result.detail), "%s", detail);
    }
    return result;
}

static inline check_result_t make_skip(const char *name, skip_reason_t reason, const char *detail) {
    check_result_t result = make_result(name, CHECK_SKIP, detail);
    result.skip_reason = reason;
    return result;
}

static inline check_result_t make_skip_actionable(const char *name, skip_reason_t reason, const char *detail) {
    check_result_t result = make_skip(name, reason, detail);
    result.actionable = true;
    return result;
}

static inline check_result_t make_skip_root(const char *name, skip_reason_t reason, const char *detail) {
    check_result_t result = make_skip(name, reason, detail);
    result.requires_root = true;
    return result;
}

static inline const char *bythos_pl(size_t n, const char *singular, const char *plural) {
    return n == 1 ? singular : plural;
}

#define EMIT(name_, state_, detail_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_result((name_), (state_), (detail_)); \
        } \
    } while (0)

#define EMIT_SKIP(name_, reason_, detail_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), (reason_), (detail_)); \
        } \
    } while (0)

#define EMIT_SKIP_TOOL(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_TOOL_ABSENT, tool_ " not found"); \
        } \
    } while (0)

#define EMIT_SKIP_TOOL_INSTALL(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip_actionable((name_), SKIP_TOOL_ABSENT, "requires " tool_); \
        } \
    } while (0)

#define EMIT_SKIP_FEATURE(name_, feat_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_FEATURE_ABSENT, feat_ " not available"); \
        } \
    } while (0)

#define EMIT_SKIP_EXEC(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_EXEC_FAILED, tool_ " query failed"); \
        } \
    } while (0)

#define EMIT_SKIP_EXEC_ROOT(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip_root((name_), SKIP_EXEC_FAILED, tool_ " query failed"); \
        } \
    } while (0)

#define EMIT_SKIP_PROBE(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_PROBE_INDETERMINATE, tool_ " result indeterminate"); \
        } \
    } while (0)

#define EMIT_SKIP_FIELD(name_, field_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_REPORT_FIELD_ABSENT, field_ " absent from " tool_ " output"); \
        } \
    } while (0)

#define EMIT_SKIP_PARSE(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_OUTPUT_UNPARSEABLE, tool_ " output not parseable"); \
        } \
    } while (0)

#define EMIT_SKIP_NOT_CONF(name_, tool_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip_actionable((name_), SKIP_NOT_CONFIGURED, tool_ " not configured"); \
        } \
    } while (0)

#define EMIT_SKIP_SUBJECT(name_, subj_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_SUBJECT_ABSENT, subj_ " not present on this host"); \
        } \
    } while (0)

#define EMIT_SKIP_SUBJECT_INSTALL(name_, subj_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip_actionable((name_), SKIP_SUBJECT_ABSENT, subj_ " not present on this host"); \
        } \
    } while (0)

#define EMIT_SKIP_HW(name_, hw_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_HW_ABSENT, hw_ " not detected"); \
        } \
    } while (0)

#define EMIT_SKIP_VENDOR(name_, scope_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_skip((name_), SKIP_VENDOR_SCOPE, (scope_)); \
        } \
    } while (0)

#endif

