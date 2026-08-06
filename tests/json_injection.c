/* Hostile detail strings must never break the JSON document. */
#include <stdio.h>
#include <string.h>

#include "output.h"
#include "types.h"

static const char *const HOSTILE[] = {
    "plain",
    "quote \" inside",
    "backslash \\ inside",
    "both \\\" together",
    "newline \n and tab \t and cr \r",
    "control \x01\x02\x1f end",
    "brace } bracket ] comma ,",
    "\"},{\"name\":\"injected\",\"state\":\"ok\",\"x\":\"",
    "invalid utf8 \xff\xfe end",
    "truncated utf8 \xe2\x82",
    "overlong \xc0\xaf end",
    "surrogate \xed\xa0\x80 end",
    "valid utf8 \xc3\xa9 \xe2\x82\xac \xf0\x9f\x92\xa9",
    "\x7f delete",
    "trailing backslash \\",
};

int main(void) {
    const size_t n = sizeof(HOSTILE) / sizeof(HOSTILE[0]);
    check_subgroup_t group = {0};
    group.name = "hostile \" group \\ name";

    for (size_t i = 0; i < n && i < BYTHOS_MAX_SUBGROUP_RESULTS; i++) {
        group.results[i] = make_result("name \" with \\ quotes", CHECK_OK, HOSTILE[i]);
        bythos_summary_add(&group.summary, &group.results[i]);
        group.result_count++;
    }

    posture_summary_t overall = group.summary;
    bythos_group_view_t view = {
        .name = "hostile",
        .subgroups = &group,
        .subgroup_count = 1,
        .summary = &group.summary,
    };

    bythos_render(BYTHOS_RENDER_JSON, "hostile", "banner \" with \\ escapes",
                  &view, 1, &overall, 0);
    return 0;
}
