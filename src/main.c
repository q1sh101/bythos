#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "output.h"

enum {
    BYTHOS_EXIT_OK = 0,
    BYTHOS_EXIT_FAIL = 1,
    BYTHOS_EXIT_USAGE = 2,
};

#define BYTHOS_VERSION "0.1.1"

static void usage(const char *argv0) {
    printf(
        "usage: %s [-j|--json]\n"
        "\n"
        "  -j, --json     machine-readable JSON output (scripts, CI, pipes)\n"
        "  -h, --help     show this help and exit\n"
        "  -V, --version  print version and exit\n",
        argv0
    );
}

int main(int argc, char **argv) {
    bythos_render_mode_t render_mode = BYTHOS_RENDER_PLAIN;
    posture_summary_t overall = {0};
    int exit_code = BYTHOS_EXIT_OK;
    check_subgroup_t firmware_subgroups[BYTHOS_MAX_GROUP_SUBGROUPS];
    posture_summary_t firmware_summary = {0};
    size_t firmware_subgroup_count = 0;

    static const struct option long_options[] = {
        {"help",    no_argument, NULL, 'h'},
        {"json",    no_argument, NULL, 'j'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hjV", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'j':
            render_mode = BYTHOS_RENDER_JSON;
            break;
        case 'V':
            printf("bythos %s\n", BYTHOS_VERSION);
            return 0;
        default:
            usage(argv[0]);
            return BYTHOS_EXIT_USAGE;
        }
    }

    if (optind < argc) {
        usage(argv[0]);
        return BYTHOS_EXIT_USAGE;
    }

    firmware_subgroup_count = bythos_check_firmware(
        firmware_subgroups, BYTHOS_MAX_GROUP_SUBGROUPS);
    for (size_t i = 0; i < firmware_subgroup_count; i++) {
        bythos_summary_merge(&firmware_summary, &firmware_subgroups[i].summary);
        bythos_summary_merge(&overall, &firmware_subgroups[i].summary);
    }

    exit_code = overall.fail_count > 0 ? BYTHOS_EXIT_FAIL : BYTHOS_EXIT_OK;

    bythos_group_view_t groups[1];
    groups[0] = (bythos_group_view_t){
        .name = "firmware",
        .subgroups = firmware_subgroups,
        .subgroup_count = firmware_subgroup_count,
        .summary = &firmware_summary,
    };

    bythos_render(render_mode, "firmware",
                  "firmware trust posture",
                  groups, 1, &overall, exit_code);
    return exit_code;
}
