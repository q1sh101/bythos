#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "firmware_parsers.h"
#include "runtime.h"
#include "silicon_parsers.h"

/* sized past the EMIT_HSI call sites; a mapping added beyond that stays counted but unrecorded */
#define HSI_REPORTED_MAX 48

typedef struct {
    const char *id[HSI_REPORTED_MAX];
    size_t count;
    size_t not_supported;
} hsi_reported_t;

static void hsi_mark_reported(hsi_reported_t *reported, const char *id,
                              const char *result) {
    if (reported->count < HSI_REPORTED_MAX) {
        reported->id[reported->count] = id;
    }
    reported->count++;
    if (strcmp(result, "not-supported") == 0) {
        reported->not_supported++;
    }
}

static bool hsi_already_reported(const hsi_reported_t *reported, const char *id) {
    size_t n = reported->count < HSI_REPORTED_MAX ? reported->count : HSI_REPORTED_MAX;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(reported->id[i], id) == 0) {
            return true;
        }
    }
    return false;
}

static bool hsi_unmapped_detail(char *out, size_t size, size_t hidden,
                                const char *names, size_t named,
                                size_t inapplicable) {
    char aside[64] = {0};
    if (inapplicable > 0) {
        int n = snprintf(aside, sizeof(aside),
            "; %zu more not-supported (inapplicable)", inapplicable);
        if (n < 0 || (size_t)n >= sizeof(aside)) {
            return false;
        }
    }

    int written;
    if (named == 0) {
        written = snprintf(out, size,
            "%zu further fwupd %s not passing, unidentified%s; run: fwupdmgr security",
            hidden, bythos_pl(hidden, "attribute is", "attributes are"), aside);
    } else if (named == hidden) {
        written = snprintf(out, size,
            "%zu further fwupd %s not passing: %s%s; run: fwupdmgr security",
            hidden, bythos_pl(hidden, "attribute is", "attributes are"), names, aside);
    } else {
        written = snprintf(out, size,
            "%zu further fwupd %s not passing: %s (+%zu unidentified)%s; run: fwupdmgr security",
            hidden, bythos_pl(hidden, "attribute is", "attributes are"), names,
            hidden - named, aside);
    }
    return written >= 0 && (size_t)written < size;
}

static void hsi_format_warn(const bythos_hsi_attribute_t *attr,
                            char *out, size_t size) {
    const char *suffix = "";
    switch (attr->action) {
    case BYTHOS_HSI_ACTION_OEM:      suffix = "; OEM-controlled";       break;
    case BYTHOS_HSI_ACTION_FIRMWARE: suffix = "; configurable in BIOS"; break;
    case BYTHOS_HSI_ACTION_OS:       suffix = "; configurable in OS";   break;
    default: break;
    }
    snprintf(out, size, "%s%s", attr->result, suffix);
}

size_t bythos_check_fwupd(check_result_t *results, size_t max_results) {
    size_t used = 0;
    static const char *const lvfs_conf_candidates[] = {
        "/etc/fwupd/remotes.d/lvfs.conf",
        "/usr/share/fwupd/remotes.d/lvfs.conf",
    };
    const char *lvfs_conf = NULL;
    for (size_t i = 0; i < sizeof(lvfs_conf_candidates) / sizeof(lvfs_conf_candidates[0]); i++) {
        if (bythos_file_exists(lvfs_conf_candidates[i])) {
            lvfs_conf = lvfs_conf_candidates[i];
            break;
        }
    }
    bool has_fwupdmgr = false;
    static const char *const fwupd_devices_argv[] = {"fwupdmgr", "get-devices", NULL};
    static const char *const fwupd_updates_argv[] = {"fwupdmgr", "get-updates", NULL};

    has_fwupdmgr = bythos_command_exists("fwupdmgr");

    switch (bythos_probe_systemd_service("fwupd.service")) {
    case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
        EMIT_SKIP_TOOL_OR_UNTRUSTED("fwupd service", "systemctl", "systemd");
        break;
    case BYTHOS_SERVICE_STATE_ACTIVE:
        EMIT("fwupd service", CHECK_OK, "running");
        break;
    case BYTHOS_SERVICE_STATE_INACTIVE:
        EMIT("fwupd service", CHECK_WARN, "installed but inactive");
        break;
    case BYTHOS_SERVICE_STATE_MISSING:
        EMIT("fwupd service", CHECK_WARN, "not installed");
        break;
    default:
        EMIT_SKIP_PROBE("fwupd service", "systemctl");
        break;
    }

    switch (bythos_probe_systemd_service("fwupd-refresh.timer")) {
    case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
        EMIT_SKIP_TOOL_OR_UNTRUSTED("auto-refresh timer", "systemctl", "systemd");
        break;
    case BYTHOS_SERVICE_STATE_ACTIVE:
        EMIT("auto-refresh timer", CHECK_OK, "active");
        break;
    case BYTHOS_SERVICE_STATE_INACTIVE:
        EMIT("auto-refresh timer", CHECK_WARN, "inactive");
        break;
    case BYTHOS_SERVICE_STATE_MISSING:
        EMIT_SKIP_SUBJECT("auto-refresh timer", "fwupd-refresh.timer");
        break;
    default:
        EMIT_SKIP_PROBE("auto-refresh timer", "systemctl");
        break;
    }

    {
        char enabled[32] = {0};
        if (!has_fwupdmgr) {
            EMIT_SKIP_TOOL_OR_UNTRUSTED("LVFS remote", "fwupdmgr", "fwupd");
        } else if (lvfs_conf == NULL) {
            EMIT("LVFS remote", CHECK_WARN, "lvfs.conf not found");
        } else if (!bythos_read_key_value(lvfs_conf, "Enabled", enabled, sizeof(enabled))) {
            EMIT("LVFS remote", CHECK_WARN, "Enabled key not found");
        } else if (strcmp(enabled, "true") == 0) {
            EMIT("LVFS remote", CHECK_OK, "enabled");
        } else {
            EMIT("LVFS remote", CHECK_WARN, "not enabled");
        }
    }

    {
        if (!has_fwupdmgr) {
            EMIT_SKIP_TOOL_OR_UNTRUSTED("firmware inventory", "fwupdmgr", "fwupd");
        } else if (bythos_run_argv_quiet(fwupd_devices_argv) == 0) {
            EMIT("firmware inventory", CHECK_OK, "device list available");
        } else {
            EMIT_SKIP_EXEC("firmware inventory", "fwupdmgr");
        }
    }

    {
        char buffer[2048] = {0};
        int status = -1;
        bythos_fwupd_updates_status_t updates = BYTHOS_FWUPD_UPDATES_UNKNOWN;

        if (!has_fwupdmgr) {
            EMIT_SKIP_TOOL_OR_UNTRUSTED("firmware update status", "fwupdmgr", "fwupd");
        } else if (!bythos_capture_argv_status(fwupd_updates_argv, buffer, sizeof(buffer), &status)) {
            EMIT_SKIP_EXEC("firmware update status", "fwupdmgr");
        } else if ((updates = bythos_parse_fwupd_updates(buffer, status)) == BYTHOS_FWUPD_UPDATES_NONE) {
            EMIT("firmware update status", CHECK_OK, "no updates available");
        } else if (updates == BYTHOS_FWUPD_UPDATES_AVAILABLE) {
            EMIT("firmware update status", CHECK_WARN, "updates available");
        } else {
            EMIT_SKIP_PROBE("firmware update status", "fwupdmgr");
        }
    }

    /* Firmware update history - informational signal, not a hard posture gate. */
    {
        static const char *const fwupd_history_argv[] = {"fwupdmgr", "get-history", NULL};
        char hist_buffer[2048] = {0};
        int hist_status = -1;

        if (!has_fwupdmgr) {
            EMIT_SKIP_TOOL_OR_UNTRUSTED("firmware update history", "fwupdmgr", "fwupd");
        } else if (!bythos_capture_argv_status(fwupd_history_argv, hist_buffer, sizeof(hist_buffer), &hist_status)) {
            EMIT_SKIP_EXEC("firmware update history", "fwupdmgr");
        } else if (hist_status != 0) {
            if (hist_buffer[0] == '\0' ||
                strstr(hist_buffer, "No history") != NULL ||
                strstr(hist_buffer, "no history") != NULL ||
                strstr(hist_buffer, "No firmware updates") != NULL) {
                EMIT_SKIP_SUBJECT("firmware update history", "firmware history");
            } else {
                EMIT_SKIP_EXEC("firmware update history", "fwupdmgr");
            }
        } else if (hist_buffer[0] != '\0') {
            EMIT("firmware update history", CHECK_OK, "available");
        } else {
            EMIT_SKIP_SUBJECT("firmware update history", "firmware history");
        }
    }

    static const char *const hsi_argv[] = {"fwupdmgr", "security", "--json", NULL};
    char hsi_json[65536] = {0};
    int hsi_status = -1;
    bool hsi_truncated = false;
    bool hsi_ok = false;

    if (has_fwupdmgr &&
        bythos_capture_argv_status_ex(hsi_argv, hsi_json, sizeof(hsi_json), &hsi_status, &hsi_truncated) &&
        hsi_status == 0 &&
        !hsi_truncated &&
        hsi_json[0] != '\0') {
        hsi_ok = true;
    }

    bythos_cpu_vendor_t vendor = bythos_cpu_vendor();

    skip_reason_t hsi_skip_reason = SKIP_NONE;
    const char *hsi_skip_detail = NULL;
    bool hsi_tool_untrusted = false;

    if (!hsi_ok) {
        if (hsi_truncated) {
            hsi_skip_reason = SKIP_OUTPUT_UNPARSEABLE;
            hsi_skip_detail = "fwupdmgr output truncated";
        } else if (has_fwupdmgr) {
            hsi_skip_reason = SKIP_EXEC_FAILED;
            hsi_skip_detail = "fwupdmgr query failed";
        } else if (bythos_command_untrusted("fwupdmgr")) {
            hsi_tool_untrusted = true;
            hsi_skip_detail =
                "fwupdmgr on PATH is not root-owned; refusing to run it as root";
        } else {
            hsi_skip_reason = SKIP_TOOL_ABSENT;
            hsi_skip_detail = "requires fwupd";
        }
    }

#define EMIT_HSI_UNAVAILABLE(name_) \
    do { \
        if (used < max_results) { \
            results[used++] = hsi_tool_untrusted \
                ? make_result((name_), CHECK_WARN, hsi_skip_detail) \
                : hsi_skip_reason == SKIP_TOOL_ABSENT \
                    ? make_skip_actionable((name_), hsi_skip_reason, hsi_skip_detail) \
                    : make_skip((name_), hsi_skip_reason, hsi_skip_detail); \
        } \
    } while (0)

#define EMIT_HSI(name_, id_, positive_, ok_msg_) \
    do { \
        if (used < max_results) { \
            bythos_hsi_attribute_t _a; \
            if (hsi_skip_detail != NULL) { \
                EMIT_HSI_UNAVAILABLE(name_); \
            } else if (!bythos_hsi_find_attribute(hsi_json, (id_), &_a)) { \
                results[used++] = make_skip((name_), SKIP_FEATURE_ABSENT, "not reported"); \
            } else { \
                if (!_a.passing) { \
                    hsi_mark_reported(&hsi_reported, (id_), _a.result); \
                } \
                if (strcmp(_a.result, "not-supported") == 0) { \
                    results[used++] = make_skip((name_), SKIP_FEATURE_ABSENT, "not supported"); \
                } else if ((_a.success[0] != '\0' && strcmp(_a.result, _a.success) == 0) || \
                           (_a.success[0] == '\0' && strcmp(_a.result, (positive_)) == 0)) { \
                    results[used++] = make_result((name_), CHECK_OK, (ok_msg_)); \
                } else { \
                    char _detail[BYTHOS_DETAIL_MAX]; \
                    hsi_format_warn(&_a, _detail, sizeof(_detail)); \
                    results[used++] = make_result((name_), CHECK_WARN, _detail); \
                } \
            } \
        } \
    } while (0)

    hsi_reported_t hsi_reported = {0};

    /* universal */
    EMIT_HSI("HSI: platform fused",
             "org.fwupd.hsi.PlatformFused",           "locked",
             "security fuses set");
    EMIT_HSI("HSI: debug locked",
             "org.fwupd.hsi.PlatformDebugLocked",     "locked",
             "locked");
    EMIT_HSI("HSI: Secure Boot",
             "org.fwupd.hsi.Uefi.SecureBoot",         "enabled",
             "enabled");
    EMIT_HSI("HSI: UEFI PK",
             "org.fwupd.hsi.Uefi.Pk",                 "valid",
             "enrolled");
    EMIT_HSI("HSI: UEFI db",
             "org.fwupd.hsi.Uefi.Db",                 "valid",
             "valid");
    /* no HSI attribute for dbx currency in fwupd; covered by the "dbx size" check */
    EMIT_HSI("HSI: UEFI boot variables",
             "org.fwupd.hsi.Uefi.BootserviceVars",    "locked",
             "locked");
    EMIT_HSI("HSI: capsule updates",
             "org.fwupd.hsi.Bios.CapsuleUpdates",     "enabled",
             "authentication enabled");
    EMIT_HSI("HSI: TPM 2.0",
             "org.fwupd.hsi.Tpm.Version20",           "found",
             "present");
    EMIT_HSI("HSI: TPM empty PCR",
             "org.fwupd.hsi.Tpm.EmptyPcr",            "valid",
             "no unexpected empty PCRs");
    EMIT_HSI("HSI: TPM PCR0 reconstruction",
             "org.fwupd.hsi.Tpm.ReconstructionPcr0",  "valid",
             "valid");
    EMIT_HSI("HSI: IOMMU",
             "org.fwupd.hsi.Iommu",                   "enabled",
             "enabled");
    EMIT_HSI("HSI: pre-boot DMA protection",
             "org.fwupd.hsi.PrebootDma",              "enabled",
             "active");
    EMIT_HSI("HSI: encrypted RAM",
             "org.fwupd.hsi.EncryptedRam",            "enabled",
             "memory encryption active");

    /* AMD-only */
    if (vendor == BYTHOS_CPU_VENDOR_AMD) {
        EMIT_HSI("HSI: platform secure boot",
                 "org.fwupd.hsi.Amd.PlatformSecureBoot",  "enabled",
                 "fused at factory");
        EMIT_HSI("HSI: SMM locked",
                 "org.fwupd.hsi.Amd.SmmLocked",           "locked",
                 "locked");
        EMIT_HSI("HSI: SPI replay protection",
                 "org.fwupd.hsi.Amd.SpiReplayProtection", "enabled",
                 "enabled");
        EMIT_HSI("HSI: firmware rollback protection",
                 "org.fwupd.hsi.Amd.RollbackProtection",  "enabled",
                 "enabled");
        EMIT_HSI("HSI: SPI write protection",
                 "org.fwupd.hsi.Amd.SpiWriteProtection",  "enabled",
                 "enabled");
    }

    /* Intel-only */
    if (vendor == BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_HSI("HSI: SPI BIOSWE",
                 "org.fwupd.hsi.Spi.Bioswe",              "valid",
                 "BIOS write-enable clear");
        EMIT_HSI("HSI: SPI BLE",
                 "org.fwupd.hsi.Spi.Ble",                 "valid",
                 "BIOS lock enabled");
        EMIT_HSI("HSI: SPI SMM_BWP",
                 "org.fwupd.hsi.Spi.SmmBwp",              "valid",
                 "SMM write protection enabled");
        EMIT_HSI("HSI: ME manufacturing mode",
                 "org.fwupd.hsi.Mei.ManufacturingMode",   "locked",
                 "not in manufacturing mode");
        EMIT_HSI("HSI: Boot Guard ACM",
                 "org.fwupd.hsi.IntelBootguard.Acm",      "valid",
                 "valid");
        EMIT_HSI("HSI: Boot Guard policy",
                 "org.fwupd.hsi.IntelBootguard.Policy",   "valid",
                 "valid");

        if (hsi_skip_detail != NULL) {
            EMIT_HSI_UNAVAILABLE("HSI: Boot Guard");
        } else {
            bythos_hsi_attribute_t en_attr;
            bythos_hsi_attribute_t ver_attr;
            bool has_en  = bythos_hsi_find_attribute(hsi_json,
                               "org.fwupd.hsi.IntelBootguard.Enabled", &en_attr);
            bool has_ver = bythos_hsi_find_attribute(hsi_json,
                               "org.fwupd.hsi.IntelBootguard.Verified", &ver_attr);

            if (has_en && !en_attr.passing) {
                hsi_mark_reported(&hsi_reported, "org.fwupd.hsi.IntelBootguard.Enabled",
                                  en_attr.result);
            }
            if (has_ver && !ver_attr.passing) {
                hsi_mark_reported(&hsi_reported, "org.fwupd.hsi.IntelBootguard.Verified",
                                  ver_attr.result);
            }

            if (!has_en) {
                EMIT_SKIP("HSI: Boot Guard", SKIP_FEATURE_ABSENT, "not reported");
            } else if (strcmp(en_attr.result, "not-supported") == 0) {
                EMIT_SKIP("HSI: Boot Guard", SKIP_FEATURE_ABSENT, "not supported");
            } else if (strcmp(en_attr.result, "enabled") != 0) {
                char detail[BYTHOS_DETAIL_MAX];
                hsi_format_warn(&en_attr, detail, sizeof(detail));
                EMIT("HSI: Boot Guard", CHECK_WARN, detail);
            } else if (has_ver && strcmp(ver_attr.result, "enabled") != 0) {
                EMIT("HSI: Boot Guard", CHECK_WARN, "measurement-only");
            } else {
                EMIT("HSI: Boot Guard", CHECK_OK, "enabled and verified");
            }
        }

    }

    {
        bythos_hsi_not_passing_t not_passing = {0};
        if (hsi_skip_detail == NULL) {
            bythos_hsi_collect_not_passing(hsi_json, &not_passing);
        }

        /* not-supported means inapplicable, not weak; the two readers may disagree on hostile output, so no difference may wrap */
        size_t weak = not_passing.total - not_passing.not_supported;
        size_t reported_weak = hsi_reported.count > hsi_reported.not_supported
            ? hsi_reported.count - hsi_reported.not_supported : 0;
        size_t inapplicable = not_passing.not_supported > hsi_reported.not_supported
            ? not_passing.not_supported - hsi_reported.not_supported : 0;

        if (hsi_skip_detail != NULL) {
            EMIT_HSI_UNAVAILABLE("HSI: unmapped attributes");
        } else if (weak > reported_weak) {
            size_t hidden = weak - reported_weak;
            size_t named = 0;
            char names[BYTHOS_DETAIL_MAX] = {0};
            char detail[BYTHOS_DETAIL_MAX];

            (void)hsi_unmapped_detail(detail, sizeof(detail), hidden, names, named,
                                      inapplicable);
            /* name at most `hidden` attributes and only whole identifiers, so the row never claims more than it counts */
            for (size_t i = 0; i < not_passing.named && named < hidden; i++) {
                char next_names[sizeof(names)];
                char next_detail[sizeof(detail)];

                if (hsi_already_reported(&hsi_reported, not_passing.id[i])) {
                    continue;
                }
                int written = snprintf(next_names, sizeof(next_names), "%s%s%s",
                                       names, named == 0 ? "" : ", ",
                                       not_passing.id[i]);
                if (written < 0 || (size_t)written >= sizeof(next_names)) {
                    break;
                }
                if (!hsi_unmapped_detail(next_detail, sizeof(next_detail),
                                         hidden, next_names, named + 1,
                                         inapplicable)) {
                    break;
                }
                memcpy(names, next_names, (size_t)written + 1);
                memcpy(detail, next_detail, strlen(next_detail) + 1);
                named++;
            }

            EMIT("HSI: unmapped attributes", CHECK_WARN, detail);
        } else if (inapplicable > 0) {
            char detail[BYTHOS_DETAIL_MAX];
            snprintf(detail, sizeof(detail),
                "%zu further fwupd %s not-supported, so inapplicable; "
                "nothing else not passing is unreported",
                inapplicable, bythos_pl(inapplicable, "attribute is", "attributes are"));
            EMIT("HSI: unmapped attributes", CHECK_OK, detail);
        } else {
            EMIT("HSI: unmapped attributes", CHECK_OK,
                 "every fwupd attribute not passing is reported above");
        }
    }

#undef EMIT_HSI
#undef EMIT_HSI_UNAVAILABLE

    return used;
}
