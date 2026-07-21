#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "firmware_parsers.h"
#include "runtime.h"
#include "silicon_parsers.h"

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
    static const char *fwupd_devices_argv[] = {"fwupdmgr", "get-devices", NULL};
    static const char *fwupd_updates_argv[] = {"fwupdmgr", "get-updates", NULL};

    has_fwupdmgr = bythos_command_exists("fwupdmgr");

    switch (bythos_probe_systemd_service("fwupd.service")) {
    case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
        EMIT_SKIP_TOOL_INSTALL("fwupd service", "systemd");
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
        EMIT_SKIP_TOOL_INSTALL("auto-refresh timer", "systemd");
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
            EMIT_SKIP_TOOL_INSTALL("LVFS remote", "fwupd");
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
            EMIT_SKIP_TOOL_INSTALL("firmware inventory", "fwupd");
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
            EMIT_SKIP_TOOL_INSTALL("firmware update status", "fwupd");
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
        static const char *fwupd_history_argv[] = {"fwupdmgr", "get-history", NULL};
        char hist_buffer[2048] = {0};
        int hist_status = -1;

        if (!has_fwupdmgr) {
            EMIT_SKIP_TOOL_INSTALL("firmware update history", "fwupd");
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

    if (!hsi_ok) {
        if (hsi_truncated) {
            EMIT_SKIP("HSI query", SKIP_OUTPUT_UNPARSEABLE, "fwupdmgr output truncated");
        } else if (has_fwupdmgr) {
            EMIT_SKIP_EXEC("HSI query", "fwupdmgr");
        } else {
            EMIT_SKIP_TOOL_INSTALL("HSI query", "fwupd");
        }
        return used;
    }

#define EMIT_HSI(name_, id_, positive_, ok_msg_) \
    do { \
        if (used < max_results) { \
            bythos_hsi_attribute_t _a; \
            if (!bythos_hsi_find_attribute(hsi_json, (id_), &_a)) { \
                results[used++] = make_skip((name_), SKIP_FEATURE_ABSENT, "not reported"); \
            } else if (strcmp(_a.result, "not-supported") == 0) { \
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
    } while (0)

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

        {
            bythos_hsi_attribute_t en_attr;
            bythos_hsi_attribute_t ver_attr;
            bool has_en  = bythos_hsi_find_attribute(hsi_json,
                               "org.fwupd.hsi.IntelBootguard.Enabled", &en_attr);
            bool has_ver = bythos_hsi_find_attribute(hsi_json,
                               "org.fwupd.hsi.IntelBootguard.Verified", &ver_attr);

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

#undef EMIT_HSI

    return used;
}
