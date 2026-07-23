# bythos

![Linux](https://img.shields.io/badge/Linux-FFA500?logo=linux&logoColor=black&labelColor=FFA500) ![C11](https://img.shields.io/badge/C11-A8B9CC?logo=c&logoColor=black&labelColor=A8B9CC) ![Zero--deps](https://img.shields.io/badge/Zero--deps-brightgreen.svg) ![UEFI](https://img.shields.io/badge/UEFI-firmware%20trust-7B68EE?labelColor=7B68EE)

Read-only firmware trust posture auditor for Linux. Single C11 binary, no
daemon, zero third-party deps.

bythos does not harden. It reads, classifies, prints, exits.

## At a glance

```text
+-----------------------------------------------------------------------------------------+
| BYTHOS 0.1.0                                                ~81 checks · 10 subgroups   |
+----------------+-----------------+-----------------+-----------------+------------------+
| Trust layer    | hardware        | firmware        | Secure Boot     | boot chain       |
+================+=================+=================+=================+==================+
|                | TPM             | BIOS_CNTL       | db, dbx         | shim             |
|  sample        | IOMMU           | Intel ME        | MOK, PK         | SBAT             |
|  checks        | Thunderbolt     | Intel DCI       | SbatLevel       | BootOrder        |
|                | DMA             | AMD PSP         | CA breadth      | BootNext         |
|                | ...             | ...             | ...             | ...              |
+----------------+-----------------+-----------------+-----------------+------------------+

+-------------------+---------------------------------------------------------------------+
| Subgroup          | Sample checks                                                       |
+===================+=====================================================================+
| EFI               | EFI boot mode, ESRT entries                                         |
| Secure Boot       | state, setup mode, db/dbx, SBAT, MOK, trust breadth, efivarfs       |
| Boot chain        | shim signature, SBAT revocations, BootOrder, EFI one-shot boot, ... |
| ESP               | ownership, filesystem type, fallback boot binary, capsules          |
| TPM               | TPM 2.0, DA lockout, PCR 0/7, event-log CRTM signal                 |
| LUKS              | encrypted volumes, LUKS2 version, dm-integrity, TPM2 binding tiers  |
| Platform firmware | BIOS_CNTL, Intel ME, Intel DCI, AMD PSP, chipsec availability       |
| Platform DMA      | IOMMU groups, IOMMU DMA posture, Thunderbolt DMA protection         |
| CPU               | microcode, kernel vulnerability status, memory encryption, scan     |
| fwupd             | service state, LVFS, inventory, updates, history, HSI signals       |
+-------------------+---------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------+
| Reads:      sysfs . efivarfs . /proc . PCI config . MSRs . trusted CLI helpers          |
| Outputs:    plain colored text  |  --json (CI / dashboards / posture diffs)             |
| Exit:       0 = no FAIL  |  1 = FAIL  |  2 = usage error                                |
+-----------------------------------------------------------------------------------------+
```

## Mini example

Plain output is colored in a terminal; `--json` emits the same tree for CI and posture diffs.

```text
$ sudo bythos
  [bythos] firmware trust posture
    warn:  55 ok  8 warn  0 fail  12 skip

    secure boot:
      ok    state              Secure Boot enabled
      ok    SBAT policy level  SbatLevel: sbat,1,2024010100
      warn  trust breadth      Microsoft 3rd Party UEFI CA in db

    tpm:
      ok    PCR 0  non-zero; firmware measured at boot
      ok    PCR 7  non-zero; Secure Boot state measured

    platform firmware:
      ok    Intel BIOS write protection  BLE and SMM_BWP set; BIOS region protected
      ok    Intel DCI                    DCI disabled and locked

    fwupd:
      ok    HSI: Boot Guard               enabled and verified
      ok    HSI: pre-boot DMA protection  active
```

## Quick Start

```bash
git clone https://github.com/q1sh101/bythos
cd bythos && make && sudo make install

sudo bythos       # requires root for full coverage
bythos --json     # machine-readable output
bythos --help
bythos --version
```

Install paths can be overridden with `prefix`, `bindir`, `mandir`, `DESTDIR`.
Remove with `sudo make uninstall`.

## How It Works

**bythos opens no sockets, writes no files, runs no shell, and ignores `$PATH`.**
Helpers are spawned via `fork` + `execvp` against a compile-time PATH; their
output is captured through a bounded pipe with a 10-second timeout and parsed
by hand-written C parsers.

PE/COFF parsing extracts `.sbat` from installed shim/grub binaries. JSON
output escapes control characters and sanitizes invalid UTF-8.

## Optional Helpers

bythos reads kernel-exposed state without extra packages. Helpers expand
coverage:

| Helper       | Adds coverage for                                  |
|--------------|----------------------------------------------------|
| `fwupdmgr`   | HSI signals, firmware inventory, update status     |
| `mokutil`    | Secure Boot state, MOK, trust breadth, SBAT        |
| `sbctl`      | Secure Boot owner GUID and vendor-key state        |
| `tpm2-tools` | TPM PCR reads and dictionary-attack lockout policy |
| `dmidecode`  | SMBIOS firmware password status                    |

Narrower probes also use `cryptsetup`, `lsblk`, `pesign`, `sha256sum`, and
`systemctl`. `chipsec` and `spectre-meltdown-checker` are detected for
availability only. Missing helpers degrade their checks to `skip`, never `fail`.

## Output States

| State  | Meaning                                      |
|--------|----------------------------------------------|
| `ok`   | Expected posture was observed                |
| `warn` | Weaker posture, stale state, or softer risk  |
| `fail` | Direct posture regression                    |
| `skip` | Not applicable or not observable on this run |

`skip` is not a hidden pass. It means bythos could not make that observation:
hardware absent, helper missing, field absent, root required, vendor mismatch,
or output unparseable, among other typed reasons (full list in `man bythos`).

Plain output uses lowercase labels. `--json` capitalizes them (`OK`, `WARN`,
`FAIL`, `SKIP`) and adds a `skip_reason` field per row. Exit codes are
listed in the overview at the top.

## Comparison

| Tool       | Layer                       | Best at                         | Footprint             |
|------------|-----------------------------|---------------------------------|-----------------------|
| **bythos** | UEFI / TPM / DMA / EFI vars | Firmware trust posture report   | read-only, userland   |
| lynis      | OS configuration            | Compliance hardening sweep      | read-only, user/root  |
| aide       | Filesystem hashes           | Post-deploy integrity tripwire  | writes hash DB, root  |
| chkrootkit | Known-bad signatures        | Userland rootkit detection      | read-only, root       |
| fwupdmgr   | LVFS + HSI subset           | Firmware updates and HSI report | writes firmware, root |
| fwts       | ACPI / SMBIOS / UEFI tests  | Firmware compliance test suite  | read-only, root       |
| chipsec    | SMI / SMM / SPI flash       | Deep firmware research audit    | kernel module, root   |

chipsec goes deeper and needs lower-level access. bythos stays in userland and
reads what Linux already exposes.

## Requirements

**Runtime**:
- Linux 5.x or newer
- UEFI host recommended
- x86_64 primary; ARM64 coverage is narrower

**Build**:
- glibc or musl
- GNU Make and a C11 compiler

On legacy BIOS hosts and inside containers, most firmware paths are
unavailable; bythos still completes, marking missing checks as `skip` and
flagging absent EFI runtime as `warn`.

## Limitations

- Pre-OS firmware internals (SMI / SMM / SPI flash) are not exposed by Linux and are invisible to bythos.
- Versions and posture only - not a CVE scanner.
- Hash comparisons confirm file identity, not Authenticode chain validity.
- BMC / IPMI / iLO / iDRAC management plane is out of scope.
- PCR reads are local observations; remote attestation is out of scope.
- ACPI / SMBIOS structural validation is out of scope (see `fwts`).
- Userland security (processes, memory, network) is out of scope.

## Build and Test

```bash
make          # build bythos
make ci-test  # unit suite
make smoke    # end-to-end smoke test
make asan     # ASan + UBSan unit suite
```

The default build uses `-Wall -Wextra -Wpedantic -Werror`,
`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, PIE, RELRO, now binding, and
non-executable stack linker flags. ASan and UBSan are clean on the unit suite
and live binary.

## Contributing

Found a bug or have a feature request? Open an issue at
[github.com/q1sh101/bythos](https://github.com/q1sh101/bythos/issues)

Human-written PRs only; LLM-generated submissions are not accepted.

Built for engineers who care about firmware trust.

**Built by** Giorgi Kishmareia · [q1sh101](https://github.com/q1sh101)
