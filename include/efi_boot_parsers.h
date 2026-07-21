#ifndef BYTHOS_EFI_BOOT_PARSERS_H
#define BYTHOS_EFI_BOOT_PARSERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BYTHOS_EFI_BOOT_MAX_ENTRIES 32

typedef enum {
    BYTHOS_EFI_BOOT_TYPE_UNKNOWN = 0,
    BYTHOS_EFI_BOOT_TYPE_DISK,
    BYTHOS_EFI_BOOT_TYPE_CD,
    BYTHOS_EFI_BOOT_TYPE_USB,
    BYTHOS_EFI_BOOT_TYPE_NETWORK,
} bythos_efi_boot_type_t;

typedef struct {
    uint16_t number;
    bool active;
    bythos_efi_boot_type_t type;
    char description[128];
    char filepath[256];
} bythos_efi_boot_entry_t;

typedef struct {
    uint16_t order[BYTHOS_EFI_BOOT_MAX_ENTRIES];
    size_t order_count;
} bythos_efi_boot_order_t;

bool bythos_parse_efi_boot_order(const unsigned char *data, size_t len,
                                     bythos_efi_boot_order_t *order);

bool bythos_parse_efi_boot_entry(const unsigned char *data, size_t len,
                                     uint16_t number,
                                     bythos_efi_boot_entry_t *entry);

bool bythos_parse_efi_boot_next(const unsigned char *data, size_t len,
                                    uint16_t *number);

/* Secure Boot signature database (db/dbx) payload classification */
typedef enum {
    BYTHOS_EFI_SIGDB_NONEMPTY = 0,
    BYTHOS_EFI_SIGDB_EMPTY,
    BYTHOS_EFI_SIGDB_INVALID,
} bythos_efi_sigdb_status_t;

bythos_efi_sigdb_status_t bythos_classify_efi_sigdb(
    const unsigned char *data, size_t len);

size_t bythos_count_efi_sigdb_lists(const unsigned char *data, size_t len);

#endif
