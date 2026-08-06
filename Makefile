CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200809L -Iinclude
TEST_CFLAGS = $(CFLAGS) -DBYTHOS_ALLOW_PATH_OVERRIDE
LDFLAGS ?=

prefix ?= /usr/local
bindir ?= $(prefix)/bin
mandir ?= $(prefix)/share/man/man1
DESTDIR ?=
INSTALL ?= install

# _FORTIFY_SOURCE redefines and skews sanitizer findings - drop under SANITIZE.
ifdef SANITIZE
override CFLAGS  += -fstack-protector-strong -fPIE -fsanitize=address,undefined -fno-omit-frame-pointer -g3
override LDFLAGS += -pie -Wl,-z,relro,-z,now,-z,noexecstack -fsanitize=address,undefined
else
override CFLAGS  += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
override LDFLAGS += -pie -Wl,-z,relro,-z,now,-z,noexecstack
endif

SRC := $(sort $(wildcard src/*.c))
OBJ := $(SRC:.c=.o)
BIN := bythos
MAN1 := man/bythos.1
FIRMWARE_TEST_BIN := tests/firmware_parsers
FIRMWARE_OWNERSHIP_TEST_BIN := tests/firmware_ownership
SILICON_TEST_BIN := tests/silicon_parsers
STORAGE_TEST_BIN := tests/storage_parsers
RUNTIME_TEST_BIN := tests/runtime_capture
EFI_BOOT_TEST_BIN := tests/efi_boot_parsers
ESP_TEST_BIN := tests/esp_posture
SKIP_REASON_TEST_BIN := tests/skip_reason
FUZZ_TEST_BIN := tests/fuzz_parsers
TEST_BINS := $(FUZZ_TEST_BIN) $(FIRMWARE_TEST_BIN) $(FIRMWARE_OWNERSHIP_TEST_BIN) $(SILICON_TEST_BIN) $(STORAGE_TEST_BIN) $(RUNTIME_TEST_BIN) $(EFI_BOOT_TEST_BIN) $(ESP_TEST_BIN) $(SKIP_REASON_TEST_BIN)

.PHONY: all clean run help-check smoke fuzz-test ci-test test host-test asan install uninstall firmware-test firmware-ownership-test silicon-test storage-test runtime-test efi-boot-test esp-test skip-reason-test

.DELETE_ON_ERROR:

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(BIN)
	./$(BIN)

help-check: $(BIN)
	./$(BIN) --help >/dev/null

smoke: $(BIN)
	bash tests/smoke.sh

firmware-test: $(FIRMWARE_TEST_BIN)
	./$(FIRMWARE_TEST_BIN)

firmware-ownership-test: $(FIRMWARE_OWNERSHIP_TEST_BIN)
	./$(FIRMWARE_OWNERSHIP_TEST_BIN)

silicon-test: $(SILICON_TEST_BIN)
	./$(SILICON_TEST_BIN)

storage-test: $(STORAGE_TEST_BIN)
	./$(STORAGE_TEST_BIN)

runtime-test: $(RUNTIME_TEST_BIN)
	./$(RUNTIME_TEST_BIN)

efi-boot-test: $(EFI_BOOT_TEST_BIN)
	./$(EFI_BOOT_TEST_BIN)

esp-test: $(ESP_TEST_BIN)
	./$(ESP_TEST_BIN)

skip-reason-test: $(SKIP_REASON_TEST_BIN)
	./$(SKIP_REASON_TEST_BIN)

fuzz-test: $(FUZZ_TEST_BIN)
	./$(FUZZ_TEST_BIN)

ci-test: help-check fuzz-test firmware-test firmware-ownership-test silicon-test storage-test runtime-test efi-boot-test esp-test skip-reason-test

test: ci-test

host-test: smoke ci-test

asan:
	$(MAKE) clean
	ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 \
	$(MAKE) ci-test SANITIZE=1
	$(MAKE) clean

install: $(BIN) $(MAN1)
	$(INSTALL) -d "$(DESTDIR)$(bindir)" "$(DESTDIR)$(mandir)"
	$(INSTALL) -m 0755 "$(BIN)" "$(DESTDIR)$(bindir)/$(BIN)"
	$(INSTALL) -m 0644 "$(MAN1)" "$(DESTDIR)$(mandir)/bythos.1"

uninstall:
	rm -f "$(DESTDIR)$(bindir)/$(BIN)" "$(DESTDIR)$(mandir)/bythos.1"

$(FIRMWARE_TEST_BIN): tests/firmware_parsers.c src/firmware_parsers.c include/firmware_parsers.h tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/firmware_parsers.c src/firmware_parsers.c -o $@ $(LDFLAGS)

$(FIRMWARE_OWNERSHIP_TEST_BIN): tests/firmware_ownership.c src/firmware_ownership.c src/runtime.c src/firmware_parsers.c include/firmware_ownership.h include/runtime.h include/firmware_parsers.h tests/assert_helpers.h tests/test_harness.h
	$(CC) $(TEST_CFLAGS) tests/firmware_ownership.c src/firmware_ownership.c src/runtime.c src/firmware_parsers.c -o $@ $(LDFLAGS)

$(SILICON_TEST_BIN): tests/silicon_parsers.c src/silicon_parsers.c src/runtime.c include/silicon_parsers.h include/runtime.h tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/silicon_parsers.c src/silicon_parsers.c src/runtime.c -o $@ $(LDFLAGS)

$(STORAGE_TEST_BIN): tests/storage_parsers.c src/storage_parsers.c include/storage_parsers.h tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/storage_parsers.c src/storage_parsers.c -o $@ $(LDFLAGS)

$(RUNTIME_TEST_BIN): tests/runtime_capture.c src/runtime.c include/runtime.h tests/assert_helpers.h tests/test_harness.h
	$(CC) $(TEST_CFLAGS) tests/runtime_capture.c src/runtime.c -o $@ $(LDFLAGS)

$(EFI_BOOT_TEST_BIN): tests/efi_boot_parsers.c src/efi_boot_parsers.c src/runtime.c include/efi_boot_parsers.h include/runtime.h tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/efi_boot_parsers.c src/efi_boot_parsers.c src/runtime.c -o $@ $(LDFLAGS)

$(ESP_TEST_BIN): tests/esp_posture.c src/esp_parsers.c include/esp_parsers.h tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/esp_posture.c src/esp_parsers.c -o $@ $(LDFLAGS)

$(FUZZ_TEST_BIN): tests/fuzz_parsers.c src/efi_boot_parsers.c src/firmware_parsers.c src/esp_parsers.c src/silicon_parsers.c src/storage_parsers.c src/runtime.c tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/fuzz_parsers.c src/efi_boot_parsers.c src/firmware_parsers.c src/esp_parsers.c src/silicon_parsers.c src/storage_parsers.c src/runtime.c -o $@ $(LDFLAGS)

$(SKIP_REASON_TEST_BIN): tests/skip_reason.c src/output.c include/output.h include/types.h tests/assert_helpers.h
	$(CC) $(TEST_CFLAGS) tests/skip_reason.c src/output.c -o $@ $(LDFLAGS)

clean:
	rm -f src/*.o *.o $(BIN) $(TEST_BINS)
