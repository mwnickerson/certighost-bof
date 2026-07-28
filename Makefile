HOST_CC ?= clang
HOST_CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude
PYTHON ?= python3

BOF_CC_MINGW := $(shell command -v x86_64-w64-mingw32-gcc 2>/dev/null)
BOF_CC_CLANG := $(shell command -v /opt/homebrew/opt/llvm@21/bin/clang 2>/dev/null || command -v clang 2>/dev/null)
BOF_CC ?= $(if $(BOF_CC_MINGW),$(BOF_CC_MINGW),$(BOF_CC_CLANG))
BOF_TARGET_FLAG := $(if $(BOF_CC_MINGW),,--target=x86_64-w64-windows-gnu)
BOF_CFLAGS ?= $(BOF_TARGET_FLAG) -O2 -std=c11 -Wall -Wextra -Werror -Iinclude -Isrc -c -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-jump-tables -fwritable-strings

LLVM_NM ?= $(shell command -v /opt/homebrew/opt/llvm@21/bin/llvm-nm 2>/dev/null || command -v llvm-nm 2>/dev/null)
LLVM_OBJDUMP ?= $(shell command -v /opt/homebrew/opt/llvm@21/bin/llvm-objdump 2>/dev/null || command -v llvm-objdump 2>/dev/null)
BOFLINT ?= /Users/redantonetta/Projects/skills/plugins/c2-extensions/skills/c2-bof-development/scripts/boflint.py

BUILD_DIR := build
HOST_TEST := $(BUILD_DIR)/test_core
BOF_OBJ := $(BUILD_DIR)/certighost.x64.o

.PHONY: all bof test lint imports clean

all: bof test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(HOST_TEST): src/certighost_core.c include/certighost_core.h tests/test_core.c | $(BUILD_DIR)
	$(HOST_CC) $(HOST_CFLAGS) src/certighost_core.c tests/test_core.c -o $(HOST_TEST)

test: $(HOST_TEST)
	$(HOST_TEST)
	PYTHONPYCACHEPREFIX=$(BUILD_DIR)/pycache $(PYTHON) -m unittest discover -s tests -p 'test_*.py'

$(BOF_OBJ): src/certighost_bof.c src/certighost_core.c include/certighost_core.h include/certighost_win.h include/beacon.h | $(BUILD_DIR)
	@if [ -z "$(BOF_CC)" ]; then echo "no x86_64-w64-mingw32-gcc or clang available for x64 COFF build" >&2; exit 1; fi
	$(BOF_CC) $(BOF_CFLAGS) src/certighost_bof.c -o $(BOF_OBJ)

bof: $(BOF_OBJ)
	$(LLVM_OBJDUMP) -f $(BOF_OBJ)

lint: $(BOF_OBJ)
	python3 $(BOFLINT) --loader cs $(BOF_OBJ)

imports: $(BOF_OBJ)
	$(LLVM_NM) --undefined-only $(BOF_OBJ)

clean:
	rm -rf $(BUILD_DIR)
