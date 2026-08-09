# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
# Shell-free: `pwd` and `rm` are unavailable under mingw32-make on Windows.
ifeq ($(origin CC),default)
  ifeq ($(OS),Windows_NT)
    CC := gcc
  else
    CC := cc
  endif
endif

ROOT   := $(CURDIR)/../..
CFLAGS := -I$(ROOT)/include -O2 -Wall -Wextra -std=c11
LIB    := $(ROOT)/libUniCrypto.a

ifeq ($(OS),Windows_NT)
  BIN  := test_unicrypto.exe
  RUN  := $(BIN)
  RM_F := del /q
else
  BIN  := test_unicrypto
  RUN  := ./$(BIN)
  RM_F := rm -f
endif

.PHONY: all test run clean
all: test
test: run
run: $(BIN)
	$(RUN)
$(BIN): test_unicrypto.c $(ROOT)/include/UniCrypto.h $(LIB)
	$(CC) $(CFLAGS) -o $(BIN) test_unicrypto.c $(LIB)
# File target, not phony: `nimble ctest` already built the lib, don't redo it.
$(LIB):
	cd $(ROOT) && nimble clibStatic
clean:
	$(RM_F) $(BIN)
