TEST_DIR=x86
cstart.o = $(TEST_DIR)/cstart64.o
bits = 64
ldarch = elf64-x86-64
CFLAGS += -D__x86_64__

tests = $(TEST_DIR)/access.flat $(TEST_DIR)/sieve.flat \
	  $(TEST_DIR)/emulator.flat $(TEST_DIR)/apic.flat

include config-x86-common.mak