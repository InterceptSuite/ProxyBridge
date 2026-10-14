# Compiler and linker flags shared by the library, the CLI and the GUI.
#   OPT=-O2        optimisation level          LTO=0      disable link-time optimisation
#   WERROR=1       warnings are errors (CI)    EXTRA_CFLAGS / EXTRA_LDFLAGS   e.g. sanitizers
CC ?= gcc
OPT ?= -O2
LTO ?= 1

# Keeps a flag only if the compiler accepts it (other GCC versions and architectures differ).
cc-option = $(shell $(CC) $(1) -Werror -x c -c /dev/null -o /dev/null 2>/dev/null && echo $(1))

HARDEN_CFLAGS = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
	$(call cc-option,-fstack-clash-protection) $(call cc-option,-fcf-protection=full) \
	$(call cc-option,-mbranch-protection=standard) $(call cc-option,-ftrivial-auto-var-init=zero) \
	$(call cc-option,-fno-plt) -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv \
	-Wformat -Wformat-security -Werror=format-security

CFLAGS_COMMON = $(OPT) -Wall -Wextra $(if $(WERROR),-Werror) $(HARDEN_CFLAGS) \
	-ffunction-sections -fdata-sections $(if $(filter 1,$(LTO)),-flto=auto) $(EXTRA_CFLAGS)

HARDEN_LDFLAGS = -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--as-needed -Wl,--gc-sections \
	$(if $(filter 1,$(LTO)),-flto=auto) $(EXTRA_LDFLAGS)

STRIP_FLAG ?= -s
