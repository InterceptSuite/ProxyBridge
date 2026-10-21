include ../common.mk

CLANG ?= clang
BPFTOOL ?= bpftool
MULTIARCH := $(shell $(CC) -print-multiarch)

# BUILD_DIR keeps every generated file out of the source tree; build.sh points it at a temporary directory.
BUILD_DIR ?= .

# libbpf, libelf and zlib are linked statically from pinned releases built as position-independent code, so the library
# depends on nothing but glibc: not on the distribution's libbpf (Ubuntu 22.04 ships 0.5), and not on libelf or zlib
# (distribution .a files are not PIC). With LIBBPF_DIR unset the system libbpf is used instead.
LIBBPF_VERSION ?= 1.6.3
LIBBPF_SHA256 ?= 989ed3c1a3db8ff0f7c08dd43953c6b9d0c3ac252653a48d566aaedf98bc80ca
ZLIB_VERSION ?= 1.3.1
ZLIB_SHA256 ?= 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
ELFUTILS_VERSION ?= 0.191
ELFUTILS_SHA256 ?= df76db71366d1d708365fc7a6c60ca48398f14367eb2b8954efc8897147ad871
LIBBPF_RECIPE ?= 3
LIBBPF_CACHE ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/proxybridge/libbpf-$(LIBBPF_VERSION)-r$(LIBBPF_RECIPE)
LIBBPF_DIR ?=

ifneq ($(LIBBPF_DIR),)
LIBBPF_INCLUDE = -I$(LIBBPF_DIR)/include
LIBBPF_LIBS = $(LIBBPF_DIR)/lib/libbpf.a $(LIBBPF_DIR)/lib/libelf.a $(LIBBPF_DIR)/lib/libz.a
else
LIBBPF_LIBS = -lbpf
endif

CFLAGS = $(CFLAGS_COMMON) -fPIC -fvisibility=hidden -D_GNU_SOURCE -I$(BUILD_DIR) $(LIBBPF_INCLUDE)
LDFLAGS = -shared $(HARDEN_LDFLAGS) -Wl,-z,defs -Wl,--version-script=$(CURDIR)/exports.map $(STRIP_FLAG)
LIBS = -lpthread $(LIBBPF_LIBS)

SOURCES = ProxyBridge.c pb_rules.c pb_dns.c pb_proc.c pb_bpf.c pb_relay.c
OBJECTS = $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))
TARGET = $(BUILD_DIR)/libproxybridge.so
BPF_OBJ = $(BUILD_DIR)/proxybridge.bpf.o
SKEL = $(BUILD_DIR)/proxybridge.skel.h

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BPF_OBJ): bpf/proxybridge.bpf.c bpf/pb_bpf_shared.h | $(BUILD_DIR)
	$(CLANG) -O2 -g -target bpf -D__BPF__ $(LIBBPF_INCLUDE) -I/usr/include/$(MULTIARCH) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@.tmp && mv $@.tmp $@

$(BUILD_DIR)/pb_bpf.o: $(SKEL)

$(TARGET): $(OBJECTS) exports.map
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

$(BUILD_DIR)/%.o: %.c pb_internal.h ProxyBridge.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

test-rules: tests/rules_test.c tests/dns_test.c tests/proc_test.c tests/ipc_test.c pb_rules.c pb_rules.h pb_dns.c pb_dns.h pb_proc.c pb_proc.h pb_ipc.c pb_ipc.h | $(BUILD_DIR)
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/rules_test.c pb_rules.c -o $(BUILD_DIR)/rules_test && $(BUILD_DIR)/rules_test
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/dns_test.c pb_dns.c -o $(BUILD_DIR)/dns_test && $(BUILD_DIR)/dns_test
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/proc_test.c pb_proc.c -o $(BUILD_DIR)/proc_test && $(BUILD_DIR)/proc_test
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/ipc_test.c pb_ipc.c -o $(BUILD_DIR)/ipc_test && $(BUILD_DIR)/ipc_test

# Downloads, verifies and builds zlib, libelf (from elfutils) and libbpf (cached); prints nothing. `make -s libbpf-path` prints
# the directory to use as LIBBPF_DIR. Every download is checked against a pinned SHA-256.
libbpf-static: $(LIBBPF_CACHE)/lib/libbpf.a

$(LIBBPF_CACHE)/lib/libbpf.a:
	@set -e; work=$$(mktemp -d); cd "$$work"; root="$$work/root"; mkdir -p "$$root/include" "$$root/lib"; \
	fetch() { curl -fsSL -o "$$1" "$$2"; echo "$$3  $$1" | sha256sum -c --quiet -; }; \
	fetch zlib.tar.gz https://github.com/madler/zlib/releases/download/v$(ZLIB_VERSION)/zlib-$(ZLIB_VERSION).tar.gz $(ZLIB_SHA256); \
	fetch elfutils.tar.bz2 https://sourceware.org/elfutils/ftp/$(ELFUTILS_VERSION)/elfutils-$(ELFUTILS_VERSION).tar.bz2 $(ELFUTILS_SHA256); \
	fetch libbpf.tar.gz https://github.com/libbpf/libbpf/archive/refs/tags/v$(LIBBPF_VERSION).tar.gz $(LIBBPF_SHA256); \
	tar --no-same-owner -xzf zlib.tar.gz; tar --no-same-owner -xjf elfutils.tar.bz2; tar --no-same-owner -xzf libbpf.tar.gz; \
	( cd zlib-$(ZLIB_VERSION) && CFLAGS="-O2 -fPIC -include $(CURDIR)/glibc_compat.h" ./configure --static --prefix="$$root" >/dev/null && $(MAKE) -s install >/dev/null ); \
	( cd elfutils-$(ELFUTILS_VERSION) && CFLAGS="-O2 -fPIC -Wno-error -include $(CURDIR)/glibc_compat.h" CPPFLAGS="-I$$root/include" LDFLAGS="-L$$root/lib" \
	  ./configure --disable-debuginfod --disable-libdebuginfod --disable-nls \
	  --without-bzlib --without-lzma --without-zstd --disable-demangler --disable-symbol-versioning >/dev/null && \
	  $(MAKE) -s -C lib >/dev/null && $(MAKE) -s -C libelf libelf.a >/dev/null && \
	  cp libelf/libelf.a "$$root/lib/" && cp libelf/libelf.h libelf/gelf.h libelf/nlist.h "$$root/include/" ); \
	$(MAKE) -s -C libbpf-$(LIBBPF_VERSION)/src BUILD_STATIC_ONLY=y OBJDIR="$$work/obj" PKG_CONFIG=true \
		CFLAGS="-O2 -fPIC -I$$root/include -include $(CURDIR)/glibc_compat.h" \
		DESTDIR="$$work/root" PREFIX=/ LIBDIR=/lib install >/dev/null; \
	mkdir -p "$(LIBBPF_CACHE)"; cp -r "$$root/include" "$$root/lib" "$(LIBBPF_CACHE)/"; \
	cd /; rm -rf "$$work"

libbpf-path:
	@echo $(LIBBPF_CACHE)

clean:
	rm -f $(OBJECTS) $(TARGET) $(BPF_OBJ) $(SKEL) $(BUILD_DIR)/rules_test $(BUILD_DIR)/dns_test

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/lib/
	ldconfig

.PHONY: all clean install test-rules libbpf-static libbpf-path
