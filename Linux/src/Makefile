include ../common.mk

CLANG ?= clang
BPFTOOL ?= bpftool
MULTIARCH := $(shell $(CC) -print-multiarch)

# BUILD_DIR keeps every generated file out of the source tree; build.sh points it at a temporary directory.
BUILD_DIR ?= .

# libbpf is linked statically from a pinned release built as position-independent code, so the library does not depend on the
# distribution's libbpf (Ubuntu 22.04 ships 0.5, and distribution libbpf.a is not PIC). With LIBBPF_DIR unset the system
# libbpf is used instead.
LIBBPF_VERSION ?= 1.6.3
LIBBPF_SHA256 ?= 989ed3c1a3db8ff0f7c08dd43953c6b9d0c3ac252653a48d566aaedf98bc80ca
LIBBPF_RECIPE ?= 2
LIBBPF_CACHE ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/proxybridge/libbpf-$(LIBBPF_VERSION)-r$(LIBBPF_RECIPE)
LIBBPF_DIR ?=

ifneq ($(LIBBPF_DIR),)
LIBBPF_INCLUDE = -I$(LIBBPF_DIR)/include
LIBBPF_LIBS = $(LIBBPF_DIR)/lib/libbpf.a -lelf -lz
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

test-rules: tests/rules_test.c tests/dns_test.c pb_rules.c pb_rules.h pb_dns.c pb_dns.h | $(BUILD_DIR)
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/rules_test.c pb_rules.c -o $(BUILD_DIR)/rules_test && $(BUILD_DIR)/rules_test
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/dns_test.c pb_dns.c -o $(BUILD_DIR)/dns_test && $(BUILD_DIR)/dns_test

# Downloads, verifies and builds libbpf (cached); prints nothing. `make -s libbpf-path` prints the directory to use as LIBBPF_DIR.
libbpf-static: $(LIBBPF_CACHE)/lib/libbpf.a

$(LIBBPF_CACHE)/lib/libbpf.a:
	@set -e; work=$$(mktemp -d); cd "$$work"; \
	curl -fsSL -o libbpf.tar.gz https://github.com/libbpf/libbpf/archive/refs/tags/v$(LIBBPF_VERSION).tar.gz; \
	echo "$(LIBBPF_SHA256)  libbpf.tar.gz" | sha256sum -c --quiet -; \
	tar xzf libbpf.tar.gz; \
	$(MAKE) -s -C libbpf-$(LIBBPF_VERSION)/src BUILD_STATIC_ONLY=y OBJDIR="$$work/obj" CFLAGS="-O2 -fPIC -include $(CURDIR)/glibc_compat.h" \
		DESTDIR="$$work/root" PREFIX=/ LIBDIR=/lib install >/dev/null; \
	mkdir -p "$(LIBBPF_CACHE)"; cp -r "$$work/root/include" "$$work/root/lib" "$(LIBBPF_CACHE)/"; \
	cd /; rm -rf "$$work"

libbpf-path:
	@echo $(LIBBPF_CACHE)

clean:
	rm -f $(OBJECTS) $(TARGET) $(BPF_OBJ) $(SKEL) $(BUILD_DIR)/rules_test $(BUILD_DIR)/dns_test

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/lib/
	ldconfig

.PHONY: all clean install test-rules libbpf-static libbpf-path
