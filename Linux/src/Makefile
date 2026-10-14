CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
MULTIARCH := $(shell $(CC) -print-multiarch)

# BUILD_DIR keeps every generated file (objects, BPF object, skeleton, library) out of the source tree.
# build.sh points it at a temporary directory; a plain `make` builds in place for quick development.
BUILD_DIR ?= .

# EXTRA_CFLAGS / EXTRA_LDFLAGS: e.g. -fsanitize=address,undefined (use STRIP_FLAG= to keep symbols for the report).
STRIP_FLAG ?= -s

CFLAGS = -Wall -Wextra -O2 -fPIC -D_GNU_SOURCE -I$(BUILD_DIR) \
	-fstack-protector-strong \
	-D_FORTIFY_SOURCE=2 \
	-fPIE \
	-Wformat -Wformat-security \
	-Werror=format-security \
	-fno-strict-overflow \
	-fno-delete-null-pointer-checks \
	-fwrapv -fvisibility=hidden -ffunction-sections -fdata-sections $(EXTRA_CFLAGS)
LDFLAGS = -shared -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--gc-sections $(STRIP_FLAG) $(EXTRA_LDFLAGS)
LIBS = -lpthread -lbpf

SOURCES = ProxyBridge.c pb_rules.c pb_dns.c pb_proc.c pb_bpf.c pb_relay.c
OBJECTS = $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))
TARGET = $(BUILD_DIR)/libproxybridge.so
BPF_OBJ = $(BUILD_DIR)/proxybridge.bpf.o
SKEL = $(BUILD_DIR)/proxybridge.skel.h

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(BPF_OBJ): bpf/proxybridge.bpf.c bpf/pb_bpf_shared.h | $(BUILD_DIR)
	$(CLANG) -O2 -g -target bpf -D__BPF__ -I/usr/include/$(MULTIARCH) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@.tmp && mv $@.tmp $@

$(BUILD_DIR)/pb_bpf.o: $(SKEL)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BUILD_DIR)/%.o: %.c pb_internal.h ProxyBridge.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Unit tests (no root needed); binaries go to BUILD_DIR as well.
test-rules: tests/rules_test.c tests/dns_test.c pb_rules.c pb_rules.h pb_dns.c pb_dns.h | $(BUILD_DIR)
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/rules_test.c pb_rules.c -o $(BUILD_DIR)/rules_test && $(BUILD_DIR)/rules_test
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/dns_test.c pb_dns.c -o $(BUILD_DIR)/dns_test && $(BUILD_DIR)/dns_test

clean:
	rm -f $(OBJECTS) $(TARGET) $(BPF_OBJ) $(SKEL) $(BUILD_DIR)/rules_test $(BUILD_DIR)/dns_test

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/lib/
	ldconfig

.PHONY: all clean install test-rules
