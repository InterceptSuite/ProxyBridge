CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
MULTIARCH := $(shell $(CC) -print-multiarch)

CFLAGS = -Wall -Wextra -O2 -fPIC -D_GNU_SOURCE \
	-fstack-protector-strong \
	-D_FORTIFY_SOURCE=2 \
	-fPIE \
	-Wformat -Wformat-security \
	-Werror=format-security \
	-fno-strict-overflow \
	-fno-delete-null-pointer-checks \
	-fwrapv
LDFLAGS = -shared -Wl,-z,relro,-z,now -Wl,-z,noexecstack -s
LIBS = -lpthread -lbpf

TARGET = libproxybridge.so
SOURCES = ProxyBridge.c pb_rules.c pb_dns.c pb_bpf.c pb_relay.c
OBJECTS = $(SOURCES:.c=.o)
BPF_OBJ = bpf/proxybridge.bpf.o
SKEL = proxybridge.skel.h

all: $(TARGET)

$(BPF_OBJ): bpf/proxybridge.bpf.c bpf/pb_bpf_shared.h
	$(CLANG) -O2 -g -target bpf -D__BPF__ -I/usr/include/$(MULTIARCH) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

pb_bpf.o: $(SKEL)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c pb_internal.h ProxyBridge.h
	$(CC) $(CFLAGS) -c $< -o $@

test-rules: tests/rules_test.c tests/dns_test.c pb_rules.c pb_rules.h pb_dns.c pb_dns.h
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/rules_test.c pb_rules.c -o tests/rules_test && tests/rules_test
	$(CC) -Wall -Wextra -g -fsanitize=address,undefined -D_GNU_SOURCE tests/dns_test.c pb_dns.c -o tests/dns_test && tests/dns_test

clean:
	rm -f $(OBJECTS) $(TARGET) $(BPF_OBJ) $(SKEL) tests/rules_test tests/dns_test

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/lib/
	ldconfig

.PHONY: all clean install test-rules
