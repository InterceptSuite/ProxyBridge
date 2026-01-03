CLANG ?= clang
LLVM_STRIP ?= $(shell which llvm-strip-18 2>/dev/null || which llvm-strip 2>/dev/null || echo llvm-strip)
BPFTOOL ?= bpftool
LIBBPF_DIR = /usr/include
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I$(LIBBPF_DIR) -I/usr/include/$(shell uname -m)-linux-gnu -Isrc
CFLAGS := -O3 -Wall -Wextra -Werror -fPIC -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection -Wformat -Wformat-security -pie -fPIE
LDFLAGS := -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--as-needed
LIB_NAME = libproxybridge.so
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all
all: $(LIB_NAME)

.PHONY: clean
clean:
	rm -f src/*.o src/*.skel.h src/vmlinux.h $(LIB_NAME)

src/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

src/%.bpf.o: src/%.bpf.c src/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

src/%.skel.h: src/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(LIB_NAME): src/proxybridge.c src/proxybridge.skel.h
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -shared -o $@ $< -lbpf -lelf -lz

.PHONY: install
install: $(LIB_NAME)
	install -d $(DESTDIR)/usr/lib
	install -m 755 $(LIB_NAME) $(DESTDIR)/usr/lib/
	install -d $(DESTDIR)/usr/include
	install -m 644 src/proxybridge.h $(DESTDIR)/usr/include/

.PHONY: install-deps
install-deps:
	@echo "Installing required dependencies..."
	@echo "This requires root privileges"
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(shell uname -r) build-essential libelf-dev zlib1g-dev

.PHONY: help
help:
	@echo "ProxyBridge eBPF Library Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build the shared library (default)"
	@echo "  clean         - Remove built files"
	@echo "  install       - Install library and header"
	@echo "  install-deps  - Install required dependencies (requires sudo)"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  1. Run 'make install-deps' to install dependencies"
	@echo "  2. Run 'make' to build the library"
	@echo "  3. Run 'sudo make install' to install system-wide"
