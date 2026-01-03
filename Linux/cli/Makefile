CC ?= gcc
CFLAGS := -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS := -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
INCLUDES := -I../src
LIBS := -L../src -lproxybridge

TARGET = proxybridge-cli

.PHONY: all
all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -f $(TARGET)

.PHONY: run
run: $(TARGET)
	sudo LD_LIBRARY_PATH=../src ./$(TARGET)

.PHONY: help
help:
	@echo "ProxyBridge CLI Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all   - Build the CLI executable (default)"
	@echo "  clean - Remove built executable"
	@echo "  run   - Build and run with sudo"
	@echo "  help  - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  1. Build library first: cd ../src && make"
	@echo "  2. Build CLI: make"
	@echo "  3. Run: sudo LD_LIBRARY_PATH=../src ./proxybridge-cli"
