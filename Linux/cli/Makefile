CC = gcc

# BUILD_DIR / LIBDIR: where generated files go and where libproxybridge.so was built (build.sh sets both).
BUILD_DIR ?= .
LIBDIR ?= ../src

CFLAGS = -Wall -Wextra -O3 -I../src \
	-fstack-protector-strong \
	-D_FORTIFY_SOURCE=2 \
	-fPIE \
	-Wformat -Wformat-security \
	-Werror=format-security \
	-fno-strict-overflow \
	-fno-delete-null-pointer-checks \
	-fwrapv
LDFLAGS = -L$(LIBDIR) -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -s \
	-Wl,-rpath,/usr/local/lib
LIBS = -lproxybridge -lpthread

TARGET = $(BUILD_DIR)/ProxyBridge
SOURCES = main.c
OBJECTS = $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "Stripping debug symbols..."
	strip --strip-all $@

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
