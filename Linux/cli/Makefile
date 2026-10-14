include ../common.mk

# BUILD_DIR / LIBDIR: where generated files go and where libproxybridge.so was built (build.sh sets both).
BUILD_DIR ?= .
LIBDIR ?= ../src

CFLAGS = $(CFLAGS_COMMON) -fPIE -I../src
LDFLAGS = -pie $(HARDEN_LDFLAGS) -L$(LIBDIR) -Wl,-rpath,/usr/local/lib $(STRIP_FLAG)
LIBS = -lproxybridge -lpthread

TARGET = $(BUILD_DIR)/ProxyBridge
OBJECTS = $(BUILD_DIR)/main.o

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
