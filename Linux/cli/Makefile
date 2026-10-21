include ../common.mk

# BUILD_DIR / LIBDIR: where generated files go and where libproxybridge.so was built (build.sh sets both).
BUILD_DIR ?= .
LIBDIR ?= ../src

CFLAGS = $(CFLAGS_COMMON) -fPIE -I../src -I../profile
LDFLAGS = -pie $(HARDEN_LDFLAGS) $(STRIP_FLAG)

# With LIBBPF_DIR (the pinned static libbpf, libelf and zlib built by src/Makefile) the engine objects are linked straight into
# the program: one self-contained file that needs nothing but glibc and runs from any directory. Without it the program uses
# libproxybridge.so (a build against the distribution's libbpf).
LIBBPF_DIR ?=
ENGINE = ProxyBridge pb_rules pb_dns pb_proc pb_bpf pb_relay
ifneq ($(LIBBPF_DIR),)
ENGINE_OBJECTS = $(addprefix $(LIBDIR)/,$(addsuffix .o,$(ENGINE)))
LIBS = $(ENGINE_OBJECTS) $(LIBBPF_DIR)/lib/libbpf.a $(LIBBPF_DIR)/lib/libelf.a $(LIBBPF_DIR)/lib/libz.a -lpthread
else
LDFLAGS += -L$(LIBDIR) -Wl,-rpath,/usr/local/lib
LIBS = -lproxybridge -lpthread
endif

TARGET = $(BUILD_DIR)/ProxyBridge
OBJECTS = $(BUILD_DIR)/main.o $(BUILD_DIR)/daemon.o $(BUILD_DIR)/pb_profile.o $(BUILD_DIR)/pb_ipc.o $(BUILD_DIR)/pb_unit.o

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pb_unit.o: ../src/pb_unit.c ../src/pb_unit.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pb_ipc.o: ../src/pb_ipc.c ../src/pb_ipc.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pb_profile.o: ../profile/pb_profile.c ../profile/pb_profile.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
