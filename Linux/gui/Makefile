include ../common.mk

BUILD_DIR ?= .
LIBDIR ?= ../src

# Compile-time API limits keep the GUI runnable on Ubuntu 22.04 (GTK 3.24.33, GLib 2.72).
GTK_CFLAGS = $(shell pkg-config --cflags gtk+-3.0) -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_22 -DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_3_22 \
	-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_72 -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_72
GTK_LIBS = $(shell pkg-config --libs gtk+-3.0)

CFLAGS = $(CFLAGS_COMMON) -Wno-unused-parameter -fPIE -D_GNU_SOURCE -I../src -I../profile $(GTK_CFLAGS)
LDFLAGS = -pie $(HARDEN_LDFLAGS) -L$(LIBDIR) -Wl,-rpath,'$$ORIGIN' -export-dynamic $(STRIP_FLAG)
LIBS = -lproxybridge -lpthread $(GTK_LIBS)

SOURCES = $(filter-out tests/%,$(wildcard *.c))
OBJECTS = $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o)) $(BUILD_DIR)/pb_profile.o $(BUILD_DIR)/pb_ipc.o $(BUILD_DIR)/pb_unit.o
TARGET = $(BUILD_DIR)/ProxyBridgeGUI

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: %.c gui.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pb_profile.o: ../profile/pb_profile.c ../profile/pb_profile.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pb_ipc.o: ../src/pb_ipc.c ../src/pb_ipc.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pb_unit.o: ../src/pb_unit.c ../src/pb_unit.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
