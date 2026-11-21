APP_OPTIM := release
APP_PLATFORM := android-29
APP_ABI := arm64-v8a x86_64
# the package and class of the Java side, which hev's JNI wrapper looks up by name
APP_CFLAGS := -O3 -DPKGNAME=com/interceptsuite/proxybridge/vpn -DCLSNAME=HevTunnel
APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
NDK_TOOLCHAIN_VERSION := clang
