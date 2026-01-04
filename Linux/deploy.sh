#!/bin/bash

# ProxyBridge Deployment Script
# Simple automated deployment with requirement checks

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

print_info() {
    echo -e "  $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root (sudo ./deploy.sh)"
        exit 1
    fi
}

# Check kernel version (need 4.18+)
check_kernel() {
    echo "Checking kernel version..."
    KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
    MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    
    if [ "$MAJOR" -lt 4 ] || { [ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 18 ]; }; then
        print_error "Kernel version $KERNEL_VERSION is too old"
        print_info "ProxyBridge requires kernel 4.18 or newer"
        print_info "Your kernel: $(uname -r)"
        print_warning "Please update your kernel manually and retry"
        exit 1
    fi
    
    print_success "Kernel $(uname -r) is compatible"
}

# Check cgroup v2
check_cgroup() {
    echo "Checking cgroup v2..."
    if mount | grep -q "cgroup2 on /sys/fs/cgroup"; then
        print_success "cgroup v2 is mounted"
    elif [ -d /sys/fs/cgroup/cgroup.controllers ]; then
        print_success "cgroup v2 is available"
    else
        print_error "cgroup v2 not found"
        print_info "ProxyBridge requires cgroup v2 (unified cgroup hierarchy)"
        print_info "Add 'systemd.unified_cgroup_hierarchy=1' to kernel boot parameters"
        exit 1
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
        print_info "Detected: Debian/Ubuntu (apt)"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
        print_info "Detected: Fedora/RHEL 8+ (dnf)"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
        print_info "Detected: CentOS/RHEL 7 (yum)"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MANAGER="pacman"
        print_info "Detected: Arch Linux (pacman)"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MANAGER="zypper"
        print_info "Detected: openSUSE (zypper)"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MANAGER="apk"
        print_info "Detected: Alpine Linux (apk)"
    else
        print_error "No supported package manager found"
        print_info "Supported: apt, dnf, yum, pacman, zypper, apk"
        exit 1
    fi
}

# Check and install libraries
check_install_libs() {
    echo "Checking required libraries..."
    
    MISSING_LIBS=()
    
    # Check each library
    if ! ldconfig -p | grep -q "libbpf.so.1"; then
        MISSING_LIBS+=("libbpf")
    fi
    
    if ! ldconfig -p | grep -q "libelf.so.1"; then
        MISSING_LIBS+=("libelf")
    fi
    
    if ! ldconfig -p | grep -q "libz.so.1"; then
        MISSING_LIBS+=("zlib")
    fi
    
    if ! ldconfig -p | grep -q "libzstd.so.1"; then
        MISSING_LIBS+=("libzstd")
    fi
    
    if [ ${#MISSING_LIBS[@]} -eq 0 ]; then
        print_success "All required libraries are installed"
        return
    fi
    
    # Install missing libraries
    print_warning "Missing libraries: ${MISSING_LIBS[*]}"
    echo "Installing required libraries..."
    
    case "$PKG_MANAGER" in
        apt)
            apt-get update -qq
            for lib in "${MISSING_LIBS[@]}"; do
                case $lib in
                    libbpf) apt-get install -y libbpf1 ;;
                    libelf) apt-get install -y libelf1 ;;
                    zlib) apt-get install -y zlib1g ;;
                    libzstd) apt-get install -y libzstd1 ;;
                esac
            done
            ;;
        dnf|yum)
            for lib in "${MISSING_LIBS[@]}"; do
                case $lib in
                    libbpf) $PKG_MANAGER install -y libbpf ;;
                    libelf) $PKG_MANAGER install -y elfutils-libelf ;;
                    zlib) $PKG_MANAGER install -y zlib ;;
                    libzstd) $PKG_MANAGER install -y libzstd ;;
                esac
            done
            ;;
        pacman)
            for lib in "${MISSING_LIBS[@]}"; do
                case $lib in
                    libbpf) pacman -S --noconfirm libbpf ;;
                    libelf) pacman -S --noconfirm libelf ;;
                    zlib) pacman -S --noconfirm zlib ;;
                    libzstd) pacman -S --noconfirm zstd ;;
                esac
            done
            ;;
        zypper)
            for lib in "${MISSING_LIBS[@]}"; do
                case $lib in
                    libbpf) zypper install -y libbpf1 ;;
                    libelf) zypper install -y libelf1 ;;
                    zlib) zypper install -y libz1 ;;
                    libzstd) zypper install -y libzstd1 ;;
                esac
            done
            ;;
        apk)
            apk add --no-cache libbpf elfutils zlib zstd-libs
            ;;
    esac
    
    print_success "Libraries installed successfully"
    ldconfig 2>/dev/null || true
}



# Main deployment
main() {
    echo "======================================="
    echo "  ProxyBridge Deployment"
    echo "======================================="
    echo ""
    
    check_root
    check_kernel
    check_cgroup
    detect_package_manager
    check_install_libs
    
    echo ""
    echo "======================================="
    print_success "Deployment completed successfully!"
    echo "======================================="
    echo ""
    print_info "Run 'proxybridge --help' to get started"
    echo ""
}

main
