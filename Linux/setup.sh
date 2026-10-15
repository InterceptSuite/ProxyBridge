#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "==================================="
echo "ProxyBridge Setup Script"
echo "==================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    echo "Please run: sudo ./setup.sh"
    exit 1
fi

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=$ID_LIKE
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
    else
        DISTRO=$(uname -s)
    fi
    echo "Detected distribution: $DISTRO"
}

# Install dependencies based on distribution
install_dependencies() {
    echo ""
    echo "Checking and installing dependencies..."
    
    # Normalize distro name using ID_LIKE fallback
    local distro_family="$DISTRO"
    if [ -n "$DISTRO_LIKE" ]; then
        case "$DISTRO_LIKE" in
            *ubuntu*|*debian*) distro_family="debian" ;;
            *fedora*) distro_family="fedora" ;;
            *rhel*|*centos*) distro_family="rhel" ;;
            *arch*) distro_family="arch" ;;
            *suse*) distro_family="opensuse" ;;
        esac
    fi
    
    case "$distro_family" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|raspbian|mx|antix|deepin|lmde)
            echo "Using apt package manager..."
            apt-get update -qq
            # libgtk-3-0 is for the GUI, libelf+zlib are what the statically linked libbpf needs
            apt-get install -y libelf1 zlib1g libgtk-3-0
            ;;
        fedora)
            echo "Using dnf package manager..."
            dnf install -y elfutils-libelf zlib gtk3
            ;;
        rhel|centos|rocky|almalinux)
            echo "Using yum package manager..."
            yum install -y elfutils-libelf zlib gtk3
            ;;
        arch|manjaro|endeavouros|garuda)
            echo "Using pacman package manager..."
            pacman -Sy --noconfirm libelf zlib gtk3
            ;;
        opensuse*|sles)
            echo "Using zypper package manager..."
            zypper install -y libelf1 libz1 gtk3
            ;;
        void)
            echo "Using xbps package manager..."
            xbps-install -Sy libelf zlib gtk3
            ;;
        *)
            echo "WARNING: Unknown distribution '$DISTRO' (family: '$DISTRO_LIKE')"
            echo ""
            echo "Please manually install the following packages:"
            echo "  Debian/Ubuntu: sudo apt install libelf1 zlib1g libgtk-3-0"
            echo "  Fedora:        sudo dnf install elfutils-libelf zlib gtk3"
            echo "  Arch:          sudo pacman -S libelf zlib gtk3"
            echo ""
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    echo "Dependencies installed"
}

# Use /usr/local/lib (matches RPATH in binary)
detect_lib_path() {
    LIB_PATH="/usr/local/lib"
    echo "Library installation path: $LIB_PATH"
}

# Check if files exist in current directory
check_files() {
    echo ""
    echo "Checking for required files..."
    
    if [ ! -f "$SCRIPT_DIR/libproxybridge.so" ]; then
        echo "ERROR: libproxybridge.so not found in $SCRIPT_DIR"
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/ProxyBridge" ]; then
        echo "ERROR: ProxyBridge binary not found in $SCRIPT_DIR"
        exit 1
    fi
    
    if [ ! -f "$SCRIPT_DIR/ProxyBridgeGUI" ]; then
         echo "WARNING: ProxyBridgeGUI binary not found in $SCRIPT_DIR - GUI will not be installed"
    fi
    
    echo "All files present"
}

# Install files
install_files() {
    echo ""
    echo "Installing ProxyBridge..."
    
    # Create directories if they don't exist
    mkdir -p "$LIB_PATH" /usr/local/bin /etc/proxybridge
    chmod 755 /etc/proxybridge
    
    # Copy library
    echo "Installing libproxybridge.so to $LIB_PATH..."
    cp "$SCRIPT_DIR/libproxybridge.so" "$LIB_PATH/"
    chmod 755 "$LIB_PATH/libproxybridge.so"
    
    # Copy binary
    echo "Installing ProxyBridge to /usr/local/bin..."
    cp "$SCRIPT_DIR/ProxyBridge" /usr/local/bin/
    chmod 755 /usr/local/bin/ProxyBridge

    if [ -f "$SCRIPT_DIR/ProxyBridgeGUI" ]; then
        echo "Installing ProxyBridgeGUI to /usr/local/bin..."
        cp "$SCRIPT_DIR/ProxyBridgeGUI" /usr/local/bin/
        chmod 755 /usr/local/bin/ProxyBridgeGUI 
    fi
    
    echo "Files installed"
}

# Update library cache
update_ldconfig() {
    echo ""
    echo "Updating library cache..."
    
    # Add /usr/local/lib to ld.so.conf if not already there
    if [ -d /etc/ld.so.conf.d ]; then
        if ! grep -q "^/usr/local/lib" /etc/ld.so.conf.d/* 2>/dev/null; then
            echo "/usr/local/lib" > /etc/ld.so.conf.d/proxybridge.conf
            if [ "$LIB_PATH" = "/usr/local/lib64" ]; then
                echo "/usr/local/lib64" >> /etc/ld.so.conf.d/proxybridge.conf
            fi
        fi
    fi
    
    # Run ldconfig
    if command -v ldconfig &> /dev/null; then
        ldconfig 2>/dev/null || true
        # Also ensure cache is regenerated
        ldconfig -v 2>/dev/null | grep -q proxybridge || true
        echo "Library cache updated"
    else
        echo "WARNING: ldconfig not found. You may need to reboot."
    fi
}

# Verify installation
verify_installation() {
    echo ""
    echo "Verifying installation..."
    
    # Check if binary is in PATH
    if command -v ProxyBridge &> /dev/null; then
        echo "ProxyBridge binary found in PATH"
    else
        echo "ProxyBridge binary not found in PATH"
        echo "  You may need to add /usr/local/bin to your PATH"
    fi
    
    # Check if library is loadable
    if ldd /usr/local/bin/ProxyBridge 2>/dev/null | grep -q "libproxybridge.so"; then
        if ldd /usr/local/bin/ProxyBridge 2>/dev/null | grep "libproxybridge.so" | grep -q "not found"; then
            echo "libproxybridge.so not loadable"
        else
            echo "libproxybridge.so is loadable"
        fi
    fi
    
    # Final test - try to run --help
    if /usr/local/bin/ProxyBridge --help &>/dev/null; then
        echo "ProxyBridge executable is working"
    else
        echo "ProxyBridge may have issues - try: sudo ldconfig"
    fi
}

# Main deployment
main() {
    detect_distro
    check_files
    install_dependencies
    detect_lib_path
    install_files
    update_ldconfig
    verify_installation
    
    echo ""
    echo "==================================="
    echo "Installation Complete!"
    echo "==================================="
    echo ""
    echo "You can now run ProxyBridge from anywhere:"
    echo "  sudo ProxyBridge --help"
    if [ -f /usr/local/bin/ProxyBridgeGUI ]; then
       echo "  sudo ProxyBridgeGUI      (Graphical Interface)"
    fi
    echo "  sudo ProxyBridge --proxy socks5://IP:PORT --rule \"app:*:*:TCP:PROXY\""
    echo ""
    echo "No cleanup is needed after a crash: the kernel detaches the eBPF programs automatically."
    echo ""
}

main
