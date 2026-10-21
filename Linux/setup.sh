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

# The command line program and the library are self-contained (libbpf, libelf and zlib are linked in; only glibc is used), so
# nothing needs installing for them. The GUI needs GTK3, which cannot be linked statically: install it only if it is missing.
install_dependencies() {
    echo ""
    if [ ! -f "$SCRIPT_DIR/ProxyBridgeGUI" ]; then
        echo "No dependencies to install (the command line program is self-contained)."
        return
    fi
    if ldconfig -p 2>/dev/null | grep -q 'libgtk-3\.so\.0'; then
        echo "GTK3 is already installed (needed by the GUI)."
        return
    fi
    echo "Installing GTK3 (needed by the GUI)..."

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
            apt-get update -qq
            apt-get install -y libgtk-3-0
            ;;
        fedora)         dnf install -y gtk3 ;;
        rhel|centos|rocky|almalinux) yum install -y gtk3 ;;
        arch|manjaro|endeavouros|garuda) pacman -Sy --noconfirm gtk3 ;;
        opensuse*|sles) zypper install -y gtk3 ;;
        void)           xbps-install -Sy gtk3 ;;
        *)
            echo "WARNING: Unknown distribution '$DISTRO'. The GUI needs GTK3 (Debian/Ubuntu: libgtk-3-0, Fedora: gtk3, Arch: gtk3)."
            echo "The command line program works without it."
            ;;
    esac
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
    chmod 700 /etc/proxybridge                    # holds profiles with proxy passwords

    # install(1) replaces the file and sets owner and mode, so a file left by someone else is never kept
    echo "Installing libproxybridge.so to $LIB_PATH..."
    install -o root -g root -m 0755 "$SCRIPT_DIR/libproxybridge.so" "$LIB_PATH/libproxybridge.so"

    echo "Installing ProxyBridge to /usr/local/bin..."
    install -o root -g root -m 0755 "$SCRIPT_DIR/ProxyBridge" /usr/local/bin/ProxyBridge

    if [ -f "$SCRIPT_DIR/ProxyBridgeGUI" ]; then
        echo "Installing ProxyBridgeGUI to /usr/local/bin..."
        install -o root -g root -m 0755 "$SCRIPT_DIR/ProxyBridgeGUI" /usr/local/bin/ProxyBridgeGUI
    fi

    if [ -f "$SCRIPT_DIR/ProxyBridgeGUI" ] && [ -f "$SCRIPT_DIR/proxybridge.desktop" ]; then
        echo "Installing the launcher entry and icon..."
        install -d -m 0755 /usr/share/applications /usr/share/icons/hicolor/128x128/apps /usr/share/icons/hicolor/256x256/apps
        install -o root -g root -m 0644 "$SCRIPT_DIR/proxybridge.desktop" /usr/share/applications/proxybridge.desktop
        install -o root -g root -m 0644 "$SCRIPT_DIR/proxybridge-128.png" /usr/share/icons/hicolor/128x128/apps/proxybridge.png
        install -o root -g root -m 0644 "$SCRIPT_DIR/proxybridge-256.png" /usr/share/icons/hicolor/256x256/apps/proxybridge.png
        command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
        command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications 2>/dev/null || true
    fi
    
    echo "Files installed"
}

# The ProxyBridge service: the part that runs as root (it owns the engine and the profiles), so the window itself needs no root.
# Who may use it: root and the members of the group "proxybridge", looked up at every connection (no new login needed).
install_service() {
    echo ""
    echo "Setting up the ProxyBridge service..."

    if ! getent group proxybridge >/dev/null 2>&1; then
        groupadd --system proxybridge 2>/dev/null || groupadd -r proxybridge 2>/dev/null || addgroup --system proxybridge 2>/dev/null \
            || echo "WARNING: could not create the group 'proxybridge'; only root will be able to use the window"
    fi
    # Membership of the group is administrative power over ProxyBridge: a member can route, block and read the proxy passwords of every
    # user's traffic. The user who ran sudo is added (that is who just installed it); PB_NO_GROUP_USER=1 skips that.
    SERVICE_USER=""
    if [ -n "${SUDO_USER:-}" ] && [ "${PB_NO_GROUP_USER:-0}" != 1 ] && [ "$SUDO_USER" != root ] && [ "$(id -u -- "$SUDO_USER" 2>/dev/null || echo 0)" != 0 ] \
       && getent group proxybridge >/dev/null 2>&1; then
        if usermod -aG proxybridge -- "$SUDO_USER" 2>/dev/null || gpasswd -a "$SUDO_USER" proxybridge >/dev/null 2>&1 || adduser "$SUDO_USER" proxybridge >/dev/null 2>&1; then
            SERVICE_USER="$SUDO_USER"
            echo "  $SUDO_USER may now use ProxyBridge without root (member of the group 'proxybridge')"
            echo "  NOTE: members of that group can route, block and read the proxy passwords of every user's traffic."
            echo "        Add only people you would give sudo for ProxyBridge (sudo usermod -aG proxybridge <user>); remove with: sudo gpasswd -d <user> proxybridge"
        else
            echo "WARNING: could not add $SUDO_USER to the group 'proxybridge'. Do it with: sudo usermod -aG proxybridge $SUDO_USER"
        fi
    fi

    SERVICE_STARTED=0
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        if /usr/local/bin/ProxyBridge --print-unit /usr/local/bin/ProxyBridge > /etc/systemd/system/proxybridge.service.new; then
            install -o root -g root -m 0644 /etc/systemd/system/proxybridge.service.new /etc/systemd/system/proxybridge.service
            rm -f /etc/systemd/system/proxybridge.service.new
            systemctl daemon-reload
            systemctl enable proxybridge.service >/dev/null 2>&1 || true
            if systemctl restart proxybridge.service; then
                SERVICE_STARTED=1
                echo "  proxybridge.service is installed, enabled and running"
            else
                echo "WARNING: proxybridge.service did not start. See: journalctl -u proxybridge"
            fi
        else
            rm -f /etc/systemd/system/proxybridge.service.new
            echo "WARNING: could not create the service file"
        fi
    else
        echo "  systemd is not running here, so no service was installed."
        echo "  Start it yourself with: sudo ProxyBridge --daemon     (or run the window with sudo: it then uses its own engine)"
    fi
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

# Removes everything setup.sh and the GUI installed, including the boot service. Profiles are kept unless --purge is given.
uninstall() {
    echo "Removing ProxyBridge..."
    if [ -f /etc/systemd/system/proxybridge.service ]; then
        systemctl disable --now proxybridge.service 2>/dev/null || true
        rm -f /etc/systemd/system/proxybridge.service
        systemctl daemon-reload 2>/dev/null || true
        echo "  service removed"
    fi
    rm -f /usr/local/bin/ProxyBridge /usr/local/bin/ProxyBridgeGUI
    rm -f /usr/share/applications/proxybridge.desktop /usr/share/icons/hicolor/128x128/apps/proxybridge.png /usr/share/icons/hicolor/256x256/apps/proxybridge.png
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
    rm -f /usr/local/lib/libproxybridge.so /usr/local/lib64/libproxybridge.so /usr/lib/libproxybridge.so /usr/lib64/libproxybridge.so
    rm -f /etc/ld.so.conf.d/proxybridge.conf
    ldconfig 2>/dev/null || true
    if [ "$1" = "--purge" ]; then
        getent group proxybridge >/dev/null 2>&1 && { groupdel proxybridge 2>/dev/null || delgroup proxybridge 2>/dev/null || true; }
        rm -rf /etc/proxybridge
        echo "  profiles and settings removed"
    else
        echo "  profiles kept in /etc/proxybridge (use --uninstall --purge to remove them)"
        echo "  the group 'proxybridge' and its members were kept too (--purge removes the group)"
    fi
    echo "Done."
}

if [ "$1" = "--uninstall" ]; then
    [ "$(id -u)" = 0 ] || { echo "Please run as root: sudo $0 --uninstall"; exit 1; }
    uninstall "$2"
    exit 0
fi

# Main deployment
main() {
    detect_distro
    check_files
    install_dependencies
    detect_lib_path
    install_files
    update_ldconfig
    verify_installation
    install_service
    
    echo ""
    echo "==================================="
    echo "Installation Complete!"
    echo "==================================="
    echo ""
    if [ -f /usr/local/bin/ProxyBridgeGUI ]; then
        if [ "${SERVICE_STARTED:-0}" = 1 ]; then
            echo "Open the window (no sudo needed) from a terminal with:   ProxyBridgeGUI"
            if [ -n "${SERVICE_USER:-}" ]; then
                echo "  ($SERVICE_USER can use it right away; other users need: sudo usermod -aG proxybridge <user>)"
            else
                echo "  (add each user who may use it to the group: sudo usermod -aG proxybridge <user>)"
            fi
        else
            echo "Open the window with:   sudo ProxyBridgeGUI"
        fi
    fi
    echo "Command line:                 sudo ProxyBridge --profile <name or .pbprofile path>"
    echo "Help:                         ProxyBridge --help"
    echo ""
    echo "No cleanup is needed after a crash: the kernel detaches the eBPF programs automatically."
    echo ""
}

main
