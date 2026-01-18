#!/bin/bash
#------------------------------------------------------------------------------
# AfterDark Threat Intelligence Plugin Installer for Amavisd-new
#
# This script installs the AfterDark threat intelligence plugin that
# integrates amavisd-new with dnsscience.io and betterphish.io
#
# Usage: sudo ./install.sh [--uninstall]
#------------------------------------------------------------------------------

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation paths
AMAVIS_LIB_DIR="/usr/local/lib/amavisd"
AMAVIS_CONF_DIR="/etc/amavisd"
AMAVIS_CONFD_DIR="/etc/amavisd/conf.d"
CACHE_DIR="/var/lib/amavis"
AMAVIS_USER="amavis"
AMAVIS_GROUP="amavis"

# Plugin files
PLUGIN_MODULE="AfterDark/Amavis/ThreatIntel.pm"
PLUGIN_CONF="conf.d/99-afterdark-threatintel.conf"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#------------------------------------------------------------------------------
# Helper functions
#------------------------------------------------------------------------------

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_amavisd() {
    if ! command -v amavisd &> /dev/null && ! command -v amavisd-new &> /dev/null; then
        log_error "amavisd-new not found. Please install it first."
        exit 1
    fi
    log_info "amavisd-new found"
}

check_perl_modules() {
    log_info "Checking required Perl modules..."

    local modules=("Net::DNS" "HTTP::Tiny" "JSON::PP" "Digest::SHA" "Storable")
    local missing=()

    for mod in "${modules[@]}"; do
        if ! perl -e "use $mod" 2>/dev/null; then
            missing+=("$mod")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing Perl modules: ${missing[*]}"
        log_info "Attempting to install missing modules..."

        # Try to install via CPAN or package manager
        if command -v cpanm &> /dev/null; then
            for mod in "${missing[@]}"; do
                cpanm "$mod" || true
            done
        elif command -v apt-get &> /dev/null; then
            apt-get update
            for mod in "${missing[@]}"; do
                pkg="lib$(echo "$mod" | tr '::' '-' | tr '[:upper:]' '[:lower:]')-perl"
                apt-get install -y "$pkg" 2>/dev/null || true
            done
        elif command -v yum &> /dev/null; then
            for mod in "${missing[@]}"; do
                pkg="perl-$(echo "$mod" | tr '::' '-')"
                yum install -y "$pkg" 2>/dev/null || true
            done
        fi
    fi

    log_info "Perl module check complete"
}

#------------------------------------------------------------------------------
# Installation
#------------------------------------------------------------------------------

install_plugin() {
    log_info "Installing AfterDark Threat Intelligence Plugin..."

    # Create directories
    log_info "Creating directories..."
    mkdir -p "${AMAVIS_LIB_DIR}/AfterDark/Amavis"
    mkdir -p "${AMAVIS_CONFD_DIR}"
    mkdir -p "${CACHE_DIR}"

    # Install the plugin module
    log_info "Installing plugin module..."
    if [[ -f "${SCRIPT_DIR}/${PLUGIN_MODULE}" ]]; then
        cp "${SCRIPT_DIR}/${PLUGIN_MODULE}" "${AMAVIS_LIB_DIR}/AfterDark/Amavis/"
        chmod 644 "${AMAVIS_LIB_DIR}/AfterDark/Amavis/ThreatIntel.pm"
        log_info "Plugin module installed to ${AMAVIS_LIB_DIR}/AfterDark/Amavis/ThreatIntel.pm"
    else
        log_error "Plugin module not found: ${SCRIPT_DIR}/${PLUGIN_MODULE}"
        exit 1
    fi

    # Install configuration file
    log_info "Installing configuration file..."
    if [[ -f "${SCRIPT_DIR}/${PLUGIN_CONF}" ]]; then
        if [[ -f "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf" ]]; then
            log_warn "Configuration file already exists, creating backup..."
            cp "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf" \
               "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf.bak.$(date +%Y%m%d%H%M%S)"
        fi
        cp "${SCRIPT_DIR}/${PLUGIN_CONF}" "${AMAVIS_CONFD_DIR}/"
        chmod 640 "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf"
        log_info "Configuration installed to ${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf"
    else
        log_error "Configuration file not found: ${SCRIPT_DIR}/${PLUGIN_CONF}"
        exit 1
    fi

    # Set cache directory permissions
    log_info "Setting permissions..."
    if id "$AMAVIS_USER" &>/dev/null; then
        chown -R "${AMAVIS_USER}:${AMAVIS_GROUP}" "${CACHE_DIR}"
        chmod 750 "${CACHE_DIR}"
    else
        log_warn "Amavis user not found, skipping permission setup"
    fi

    # Verify installation
    log_info "Verifying installation..."
    if perl -I"${AMAVIS_LIB_DIR}" -e 'use AfterDark::Amavis::ThreatIntel' 2>/dev/null; then
        log_info "Plugin module loads successfully"
    else
        log_error "Plugin module failed to load. Check Perl dependencies."
        perl -I"${AMAVIS_LIB_DIR}" -e 'use AfterDark::Amavis::ThreatIntel' 2>&1 || true
        exit 1
    fi

    # Check if amavisd.conf includes conf.d
    local AMAVIS_CONF="${AMAVIS_CONF_DIR}/amavisd.conf"
    if [[ -f "$AMAVIS_CONF" ]]; then
        if ! grep -q "99-afterdark-threatintel.conf" "$AMAVIS_CONF"; then
            echo ""
            log_warn "==================================================="
            log_warn "IMPORTANT: Add the following line to your amavisd.conf:"
            log_warn ""
            log_warn "  include('${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf');"
            log_warn ""
            log_warn "Add it near the end of the file, after other configurations."
            log_warn "==================================================="
        fi
    fi

    echo ""
    log_info "==================================================="
    log_info "Installation complete!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Edit ${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf"
    log_info "2. Add your API keys (see comments in the config file)"
    log_info "3. Add the include() line to amavisd.conf (if not done)"
    log_info "4. Restart amavisd: systemctl restart amavisd"
    log_info "5. Check logs: grep -i afterdark /var/log/maillog"
    log_info "==================================================="
}

#------------------------------------------------------------------------------
# Uninstallation
#------------------------------------------------------------------------------

uninstall_plugin() {
    log_info "Uninstalling AfterDark Threat Intelligence Plugin..."

    # Remove plugin module
    if [[ -d "${AMAVIS_LIB_DIR}/AfterDark" ]]; then
        log_info "Removing plugin module..."
        rm -rf "${AMAVIS_LIB_DIR}/AfterDark"
    fi

    # Remove configuration (but keep backup)
    if [[ -f "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf" ]]; then
        log_info "Backing up and removing configuration..."
        mv "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf" \
           "${AMAVIS_CONFD_DIR}/99-afterdark-threatintel.conf.uninstalled.$(date +%Y%m%d%H%M%S)"
    fi

    # Remove cache file
    if [[ -f "${CACHE_DIR}/afterdark_cache.db" ]]; then
        log_info "Removing cache file..."
        rm -f "${CACHE_DIR}/afterdark_cache.db"
    fi

    echo ""
    log_info "==================================================="
    log_info "Uninstallation complete!"
    log_info ""
    log_info "Don't forget to:"
    log_info "1. Remove the include() line from amavisd.conf"
    log_info "2. Restart amavisd: systemctl restart amavisd"
    log_info "==================================================="
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    echo ""
    echo "=============================================="
    echo " AfterDark Threat Intelligence Plugin"
    echo " for Amavisd-new"
    echo "=============================================="
    echo ""

    check_root

    if [[ "${1:-}" == "--uninstall" ]] || [[ "${1:-}" == "-u" ]]; then
        uninstall_plugin
    else
        check_amavisd
        check_perl_modules
        install_plugin
    fi
}

main "$@"
