#!/bin/bash
#===============================================================================
# autorecon Dependency Installer
#===============================================================================
# This script installs all required tools for the reconnaissance orchestration.
# Designed for Kali Linux/Debian-based systems. Adapts for other distros.
#===============================================================================

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

#-------------------------------------------------------------------------------
# System Package Installation
#-------------------------------------------------------------------------------

install_system_packages() {
    log_info "Updating package lists..."
    
    if command -v apt &> /dev/null; then
        sudo apt update -qq
        sudo apt install -y -qq \
            git \
            curl \
            wget \
            jq \
            dnsutils \
            netcat-traditional \
            nmap \
            masscan \
            gobuster \
            dirb \
            nikto \
            sslscan \
            openssl \
            python3 \
            python3-pip \
            golang-go \
            build-essential \
            2>/dev/null || true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y \
            git \
            curl \
            wget \
            jq \
            bind-utils \
            nmap \
            python3 \
            python3-pip \
            golang \
            gcc \
            2>/dev/null || true
    elif command -v pacman &> /dev/null; then
        sudo pacman -Sy --noconfirm \
            git \
            curl \
            wget \
            jq \
            dnsutils \
            nmap \
            python \
            python-pip \
            go \
            base-devel \
            2>/dev/null || true
    else
        log_warn "Unknown package manager. Please install dependencies manually."
        return 1
    fi
    
    log_info "System packages installed successfully"
}

#-------------------------------------------------------------------------------
# Go Tool Installation
#-------------------------------------------------------------------------------

install_go_tools() {
    log_info "Installing Go-based security tools..."
    
    # Ensure Go is available
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go first."
        return 1
    fi
    
    # Set GOPATH
    export GOPATH=${GOPATH:-$HOME/go}
    export PATH=$PATH:$GOPATH/bin
    
    # ProjectDiscovery tools
    log_info "Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    
    log_info "Installing dnsx..."
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
    
    log_info "Installing naabu..."
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true
    
    log_info "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    
    log_info "Installing tlsx..."
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null || true
    
    log_info "Installing katana..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
    
    log_info "Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
    
    # Other tools
    log_info "Installing assetfinder..."
    go install -v github.com/tomnomnom/assetfinder@latest 2>/dev/null || true
    
    log_info "Installing gospider..."
    go install -v github.com/jaeles-project/gospider@latest 2>/dev/null || true
    
    log_info "Installing gf (grep wrapper)..."
    go install -v github.com/tomnomnom/gf@latest 2>/dev/null || true
    
    # Install gf patterns
    if command -v gf &> /dev/null; then
        log_info "Installing gf patterns..."
        gfcp=$(go env GOPATH 2>/dev/null || echo "$HOME/go")
        if [[ -d "$gfcp/src/github.com/tomnomnom/gf/examples" ]]; then
            mkdir -p ~/.gf
            cp "$gfcp/src/github.com/tomnomnom/gf/examples/"* ~/.gf/ 2>/dev/null || true
        fi
    fi
    
    log_info "Go tools installation completed"
}

#-------------------------------------------------------------------------------
# Python Tools Installation
#-------------------------------------------------------------------------------

install_python_tools() {
    log_info "Installing Python-based tools..."
    
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log_warn "pip not found. Skipping Python tools."
        return 0
    fi
    
    # Install trufflehog (alternative to Go version)
    pip3 install truffleHog 2>/dev/null || true
    
    # Install other useful Python tools
    pip3 install urllib3 requests beautifulsoup4 2>/dev/null || true
    
    log_info "Python tools installation completed"
}

#-------------------------------------------------------------------------------
# Additional Tool Installation
#-------------------------------------------------------------------------------

install_additional_tools() {
    log_info "Installing additional tools..."
    
    # findomain
    log_info "Installing findomain..."
    if [[ "$(uname -s)" == "Linux" ]]; then
        curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
            2>/dev/null || true
        unzip -o findomain-linux.zip 2>/dev/null || true
        chmod +x findomain 2>/dev/null || true
        sudo mv findomain /usr/local/bin/ 2>/dev/null || true
        rm -f findomain-linux.zip 2>/dev/null || true
    fi
    
    # amass (passive mode)
    log_info "Installing amass..."
    go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true
    
    # ctfr (Certificate Transparency)
    log_info "Installing ctfr..."
    git clone --depth 1 https://github.com/UnaPibaGeek/ctfr.git /tmp/ctfr 2>/dev/null || true
    if [[ -d /tmp/ctfr ]]; then
        cd /tmp/ctfr
        pip3 install -r requirements.txt 2>/dev/null || true
        sudo python3 setup.py install 2>/dev/null || true
        cd - > /dev/null
        rm -rf /tmp/ctfr
    fi
    
    # gitleaks
    log_info "Installing gitleaks..."
    go install -v github.com/gitleaks/gitleaks@latest 2>/dev/null || true
    
    log_info "Additional tools installation completed"
}

#-------------------------------------------------------------------------------
# Setup Resolvers File
#-------------------------------------------------------------------------------

setup_resolvers() {
    log_info "Setting up DNS resolvers..."
    
    local resolver_file="./resolvers.txt"
    
    if [[ ! -f "$resolver_file" ]]; then
        cat > "$resolver_file" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
        log_info "Created default resolvers file: $resolver_file"
    else
        log_info "Resolvers file already exists: $resolver_file"
    fi
}

#-------------------------------------------------------------------------------
# Setup Wordlists Directory
#-------------------------------------------------------------------------------

setup_wordlists() {
    log_info "Setting up wordlists directory..."
    
    local wordlist_dir="./wordlists"
    
    mkdir -p "$wordlist_dir"
    
    # Create a basic subdomain wordlist if none exists
    if [[ ! -f "$wordlist_dir/subdomains.txt" ]]; then
        cat > "$wordlist_dir/subdomains.txt" << 'EOF'
www
mail
ftp
smtp
pop
imap
admin
webmail
test
dev
staging
api
app
blog
shop
store
cdn
static
assets
media
files
docs
support
help
status
monitoring
EOF
        log_info "Created basic subdomain wordlist"
    fi
    
    log_info "Wordlists directory ready: $wordlist_dir"
}

#-------------------------------------------------------------------------------
# Verify Installation
#-------------------------------------------------------------------------------

verify_installation() {
    log_info "Verifying installation..."
    
    local missing=()
    local tools=(
        "subfinder"
        "assetfinder"
        "findomain"
        "dnsx"
        "naabu"
        "httpx"
        "tlsx"
        "katana"
        "gospider"
        "nuclei"
        "gf"
        "jq"
        "curl"
    )
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "✓ $tool installed"
        else
            log_warn "✗ $tool NOT found"
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn ""
        log_warn "Some tools are missing: ${missing[*]}"
        log_warn "You can still run autorecon, but some features may be limited."
        log_warn "Try running this script again or install tools manually."
    else
        log_info ""
        log_info "✅ All tools installed successfully!"
        log_info ""
        log_info "Next steps:"
        log_info "  1. Copy config.example.yaml to config.yaml"
        log_info "  2. Edit config.yaml with your settings"
        log_info "  3. Add your targets to targets.txt"
        log_info "  4. Run: ./autorecon.sh --target example.com --allowlist targets.txt --dry-run"
    fi
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

main() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔧 autorecon Dependency Installer                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

EOF
    
    log_info "This script will install all required dependencies for autorecon."
    log_info "This may take several minutes depending on your internet connection."
    echo ""
    
    read -p "Continue with installation? [y/N]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation aborted by user"
        exit 0
    fi
    
    # Run installation steps
    install_system_packages
    install_go_tools
    install_python_tools
    install_additional_tools
    setup_resolvers
    setup_wordlists
    
    # Verify
    verify_installation
    
    log_info ""
    log_info "Installation complete!"
}

main "$@"
