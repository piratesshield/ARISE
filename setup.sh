#!/bin/bash
# Mac mini Setup Script for ARISE
# "Summon Every Hidden Exposure."
# This script installs all required dependencies on a fresh Mac mini

set -e

echo "========================================"
echo "  ARISE Setup for Mac mini"
echo "  Summon Every Hidden Exposure."
echo "========================================"

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "ERROR: This script is designed for macOS only"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Install Homebrew if not installed
install_homebrew() {
    log_info "Checking Homebrew..."
    if ! command_exists brew; then
        log_info "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
        eval "$(/opt/homebrew/bin/brew shellenv)"
        log_info "Homebrew installed successfully"
    else
        log_info "Homebrew already installed"
    fi
}

# Install core utilities
install_core_utils() {
    log_info "Installing core utilities..."
    
    local tools="wget curl git jq python3 golang"
    
    for tool in $tools; do
        if ! command_exists "$tool"; then
            log_info "Installing $tool..."
            brew install "$tool"
        else
            log_info "$tool already installed"
        fi
    done
}

# Install security tools
install_security_tools() {
    log_info "Installing security tools..."

    # Nmap
    if ! command_exists nmap; then
        log_info "Installing nmap..."
        brew install nmap
    fi

    # massdns is required by puredns.
    if ! command_exists massdns; then
        log_info "Installing massdns..."
        brew install massdns
    fi

    # libpcap is required to build naabu.
    if ! brew list libpcap &>/dev/null; then
        log_info "Installing libpcap..."
        brew install libpcap
    fi

    # wafw00f
    if ! command_exists wafw00f; then
        log_info "Installing wafw00f..."
        pip3 install wafw00f
    fi

    # tldextract
    if ! command_exists tldextract; then
        log_info "Installing tldextract..."
        pip3 install tldextract
    fi

    log_info "Security tools installed"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Upgrade pip
    pip3 install --upgrade pip
    
    # Install Python packages
    pip3 install requests urllib3 python-dateutil pytz beautifulsoup4 lxml
    pip3 install colorama tqdm rich PyYAML python-dotenv validators
    pip3 install scapy dirsearch
    
    log_info "Python dependencies installed"
}

# Install Go tools
install_go_tools() {
    log_info "Installing Go tools..."
    
    # Set up Go bin directory
    #export GOPATH="$HOME/go"
    #export PATH="$PATH:$GOPATH/bin"
    
    GOPATH="${GOPATH:-$HOME/go}"
    mkdir -p "$GOPATH/bin"
    
    # Install Go tools
    # Subdomain enumeration
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || log_warn "subfinder install failed"
    go install -v github.com/d3mondev/puredns/v2@latest 2>/dev/null || log_warn "puredns install failed"
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || log_warn "dnsx install failed"
    #go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest 2>/dev/null || log_warn "shuffledns install failed"
    #go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest 2>/dev/null || log_warn "alterx install failed"
    go install -v github.com/hakluke/haktrails@latest 2>/dev/null || log_warn "haktrails install failed"
    go install -v github.com/tomnomnom/anew@latest 2>/dev/null || log_warn "anew install failed"

    # naabu requires libpcap (installed in install_security_tools) to build with CGO.
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || log_warn "naabu install failed"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || log_warn "httpx install failed"
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null || log_warn "nuclei install failed"
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || log_warn "gau install failed"
    go install -v github.com/jaeles-project/gospider@latest 2>/dev/null || log_warn "gospider install failed"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || log_warn "katana install failed"
    go install -v github.com/tomnomnom/qsreplace@latest 2>/dev/null || log_warn "qsreplace install failed"
    go install -v github.com/ffuf/ffuf@latest 2>/dev/null || log_warn "ffuf install failed"
    go install -v github.com/tomnomnom/gf@latest 2>/dev/null || log_warn "gf install failed"
    go install -v github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog@latest 2>/dev/null || log_warn "trufflehog install failed"
    go install -v github.com/dwisiswant0/bhedak@latest 2>/dev/null || log_warn "bhedak install failed"
    go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null || log_warn "dalfox install failed"
    #go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest 2>/dev/null || log_warn "cvemap install failed"
    
    log_info "Go tools installation attempted (some may have failed - check errors above)"
}

# Setup directories and wordlists
setup_directories() {
    log_info "Setting up directories..."
    
    mkdir -p ~/recon/lists
    mkdir -p ~/recon/nuclei-templates
    
    # Download wordlists
    cd ~/recon/lists
    
    log_info "Downloading wordlists..."
    
    # DNS wordlists
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -o subdomains-top1million-110000.txt 2>/dev/null || log_warn "subdomains-top1million-110000.txt download failed"
    curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt 2>/dev/null || log_warn "resolvers.txt download failed"
    
    # Web content
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o common.txt 2>/dev/null || log_warn "common.txt download failed"
    
    # Nuclei templates
    log_info "Cloning nuclei-templates..."
    git clone --quiet https://github.com/projectdiscovery/nuclei-templates.git ~/recon/nuclei-templates 2>/dev/null || log_warn "nuclei-templates clone failed"

    # gf patterns (required for gf xss used in param/vuln fuzzing)
    log_info "Setting up gf patterns..."
    mkdir -p ~/.gf
    if [ ! "$(ls -A ~/.gf 2>/dev/null)" ]; then
        local gf_tmp
        gf_tmp="$(mktemp -d)"
        if git clone --quiet https://github.com/1ndianl33t/Gf-Patterns "$gf_tmp" 2>/dev/null; then
            cp "$gf_tmp"/*.json ~/.gf/ 2>/dev/null
            rm -rf "$gf_tmp"
        else
            log_warn "Gf-Patterns clone failed"
        fi
    fi

    # Add Go bin to PATH
    #echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
    #echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc

    log_info "Directories and wordlists set up"
}

# Setup haktrails config
setup_haktrails_config() {
    log_info "Setting up haktrails config..."
    
    mkdir -p ~/.config/haktools
    
    cat > ~/.config/haktools/haktrails-config.yml << 'CONFIG_EOF'
# haktrails config file
# Get your API keys from: https://hakluke.com/haktools

# API Keys
shodan-api: ""
censys-app-id: ""
censys-secret: ""
securitytrails-api: ""
virustotal-api: ""
github-token: ""

# Settings
# threads: 10
# timeout: 10
# max-retries: 3
CONFIG_EOF
    
    log_info "Config created at ~/.config/haktools/haktrails-config.yml"
    log_warn "Edit the config file and add your API keys from https://hakluke.com/haktools"
}

# Final setup
finalize_setup() {
    log_info "Finalizing setup..."
    
    # Create project directories
    mkdir -p ~/easm-pipeline/logs
    mkdir -p ~/easm-pipeline/outputs
    mkdir -p ~/easm-pipeline/scans
    mkdir -p ~/easm-pipeline/scope
    
    # Copy requirements to home
    cp requirements.txt ~/easm-pipeline/ 2>/dev/null || true
    
    log_info "========================================"
    log_info "ARISE Setup Complete!"
    log_info "Summon Every Hidden Exposure."
    log_info "========================================"
    log_info "Next steps:"
    log_info "1. Open a new terminal to load PATH changes"
    log_info "2. Run: python3 arise.py --hosts hosts.txt   (or: bash easm-pipeline.sh <target_domain>)"
    log_info ""
    log_info "To enable haktrails, add your API keys:"
    log_info "   nano ~/.config/haktools/haktrails-config.yml"
    log_info "   OR"
    log_info "   open ~/.config/haktools/haktrails-config.yml"
    log_info "========================================"
}

# Main execution
main() {
    echo ""
    log_info "Starting Mac mini setup for ARISE..."
    echo ""
    
    install_homebrew
    install_core_utils
    install_security_tools
    install_python_deps
    install_go_tools
    setup_directories
    setup_haktrails_config
    finalize_setup
}

main "$@"
