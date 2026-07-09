#!/bin/bash
# Linux Setup Script for ARISE
# "Summon Every Hidden Exposure."
# This script installs all required dependencies on a Debian/Ubuntu Linux system

set -e

echo "========================================"
echo "  ARISE Setup for Linux (Debian/Ubuntu)"
echo "  Summon Every Hidden Exposure."
echo "========================================"

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

# Update package lists
update_package_lists() {
    log_info "Updating APT package lists..."
    if command_exists apt-get; then
        sudo apt-get update -y
    else
        log_error "This script requires an APT-based Linux distribution (Debian/Ubuntu)."
        exit 1
    fi
}

# Install core utilities and build tools
install_core_utils() {
    log_info "Installing core build tools and utilities..."
    
    local packages="build-essential wget curl git jq python3 python3-pip python3-venv golang"
    
    for pkg in $packages; do
        log_info "Installing $pkg..."
        sudo apt-get install -y "$pkg"
    done
}

# Install security tools
install_security_tools() {
    log_info "Installing security tools..."

    # Nmap
    if ! command_exists nmap; then
        log_info "Installing nmap..."
        sudo apt-get install -y nmap
    fi

    # massdns is required by puredns.
    if ! command_exists massdns; then
        log_info "Installing massdns from source..."
        local tmp_dir
        tmp_dir=$(mktemp -d)
        git clone --quiet https://github.com/blechschmidt/massdns.git "$tmp_dir"
        if make -C "$tmp_dir" >/dev/null 2>&1; then
            sudo cp "$tmp_dir/bin/massdns" /usr/local/bin/
            log_info "massdns installed successfully"
        else
            log_warn "massdns compilation failed. Please ensure build-essential is configured correctly."
        fi
        rm -rf "$tmp_dir"
    else
        log_info "massdns already installed"
    fi

    # libpcap-dev is required to build naabu.
    log_info "Installing libpcap-dev..."
    sudo apt-get install -y libpcap-dev

    # Pip helper to support PEP 668 externally managed environments
    pip_install() {
        if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
            pip3 install --break-system-packages "$@"
        else
            pip3 install "$@"
        fi
    }

    # wafw00f
    if ! command_exists wafw00f; then
        log_info "Installing wafw00f..."
        pip_install wafw00f
    fi

    # tldextract
    if ! command_exists tldextract; then
        log_info "Installing tldextract..."
        pip_install tldextract
    fi

    log_info "Security tools installed"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Helper to support PEP 668 externally managed environments
    pip_install() {
        if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
            pip3 install --break-system-packages "$@"
        else
            pip3 install "$@"
        fi
    }

    # Upgrade pip
    pip_install --upgrade pip || log_warn "pip upgrade failed, proceeding..."
    
    # Install Python packages
    pip_install requests urllib3 python-dateutil pytz beautifulsoup4 lxml
    pip_install colorama tqdm rich PyYAML python-dotenv validators
    pip_install scapy dirsearch

    # Cloud recon + audit tooling (Module 17).
    # s3scanner: anonymous S3/GCS/Azure access checks (Phase 2).
    # prowler / scoutsuite: authenticated compliance audit (Phase 3, opt-in).
    pip_install s3scanner || log_warn "s3scanner install failed (cloud bucket enum degraded)"
    pip_install prowler || log_warn "prowler install failed (cloud compliance audit unavailable)"
    pip_install scoutsuite || log_warn "scoutsuite install failed (multi-cloud audit unavailable)"

    log_info "Python dependencies installed"
}

# Install cloud_enum (Phase 2 bucket enumeration — Python, not on PyPI).
install_cloud_enum() {
    log_info "Installing cloud_enum (AWS/GCP/Azure storage enumeration)..."
    local ce_dir="$HOME/recon/cloud_enum"
    if [ ! -d "$ce_dir" ]; then
        git clone --quiet https://github.com/initstring/cloud_enum.git "$ce_dir" 2>/dev/null \
            || { log_warn "cloud_enum clone failed; Phase 2 bucket enum will be skipped"; return; }
    fi
    # Its own deps.
    if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
        pip3 install --break-system-packages -r "$ce_dir/requirements.txt" 2>/dev/null || true
    else
        pip3 install -r "$ce_dir/requirements.txt" 2>/dev/null || true
    fi
    # Expose a `cloud_enum` command on PATH pointing at the script.
    local bindir="$HOME/go/bin"; mkdir -p "$bindir"
    cat > "$bindir/cloud_enum" << EOF
#!/usr/bin/env bash
exec python3 "$ce_dir/cloud_enum.py" "\$@"
EOF
    chmod +x "$bindir/cloud_enum"
    log_info "cloud_enum installed ($bindir/cloud_enum)"
}

# Install Go tools
install_go_tools() {
    log_info "Installing Go tools..."
    
    GOPATH="${GOPATH:-$HOME/go}"
    mkdir -p "$GOPATH/bin"
    
    # Install Go tools
    # Subdomain enumeration
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || log_warn "subfinder install failed"
    go install -v github.com/d3mondev/puredns/v2@latest 2>/dev/null || log_warn "puredns install failed"
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || log_warn "dnsx install failed"
    go install -v github.com/hakluke/haktrails@latest 2>/dev/null || log_warn "haktrails install failed"
    go install -v github.com/tomnomnom/anew@latest 2>/dev/null || log_warn "anew install failed"

    # naabu requires libpcap-dev to build with CGO.
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
    
    log_info "Go tools installation attempted"
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

    # Add Go bin to PATH if not already present
    local go_path_str='export PATH="$PATH:$HOME/go/bin"'
    if [ -f ~/.bashrc ]; then
        if ! grep -q 'go/bin' ~/.bashrc; then
            echo "" >> ~/.bashrc
            echo "$go_path_str" >> ~/.bashrc
            log_info "Added Go bin path to ~/.bashrc"
        fi
    fi
    if [ -f ~/.zshrc ]; then
        if ! grep -q 'go/bin' ~/.zshrc; then
            echo "" >> ~/.zshrc
            echo "$go_path_str" >> ~/.zshrc
            log_info "Added Go bin path to ~/.zshrc"
        fi
    fi

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
    log_info "ARISE Linux Setup Complete!"
    log_info "Summon Every Hidden Exposure."
    log_info "========================================"
    log_info "Next steps:"
    log_info "1. Open a new shell or run 'source ~/.bashrc' to load Go environment variables"
    log_info "2. Run: python3 arise.py --hosts hosts.txt   (or: bash easm-pipeline.sh <target_domain>)"
    log_info ""
    log_info "To enable haktrails, add your API keys:"
    log_info "   nano ~/.config/haktools/haktrails-config.yml"
    log_info "========================================"
}

# Main execution
main() {
    echo ""
    log_info "Starting Linux setup for ARISE..."
    echo ""
    
    update_package_lists
    install_core_utils
    install_security_tools
    install_python_deps
    install_go_tools
    install_cloud_enum
    setup_directories
    setup_haktrails_config
    finalize_setup
}

main "$@"
