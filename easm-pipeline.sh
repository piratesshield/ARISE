#!/bin/bash

###################################################################################################
#                    ARISE SCAN ENGINE  --  "Summon Every Hidden Exposure."                       #
###################################################################################################

set -o pipefail

# Version
readonly VERSION="2.1.0"
readonly SCRIPT_DATE="2026-07-07"

# Colors
readonly BOLD=$(tput bold 2>/dev/null || echo "")
readonly NORMAL=$(tput sgr0 2>/dev/null || echo "")
readonly RED=$(tput setaf 1 2>/dev/null || echo "")
readonly GREEN=$(tput setaf 2 2>/dev/null || echo "")
readonly YELLOW=$(tput setaf 3 2>/dev/null || echo "")
readonly CYAN=$(tput setaf 6 2>/dev/null || echo "")

# Paths
PROJECT_ROOT=""
SCAN_DIR=""
OUTPUT_DIR=""
LOG_DIR=""
MANIFEST_FILE=""

# Port Scanning Configuration
# Options: "fast" (top 1000 ports), "full" (all 65535 ports), "default" (top 100 ports)
# macOS defaults to "fast" because full-range scans crash naabu under thread limits
if [ "$(uname -s)" = "Darwin" ]; then
    PORT_SCAN_MODE="${PORT_SCAN_MODE:-fast}"
    NAABU_RATE="${NAABU_RATE:-1000}"
    NAABU_THREADS="${NAABU_THREADS:-25}"
else
    PORT_SCAN_MODE="${PORT_SCAN_MODE:-full}"
    NAABU_RATE="${NAABU_RATE:-3000}"
    NAABU_THREADS="${NAABU_THREADS:-100}"
fi

# Statistics
TOTAL_HOSTS=0
RESOLVED_HOSTS=0
HTTP_HOSTS=0
WAF_HOSTS=0

# Tool paths (set to tool names, will use PATH)
SUBFINDER="subfinder"
PUREDNS="puredns"
DNSX="dnsx"
NAABU="naabu"
HTTPX="httpx"
NUCLEI="nuclei"
NMAP="nmap"
GOSPIDER="gospider"
GAU="gau"
FFUF="ffuf"
GF="gf"
TRUFFLEHOG="trufflehog"
DALFOX="dalfox"
DIRSEARCH="dirsearch"
WAFW00F="wafw00f"
KATANA="katana"
HAKTRAILS="haktrails"

# Cloud recon + audit tooling (Module 17).
CLOUDENUM="${CLOUDENUM:-cloud_enum}"          # AWS/GCP/Azure bucket enumeration
S3SCANNER="${S3SCANNER:-s3scanner}"           # anonymous S3/GCS/Azure access check
PROWLER="${PROWLER:-prowler}"                 # authenticated AWS/Azure/GCP audit
SCOUTSUITE="${SCOUTSUITE:-scout}"             # authenticated multi-cloud audit

# Phase 2 (external, unauthenticated) — bucket enumeration is safe recon and
# runs by default. Phase 3 (authenticated compliance audit) needs the target's
# own cloud credentials, so it stays OFF unless the operator explicitly enables
# it and supplies credentials — you never have these in an external scan.
CLOUD_BUCKET_ENUM_ENABLED="${CLOUD_BUCKET_ENUM_ENABLED:-true}"
CLOUD_BUCKET_MUTATIONS="${CLOUD_BUCKET_MUTATIONS:-}"       # optional extra keywords, comma-sep
CLOUD_AUDIT_ENABLED="${CLOUD_AUDIT_ENABLED:-false}"        # Phase 3 master switch
CLOUD_AUDIT_PROVIDER="${CLOUD_AUDIT_PROVIDER:-aws}"        # aws|gcp|azure
CLOUD_AUDIT_TOOL="${CLOUD_AUDIT_TOOL:-prowler}"            # prowler|scoutsuite

# Extended vulnerability verification (Module 19) — dedicated FOSS scanners that
# CONFIRM classes nuclei can't (blind SSRF, CRLF, JWT, SSTI, GraphQL, smuggling).
INTERACTSH_CLIENT="${INTERACTSH_CLIENT:-interactsh-client}"  # OOB callback oracle
CRLFUZZ="${CRLFUZZ:-crlfuzz}"                                # CRLF injection
JWT_TOOL="${JWT_TOOL:-jwt_tool}"                             # JWT weakness analysis
SSTIMAP="${SSTIMAP:-sstimap}"                               # template injection
GRAPHW00F="${GRAPHW00F:-graphw00f}"                          # GraphQL fingerprint
SMUGGLER="${SMUGGLER:-smuggler}"                            # HTTP request smuggling

# PRODUCTION-SAFE contract: these checks CONFIRM, they do not EXPLOIT.
# EXTENDED_SAFE_MODE=true (default, do not disable on prod) enforces: benign
# payloads only, GET/read-only, no shells/exfil/auth-bypass actions, no state
# mutation. Confirmation comes from OOB callbacks (SSRF), response reflection
# (CRLF), or offline analysis (JWT) — never from weaponization.
EXTENDED_CHECKS_ENABLED="${EXTENDED_CHECKS_ENABLED:-true}"
EXTENDED_SAFE_MODE="${EXTENDED_SAFE_MODE:-true}"
EXTENDED_MAX_URLS="${EXTENDED_MAX_URLS:-150}"      # cap active probes per check
EXTENDED_RATE="${EXTENDED_RATE:-40}"               # requests/sec ceiling
EXTENDED_OOB_WAIT="${EXTENDED_OOB_WAIT:-25}"       # seconds to await OOB callbacks
INTERACTSH_SERVER="${INTERACTSH_SERVER:-}"         # optional self-hosted oast server
# Per-check toggles. Smuggling is OFF by default: desync probes can disturb
# other users' requests on shared production frontends.
CHECK_SSRF="${CHECK_SSRF:-true}"
CHECK_CRLF="${CHECK_CRLF:-true}"
CHECK_JWT="${CHECK_JWT:-true}"
CHECK_SSTI="${CHECK_SSTI:-true}"
CHECK_GRAPHQL="${CHECK_GRAPHQL:-true}"
CHECK_SMUGGLING="${CHECK_SMUGGLING:-false}"

# Safety/performance bounds for active testing. Override explicitly when authorized.
PARAM_FUZZ_MAX_URLS="${PARAM_FUZZ_MAX_URLS:-50}"
JS_DOWNLOAD_MAX="${JS_DOWNLOAD_MAX:-500}"
PUREDNS_ENABLED="${PUREDNS_ENABLED:-true}"
PUREDNS_WORDLIST_LIMIT="${PUREDNS_WORDLIST_LIMIT:-5000}"
PUREDNS_RESOLVER_LIMIT="${PUREDNS_RESOLVER_LIMIT:-50}"
PUREDNS_RATE_LIMIT="${PUREDNS_RATE_LIMIT:-100}"
PUREDNS_TRUSTED_RATE_LIMIT="${PUREDNS_TRUSTED_RATE_LIMIT:-25}"
PUREDNS_THREADS="${PUREDNS_THREADS:-10}"
PUREDNS_WILDCARD_BATCH="${PUREDNS_WILDCARD_BATCH:-100}"
PUREDNS_WILDCARD_TESTS="${PUREDNS_WILDCARD_TESTS:-1}"

###################################################################################################
# UTILITY FUNCTIONS
###################################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NORMAL} $1"
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && echo "[INFO] $(date) - $1" >> "$LOG_DIR/pipeline.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NORMAL} $1"
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && echo "[WARN] $(date) - $1" >> "$LOG_DIR/pipeline.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NORMAL} $1" >&2
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && echo "[ERROR] $(date) - $1" >> "$LOG_DIR/pipeline.log"
}

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NORMAL}"
    echo -e "${CYAN}  $1${NORMAL}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NORMAL}"
}

log_debug() {
    [ -n "$DEBUG" ] && echo -e "${CYAN}[DEBUG]${NORMAL} $1"
}

get_iso_timestamp() {
    date '+%Y%m%d_%H%M%S'
}

make_iso_filename() {
    local target="$1"
    local module="$2"
    local type="$3"
    local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    echo "${safe_target}_$(get_iso_timestamp)_${module}_${type}.json"
}

count_lines() {
    [ -s "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0
}

safe_name() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

url_host() {
    local value="${1#*://}"
    value="${value%%/*}"
    printf '%s\n' "${value%%:*}"
}

ensure_positive_int() {
    local var_name="$1"
    local default_value="$2"
    local current_value="${!var_name}"
    if ! printf '%s' "$current_value" | grep -Eq '^[1-9][0-9]*$'; then
        log_warn "$var_name must be a positive integer; using $default_value"
        eval "$var_name=\"$default_value\""
    fi
}

validate_runtime_limits() {
    ensure_positive_int "PUREDNS_WORDLIST_LIMIT" "5000"
    ensure_positive_int "PUREDNS_RESOLVER_LIMIT" "50"
    ensure_positive_int "PUREDNS_RATE_LIMIT" "100"
    ensure_positive_int "PUREDNS_TRUSTED_RATE_LIMIT" "25"
    ensure_positive_int "PUREDNS_THREADS" "10"
    ensure_positive_int "PUREDNS_WILDCARD_BATCH" "100"
    ensure_positive_int "PUREDNS_WILDCARD_TESTS" "1"
}

###################################################################################################
# MANIFEST MANAGEMENT
###################################################################################################

init_manifest() {
    local target="$1"
    local scan_id="$2"
    
    MANIFEST_FILE="$OUTPUT_DIR/manifest.json"
    
    cat > "$MANIFEST_FILE" << EOF
{
  "pipeline_info": {
    "version": "$VERSION",
    "target": "$target",
    "scan_id": "$scan_id",
    "start_time": "$(date -Iseconds)",
    "status": "running"
  },
  "statistics": {
    "total_hosts": 0,
    "resolved_hosts": 0,
    "http_hosts": 0,
    "waf_hosts": 0
  },
  "hosts": {}
}
EOF
    log_info "Manifest initialized: $MANIFEST_FILE"
}

update_manifest() {
    local host="$1"
    local key="$2"
    local value="$3"
    
    [ ! -f "$MANIFEST_FILE" ] && return 1
    
    if ! jq -e ".hosts[\"$host\"]" "$MANIFEST_FILE" &>/dev/null; then
        jq --arg h "$host" '.hosts += {($h): {}}' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
    fi
    
    jq --arg h "$host" --arg k "$key" --argjson v "$value" '.hosts[$h][$k] = $v' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
}

update_manifest_bulk() {
    local host="$1"
    local json_obj="$2"
    
    [ ! -f "$MANIFEST_FILE" ] && return 1
    
    if ! jq -e ".hosts[\"$host\"]" "$MANIFEST_FILE" &>/dev/null; then
        jq --arg h "$host" '.hosts += {($h): {}}' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
    fi
    
    jq --arg h "$host" --argjson obj "$json_obj" '.hosts[$h] += $obj' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
}

get_manifest() {
    local host="$1"
    local key="$2"
    jq -r ".hosts[\"$host\"][\"$key\"] // empty" "$MANIFEST_FILE" 2>/dev/null
}

get_hosts_where() {
    local filter="$1"
    jq -r ".hosts | to_entries[] | select(.value$filter) | .key" "$MANIFEST_FILE" 2>/dev/null
}

update_statistics() {
    local stat="$1"
    local val="$2"
    jq --arg s "$stat" --argjson v "$val" '.statistics[$s] = $v' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
}

###################################################################################################
# SETUP FUNCTIONS
###################################################################################################

create_directories() {
    local target="$1"
    
    PROJECT_ROOT="$(pwd)"
    SCAN_DIR="$PROJECT_ROOT/scans"
    SCOPE_DIR="$PROJECT_ROOT/scope"
    
    # Create scan-specific directory with timestamp (engineering style: target-DDMMYY-HHMM)
    local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local scan_timestamp=$(date +%d%m%y-%H%M)
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="$SCAN_DIR/${safe_target}-${scan_timestamp}"
    else
        OUTPUT_DIR="${OUTPUT_DIR%/}"
    fi
    LOG_DIR="$OUTPUT_DIR/logs"
    
    # Create root directories
    mkdir -p "$SCAN_DIR" "$SCOPE_DIR" "$LOG_DIR"
    
    # Create module subdirectories
    mkdir -p "$OUTPUT_DIR/01_asset_discovery"
    mkdir -p "$OUTPUT_DIR/02_subdomain_enum"
    mkdir -p "$OUTPUT_DIR/03_dns_resolution"
    mkdir -p "$OUTPUT_DIR/04_http_discovery"
    mkdir -p "$OUTPUT_DIR/05_waf_detection"
    mkdir -p "$OUTPUT_DIR/06_header_analysis"
    mkdir -p "$OUTPUT_DIR/07_service_fingerprint"
    mkdir -p "$OUTPUT_DIR/08_directory_discovery"
    mkdir -p "$OUTPUT_DIR/09_crawling"
    mkdir -p "$OUTPUT_DIR/10_secret_scanning"
    mkdir -p "$OUTPUT_DIR/11_param_fuzzing"
    mkdir -p "$OUTPUT_DIR/12_nuclei_scanning"
    mkdir -p "$OUTPUT_DIR/13_xss_testing"
    mkdir -p "$OUTPUT_DIR/14_port_scan"
    mkdir -p "$OUTPUT_DIR/17_cloud_exposure"
    mkdir -p "$OUTPUT_DIR/14_reporting"
    mkdir -p "$OUTPUT_DIR/reports"
    mkdir -p "$OUTPUT_DIR/04_http_discovery/responses"
    
    log_section "Directory structure created"
    log_info "Scan ID: ${safe_target}-${scan_timestamp}"
    log_info "Output: $OUTPUT_DIR"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local required_tools=("jq" "curl" "python3" "go")
    local recon_tools=("subfinder" "puredns" "dnsx" "naabu" "httpx" "nuclei" "gau" \
                       "gospider" "katana" "wafw00f" "nmap" "dirsearch" "trufflehog" \
                       "ffuf" "gf" "dalfox" "haktrails")
    local missing_required=()
    local missing_recon=()
    
    # Check required system tools
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool")
            log_error "Missing required tool: $tool"
        fi
    done
    
    # Check recon tools (optional but recommended)
    for tool in "${recon_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_recon+=("$tool")
            log_warn "Missing recon tool: $tool"
        fi
    done
    
    # Fail if required tools are missing
    if [ ${#missing_required[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_required[*]}"
        log_error "Please install them first"
        return 1
    fi
    
    # Warn about missing recon tools
    if [ ${#missing_recon[@]} -gt 0 ]; then
        log_warn "Missing recon tools: ${missing_recon[*]}"
        log_warn "Install them with: bash setup.sh"
        log_warn "Continuing with available tools..."
    else
        log_info "All dependencies available"
    fi
    
    return 0
}

download_wordlists() {
    local list_dir="$PROJECT_ROOT/lists"
    mkdir -p "$list_dir"

    download_if_missing() {
        local url="$1"
        local dest="$2"
        if [ -f "$dest" ]; then
            return 0
        fi
        if ! curl -fsSL "$url" -o "$dest" 2>/dev/null; then
            log_warn "Failed to download $(basename "$dest")"
        fi
    }
    
    download_if_missing \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
        "$list_dir/subdomains-top1million-110000.txt"

    download_if_missing \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        "$list_dir/common.txt"

    download_if_missing \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" \
        "$list_dir/LFI-Jhaddix.txt"

    download_if_missing \
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        "$list_dir/resolvers.txt"
    
    WORDLIST_DIR="$list_dir"
    log_info "Wordlists ready"
}

###################################################################################################
# MODULE 1: ASSET DISCOVERY
###################################################################################################

module_asset_discovery() {
    local target="$1"
    log_section "MODULE 1: Asset Discovery"
    log_info "Target: $target"
    
    local output_file="$OUTPUT_DIR/01_asset_discovery/$(make_iso_filename "$target" "asset_discovery" "results")"
    local start_time=$(date +%s)
    
    # Certificate Transparency
    log_info "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | sed 's/\*\.//g' | \
        awk -v root="$target" '$0 == root || substr($0, length($0)-length(root)) == "." root' | \
        sort -u > "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt"

    # Historical URLs are an asset source: they reveal hosts, paths, JS and parameters.
    local gau_status="unavailable"
    local gau_urls="$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"
    local gau_hosts="$OUTPUT_DIR/01_asset_discovery/gau_hosts.txt"
    > "$gau_urls"
    > "$gau_hosts"
    if command -v "$GAU" &>/dev/null; then
        log_info "Discovering historical assets with gau..."
        if "$GAU" --subs --threads 5 --timeout 10 "$target" 2>/dev/null | sort -u > "$gau_urls"; then
            gau_status="completed"
        else
            gau_status="failed"
            log_warn "gau failed; continuing with CT and enumeration sources"
        fi
        awk -F/ -v root="$target" 'NF >= 3 {h=$3; sub(/:.*/, "", h); if (h == root || substr(h, length(h)-length(root)) == "." root) print h}' \
            "$gau_urls" | sort -u > "$gau_hosts"
    else
        log_warn "gau is not installed; historical asset discovery is unavailable"
    fi
    
    local ct_count=$(count_lines "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt")
    local gau_url_count=$(count_lines "$gau_urls")
    local gau_host_count=$(count_lines "$gau_hosts")
    log_info "Asset sources: CT=$ct_count hosts, gau=$gau_host_count hosts/$gau_url_count URLs"
    
    # Create scope
    mkdir -p "$PROJECT_ROOT/scope"
    echo "$target" > "$PROJECT_ROOT/scope/roots.txt"
    
    local end_time=$(date +%s)
    jq -n --arg target "$target" --arg timestamp "$(date -Iseconds)" --arg gau_status "$gau_status" \
        --argjson ct "$ct_count" --argjson gau_hosts "$gau_host_count" --argjson gau_urls "$gau_url_count" \
        --argjson duration "$((end_time - start_time))" \
        '{module:"asset_discovery", target:$target, timestamp:$timestamp, root_domains:[$target], sources:{crt_sh:{status:"completed",hosts:$ct},gau:{status:$gau_status,hosts:$gau_hosts,urls:$gau_urls}}, duration_seconds:$duration}' \
        > "$output_file"
    
    log_info "Asset discovery completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 2: SUBDOMAIN ENUMERATION
###################################################################################################

module_subdomain_enum() {
    local target="$1"
    log_section "MODULE 2: Subdomain Enumeration"
    
    local output_file="$OUTPUT_DIR/02_subdomain_enum/$(make_iso_filename "$target" "subdomain_enum" "results")"
    local start_time=$(date +%s)
    local all_subs="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    
    > "$all_subs"
    printf '%s\n' "$target" >> "$all_subs"

    # Reuse Module 1 outputs instead of querying the same source and discarding gau hosts.
    [ -s "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt" ] && cat "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt" >> "$all_subs"
    [ -s "$OUTPUT_DIR/01_asset_discovery/gau_hosts.txt" ] && cat "$OUTPUT_DIR/01_asset_discovery/gau_hosts.txt" >> "$all_subs"
    
    # Passive: crt.sh
    log_info "Passive: crt.sh..."
    if [ ! -s "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt" ]; then
        curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | sed 's/\*\.//g' >> "$all_subs"
    fi
    
    # Passive: subfinder
    log_info "Passive: subfinder..."
    command -v "$SUBFINDER" &>/dev/null && "$SUBFINDER" -d "$target" -silent 2>/dev/null >> "$all_subs"
    
    # Passive: haktrails
    log_info "Passive: haktrails..."
    if command -v haktrails &>/dev/null; then
        echo "$target" | haktrails subdomains 2>/dev/null >> "$all_subs" || true
    else
        log_warn "haktrails not installed, skipping"
    fi
    
    # Active: puredns brute force with conservative bandwidth limits by default.
    local puredns_status="skipped"
    local puredns_wordlist="$OUTPUT_DIR/02_subdomain_enum/puredns_wordlist_limited.txt"
    local puredns_resolvers="$OUTPUT_DIR/02_subdomain_enum/puredns_resolvers_limited.txt"
    local puredns_results="$OUTPUT_DIR/02_subdomain_enum/bruteforce.txt"
    if [ "$PUREDNS_ENABLED" = "false" ]; then
        log_warn "puredns brute force disabled by PUREDNS_ENABLED=false"
    elif ! command -v "$PUREDNS" &>/dev/null; then
        log_warn "puredns not installed, skipping active brute force"
    elif [ -f "$WORDLIST_DIR/subdomains-top1million-110000.txt" ] && [ -f "$WORDLIST_DIR/resolvers.txt" ]; then
        log_info "Active: puredns brute force with rate limit ${PUREDNS_RATE_LIMIT} qps, ${PUREDNS_THREADS} wildcard threads..."

        head -n "$PUREDNS_WORDLIST_LIMIT" "$WORDLIST_DIR/subdomains-top1million-110000.txt" > "$puredns_wordlist"
        head -n "$PUREDNS_RESOLVER_LIMIT" "$WORDLIST_DIR/resolvers.txt" > "$puredns_resolvers"

        "$PUREDNS" bruteforce "$puredns_wordlist" "$target" \
            -r "$puredns_resolvers" \
            --rate-limit "$PUREDNS_RATE_LIMIT" \
            --rate-limit-trusted "$PUREDNS_TRUSTED_RATE_LIMIT" \
            --threads "$PUREDNS_THREADS" \
            --wildcard-batch "$PUREDNS_WILDCARD_BATCH" \
            --wildcard-tests "$PUREDNS_WILDCARD_TESTS" \
            -w "$puredns_results" 2>"$OUTPUT_DIR/02_subdomain_enum/puredns.stderr" || puredns_status="failed"

        [ "$puredns_status" = "skipped" ] && puredns_status="completed"
        [ -f "$puredns_results" ] && cat "$puredns_results" >> "$all_subs"
    else
        log_warn "puredns wordlist or resolver list missing, skipping active brute force"
    fi
    
    # Deduplicate
    awk -v root="$target" '$0 == root || substr($0, length($0)-length(root)) == "." root' "$all_subs" | sort -u > "${all_subs}.tmp"
    mv "${all_subs}.tmp" "$all_subs"
    
    local total=$(wc -l < "$all_subs" | tr -d ' ')
    log_info "Total subdomains: $total"
    
    # Update manifest
    while IFS= read -r sub; do
        [ -z "$sub" ] && continue
        update_manifest "$sub" "resolved" "false"
        update_manifest "$sub" "source" "\"subdomain_enum\""
    done < "$all_subs"
    
    update_statistics "total_hosts" "$total"
    TOTAL_HOSTS=$total
    
    # Create output JSON
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "subdomain_enum",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "total_subdomains": $total,
  "puredns": {
    "status": "$puredns_status",
    "enabled": "$PUREDNS_ENABLED",
    "wordlist_limit": $PUREDNS_WORDLIST_LIMIT,
    "resolver_limit": $PUREDNS_RESOLVER_LIMIT,
    "rate_limit_qps": $PUREDNS_RATE_LIMIT,
    "trusted_rate_limit_qps": $PUREDNS_TRUSTED_RATE_LIMIT,
    "wildcard_threads": $PUREDNS_THREADS,
    "wildcard_batch": $PUREDNS_WILDCARD_BATCH,
    "wildcard_tests": $PUREDNS_WILDCARD_TESTS
  },
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Subdomain enumeration completed: $total subdomains"
    echo "$output_file"
}

###################################################################################################
# MODULE 3: DNS RESOLUTION AND CDN FILTERING
###################################################################################################

module_dns_resolution() {
    local target="$1"
    log_section "MODULE 3: DNS Resolution"
    
    local all_subs="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    [ ! -f "$all_subs" ] && { log_error "No subdomains found"; return 1; }
    command -v "$DNSX" &>/dev/null || { log_error "dnsx is required for DNS resolution"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/03_dns_resolution/$(make_iso_filename "$target" "dns_resolution" "results")"
    
    # Resolve with dnsx - get ALL IPs (including CDN)
    log_info "Resolving subdomains..."
    $DNSX -l "$all_subs" -json -o "$OUTPUT_DIR/03_dns_resolution/dns_results.json" -t 100 -silent 2>/dev/null
    
    # Extract ALL resolved hosts (including CDN)
    [ -f "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ] && \
        jq -r 'select(.a != null) | .host' "$OUTPUT_DIR/03_dns_resolution/dns_results.json" | sort -u > "$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    
    local resolved=$(wc -l < "$OUTPUT_DIR/03_dns_resolution/resolved.txt" 2>/dev/null | tr -d ' ')
    log_info "Resolved: $resolved hosts"
    
    # Extract ALL IPs
    [ -f "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ] && \
        jq -r '.a[]?' "$OUTPUT_DIR/03_dns_resolution/dns_results.json" | sort -u > "$OUTPUT_DIR/03_dns_resolution/all_ips.txt"
    
    # Get IP annotations (ASN, PTR, CDN detection) for analysis only
    if [ -f "$OUTPUT_DIR/03_dns_resolution/all_ips.txt" ]; then
        log_info "Getting IP metadata (ASN, PTR, CDN info)..."
        $DNSX -l "$OUTPUT_DIR/03_dns_resolution/all_ips.txt" -ptr -asn -cdn -json \
            -o "$OUTPUT_DIR/03_dns_resolution/ip_annotations.json" -silent 2>/dev/null
        
        # Extract CDN info and IPs
        [ -f "$OUTPUT_DIR/03_dns_resolution/ip_annotations.json" ] && \
            jq -r 'select(.cdn_name != null or .cdn == true or .is_cdn == true) | .host' "$OUTPUT_DIR/03_dns_resolution/ip_annotations.json" 2>/dev/null | \
            sort -u > "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt"
        
        local cdn_count=$(wc -l < "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt" 2>/dev/null | tr -d ' ')
        log_info "CDN IPs detected: $cdn_count (for informational purposes, will be scanned)"
    fi
    
    # Update manifest
    [ -f "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ] && \
        jq -r 'select(.a != null) | "\(.host)|\(.a[0])"' "$OUTPUT_DIR/03_dns_resolution/dns_results.json" | \
        while IFS='|' read -r host ip; do
            [ -z "$host" ] || [ -z "$ip" ] && continue
            local is_cdn="false"
            [ -f "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt" ] && grep -q "^${ip}$" "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt" && is_cdn="true"
            update_manifest_bulk "$host" "{\"resolved\": true, \"ip\": \"$ip\", \"cdn\": $is_cdn}"
        done
    
    update_statistics "resolved_hosts" "$resolved"
    RESOLVED_HOSTS=$resolved
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "dns_resolution",
  "resolved_hosts": $resolved,
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "DNS resolution completed: $resolved resolved"
    echo "$output_file"
}
###################################################################################################
# MODULE 4: HTTP DISCOVERY AND PORT SCANNING
###################################################################################################

module_http_discovery() {
    local target="$1"
    log_section "MODULE 4: Quick HTTP Discovery (Web Apps Only)"
    
    local resolved_file="$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    [ ! -f "$resolved_file" ] && { log_error "No resolved hosts found"; return 1; }
    command -v "$HTTPX" &>/dev/null || { log_error "httpx is required for HTTP discovery"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/04_http_discovery/$(make_iso_filename "$target" "http_discovery" "results")"
    
    # Step 1: Create unique resolved list (remove duplicates) - INCLUDING CDN domains
    log_info "Deduplicating resolved hosts..."
    sort -u "$resolved_file" > "$OUTPUT_DIR/04_http_discovery/resolved_unique.txt"
    local unique_count=$(wc -l < "$OUTPUT_DIR/04_http_discovery/resolved_unique.txt" | tr -d ' ')
    log_info "Unique domains: $unique_count (CDN domains included)"
    
    # Step 2: Quick HTTP discovery with httpx ONLY (fast, no full port scan yet)
    log_info "Quick HTTP discovery with httpx (common ports only)..."
    $HTTPX -l "$OUTPUT_DIR/04_http_discovery/resolved_unique.txt" \
        -sr -srd "$OUTPUT_DIR/04_http_discovery/responses" \
        -json -o "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" \
        -timeout 10 -threads 100 -silent 2>/dev/null
    
    # Extract HTTP hosts - full URLs
    [ -f "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" ] && \
        jq -r '.url // "https://\(.host)"' "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" | sort -u > "$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    
    local http_count=$(wc -l < "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" 2>/dev/null | tr -d ' ')
    log_info "HTTP confirmed: $http_count web applications"
    
    # Create plain host list (without scheme) for crawling/scanning tools
    [ -f "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" ] && \
        awk '{value=$0; sub(/^[[:alpha:]][[:alnum:]+.-]*:\/\//, "", value); sub(/\/.*/, "", value); if (value != "") print value}' \
        "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" | sort -u > "$OUTPUT_DIR/04_http_discovery/host_list.txt"
    
    # Show sample of found web apps
    [ -f "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" ] && head -20 "$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    
    # Update manifest
    [ -f "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" ] && \
        jq -r 'select(.status_code != null) | "\(.input // .host)|\(.status_code)"' "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" | \
        while IFS='|' read -r host status; do
            [ -z "$host" ] || [ -z "$status" ] && continue
            update_manifest_bulk "$host" "{\"http_status\": $status, \"has_webapp\": true}"
        done
    
    update_statistics "http_hosts" "$http_count"
    HTTP_HOSTS=$http_count
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "http_discovery",
  "http_hosts": $http_count,
  "unique_domains": $unique_count,
  "duration_seconds": $((end_time - start_time)),
  "note": "Quick HTTP discovery only. Full port scan scheduled after web app scans."
}
EOF
    
    log_info "Quick HTTP discovery completed: $http_count web apps found"
    log_info "Full port scan will run after web application scanning modules complete"
    echo "$output_file"
}
###################################################################################################
# MODULE 5: WAF DETECTION AND BASELINE CALIBRATION
###################################################################################################

module_waf_detection() {
    local target="$1"
    log_section "MODULE 5: WAF Detection and Baseline Calibration"
    
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ ! -f "$http_hosts_file" ] && { log_error "No HTTP hosts found"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/05_waf_detection/$(make_iso_filename "$target" "waf_detection" "results")"
    
    local skip_hosts_file="$OUTPUT_DIR/05_waf_detection/skip_bruteforce.txt"
    local detections_file="$OUTPUT_DIR/05_waf_detection/waf_detections.jsonl"
    > "$skip_hosts_file"
    > "$detections_file"
    local wafw00f_status="unavailable"
    command -v "$WAFW00F" &>/dev/null && wafw00f_status="available"
    
    # Process each host
    log_info "Calibrating WAF baseline for $(wc -l < "$http_hosts_file") hosts..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host=$(url_host "$url")
        local safe_host=$(safe_name "$host")
        log_debug "Checking: $url"
        
        local baseline_dir="$OUTPUT_DIR/05_waf_detection/$safe_host"
        mkdir -p "$baseline_dir"
        
        # Request 1: Root path
        curl -skL -D "$baseline_dir/root.headers" -o "$baseline_dir/root.body" \
            "${url%/}/" --max-time 10 2>/dev/null
        
        [ ! -f "$baseline_dir/root.body" ] && continue
        
        # Request 2: Junk path
        local junk="/$(head -c 12 /dev/urandom | xxd -p)_zr"
        curl -skL -D "$baseline_dir/junk.headers" -o "$baseline_dir/junk.body" \
            "${url%/}$junk" --max-time 10 2>/dev/null
        
        [ ! -f "$baseline_dir/junk.body" ] && continue
        
        # Get lengths
        local root_len=$(wc -c < "$baseline_dir/root.body")
        local junk_len=$(wc -c < "$baseline_dir/junk.body")
        local len_diff=$((root_len - junk_len))
        [ $len_diff -lt 0 ] && len_diff=$((-len_diff))
        local len_pct=$((len_diff * 100 / (root_len + 1)))
        
        # Detect catchall
        local catchall="false"
        [ $len_pct -lt 5 ] && catchall="true"
        
        # wafw00f is authoritative when available; signatures remain a deterministic fallback.
        local waf_vendor="none"
        local detection_source="none"

        # Tier 1: wafw00f — authoritative; if it finds something, stop here
        local waf_json="$baseline_dir/wafw00f.json"
        if command -v "$WAFW00F" &>/dev/null; then
            if "$WAFW00F" -a -f json -o "$waf_json" "$url" >/dev/null 2>&1; then
                wafw00f_status="completed"
                local _vendor
                _vendor=$(jq -r '
                    (if type == "array" then .[0] else . end) as $r |
                    ($r.firewall // $r.waf // empty) |
                    if type == "array" then join(", ") else . end
                ' "$waf_json" 2>/dev/null)
                if [ -n "$_vendor" ] && [ "$_vendor" != "null" ] && [ "$_vendor" != "none" ]; then
                    waf_vendor="$_vendor"
                    detection_source="wafw00f"
                    log_info "  [wafw00f] WAF detected: $waf_vendor ($url)"
                fi
            else
                wafw00f_status="partial_failure"
                log_warn "  [wafw00f] failed for $url"
            fi
        else
            log_warn "  wafw00f not installed; skipping Tier 1"
        fi

        # Tier 2: nuclei waf-detect — only if wafw00f found nothing
        if [ "$waf_vendor" = "none" ]; then
            if command -v "$NUCLEI" &>/dev/null; then
                local nuclei_out
                nuclei_out=$("$NUCLEI" -u "$url" -tags waf -silent -nc 2>/dev/null)
                if [ -n "$nuclei_out" ]; then
                    local waf_name
                    waf_name=$(printf '%s' "$nuclei_out" | grep -o '\[[^]]*waf-detect:[^]]*\]' | head -n 1 | sed 's/\[.*waf-detect://; s/\]//')
                    if [ -n "$waf_name" ]; then
                        waf_vendor=$(printf '%s' "$waf_name" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')
                        detection_source="nuclei"
                        log_info "  [nuclei] WAF detected: $waf_vendor ($url)"
                    fi
                fi
            else
                log_warn "  nuclei not installed; skipping Tier 2"
            fi
        fi

        # Tier 3: httpx tech-detect — only if both wafw00f and nuclei found nothing
        if [ "$waf_vendor" = "none" ]; then
            if command -v "$HTTPX" &>/dev/null; then
                local httpx_out
                httpx_out=$("$HTTPX" -u "$url" -tech-detect -silent -nc 2>/dev/null)
                if [ -n "$httpx_out" ]; then
                    local -a waf_list=("Cloudflare" "AWS WAF" "Akamai" "Imperva Incapsula" "Sucuri" \
                        "F5 BIG-IP ASM" "Barracuda WAF" "Fortinet FortiWeb" "Radware AppWall" \
                        "Citrix ADC" "Citrix NetScaler" "Azure Front Door WAF" "Reblaze" \
                        "StackPath WAF" "Fastly Next-Gen WAF" "Signal Sciences" "DataDome" \
                        "Yundun" "Safe3 WAF" "ModSecurity" "Tencent Cloud WAF" "Alibaba Cloud WAF" \
                        "Huawei Cloud WAF" "Oracle Cloud WAF" "Palo Alto Prisma Cloud WAAS" \
                        "Wallarm" "AppTrana" "DenyALL WAF" "NSFocus WAF" "KnownSec WAF" \
                        "360 Web Application Firewall" "Anquanbao" "PowerCDN WAF" "Edgecast WAF" \
                        "CDN77 WAF" "Cloudbric" "Comodo WAF" "DOSarrest" "GreyWizard" \
                        "Varnish Security Layer" "Profense" "Bekchy WAF" "BinarySec" "NAXSI" \
                        "ExpressionEngine Secure Gateway")
                    for w in "${waf_list[@]}"; do
                        if printf '%s' "$httpx_out" | grep -Fqi "$w"; then
                            waf_vendor="$w"
                            detection_source="httpx"
                            log_info "  [httpx] WAF detected: $waf_vendor ($url)"
                            break
                        fi
                    done
                fi
            else
                log_warn "  httpx not installed; skipping Tier 3"
            fi
        fi

        [ "$waf_vendor" = "none" ] && log_debug "  No WAF detected for $url"
        
        # Detect JS challenge
        local js_challenge="false"
        grep -qiE 'cf-chl|jschl-answer|checking your browser|captcha|challenge-platform' \
            "$baseline_dir/junk.headers" "$baseline_dir/junk.body" 2>/dev/null && js_challenge="true"
        
        # Skip bruteforce if WAF or catchall
        local skip_bruteforce="false"
        if [ "$catchall" = "true" ] || [ "$waf_vendor" != "none" ] || [ "$js_challenge" = "true" ]; then
            skip_bruteforce="true"
        fi
        
        [ "$skip_bruteforce" == "true" ] && echo "$host" >> "$skip_hosts_file"
        
        local detection_json
        detection_json=$(jq -nc --arg url "$url" --arg host "$host" --arg vendor "$waf_vendor" \
            --arg source "$detection_source" --argjson catchall "$catchall" --argjson challenge "$js_challenge" \
            --argjson skip "$skip_bruteforce" --argjson root_len "$root_len" --argjson junk_len "$junk_len" \
            '{url:$url,host:$host,waf_vendor:$vendor,detection_source:$source,catchall_detected:$catchall,js_challenge_detected:$challenge,skip_bruteforce:$skip,baseline_root_len:$root_len,baseline_junk_len:$junk_len}')
        printf '%s\n' "$detection_json" >> "$detections_file"
        update_manifest_bulk "$host" "$detection_json"
        
        if [ "$skip_bruteforce" == "true" ]; then
            log_warn "  SKIP: $host (WAF: $waf_vendor, catchall: $catchall)"
        else
            log_info "  OK: $host"
        fi
        
    done < "$http_hosts_file"
    
    sort -u "$skip_hosts_file" -o "$skip_hosts_file"
    local waf_count=$(jq -s '[.[] | select(.waf_vendor != "none")] | length' "$detections_file" 2>/dev/null || echo 0)
    local skipped_count=$(count_lines "$skip_hosts_file")
    log_info "WAF-protected hosts: $waf_count; active discovery gated: $skipped_count"
    WAF_HOSTS=$waf_count
    
    update_statistics "waf_hosts" "$waf_count"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "waf_detection",
  "waf_hosts": $waf_count,
  "hosts_gated": $skipped_count,
  "wafw00f_status": "$wafw00f_status",
  "detections_file": "waf_detections.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "WAF detection completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 6: HEADER ANALYSIS AND SECURITY SCORING
###################################################################################################

module_header_analysis() {
    local target="$1"
    log_section "MODULE 6: Header Analysis"
    
    local http_confirmed="$OUTPUT_DIR/04_http_discovery/http_confirmed.json"
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ ! -f "$http_confirmed" ] && [ ! -f "$http_hosts_file" ] && { log_error "No HTTP hosts found"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/06_header_analysis/$(make_iso_filename "$target" "header_analysis" "results")"
    
    # Security headers to check
    local -a SEC_HEADERS=("strict-transport-security" "content-security-policy" "x-frame-options" \
                         "x-content-type-options" "referrer-policy" "permissions-policy")
    
    local header_scores=0
    local hosts_analyzed=0
    local findings_file="$OUTPUT_DIR/06_header_analysis/header_findings.jsonl"
    > "$findings_file"
    
    local host_count=$(wc -l < "$http_hosts_file" 2>/dev/null | tr -d ' ')
    [ -z "$host_count" ] && host_count=0
    log_info "Analyzing headers for $host_count hosts..."
    
    if [ -f "$http_confirmed" ]; then
        jq -r '.url // empty' "$http_confirmed" 2>/dev/null | sort -u > "$OUTPUT_DIR/04_http_discovery/http_urls.txt"
    fi
    local urls_file="$OUTPUT_DIR/04_http_discovery/http_urls.txt"
    [ ! -f "$urls_file" ] && [ -f "$http_hosts_file" ] && cp "$http_hosts_file" "$urls_file"
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host="${url#*://}"
        host="${host%%/*}"
        
        local response_dir="$OUTPUT_DIR/04_http_discovery/responses"
        local response_file=""
        local safe_name
        safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')
        
        # Find or create a headers file
        if [ -f "$response_dir/${safe_name}_headers.txt" ]; then
            response_file="$response_dir/${safe_name}_headers.txt"
        else
            mkdir -p "$response_dir"
            if ! curl -s -D "$response_dir/${safe_name}_headers.txt" -o /dev/null -k "$url" --max-time 8 2>/dev/null; then
                curl -s -D "$response_dir/${safe_name}_headers.txt" -o /dev/null "http://${host}/" --max-time 8 2>/dev/null || true
            fi
            response_file="$response_dir/${safe_name}_headers.txt"
        fi
        
        [ ! -f "$response_file" ] && continue
        
        # Score headers
        local score=0
        local missing_headers=""
        
        for header in "${SEC_HEADERS[@]}"; do
            if grep -qi "^$header:" "$response_file"; then
                ((score++))
            else
                missing_headers="${missing_headers}${header}\n"
            fi
        done
        
        # Check cookie security
        local cookie_issues=""
        if grep -qi "^set-cookie:" "$response_file"; then
            grep -i "^set-cookie:" "$response_file" | grep -qiv "httponly" && cookie_issues="${cookie_issues}missing_httponly\n"
            grep -i "^set-cookie:" "$response_file" | grep -qiv "secure" && cookie_issues="${cookie_issues}missing_secure\n"
            grep -i "^set-cookie:" "$response_file" | grep -qiv "samesite" && cookie_issues="${cookie_issues}missing_samesite\n"
        fi
        
        # Extract server banner
        local server_banner=""
        if grep -qi "^server:" "$response_file"; then
            server_banner=$(grep -i "^server:" "$response_file" | tail -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r\n')
        fi

        local missing_json cookie_json finding_json
        missing_json=$(printf '%b' "$missing_headers" | jq -Rsc 'split("\n") | map(select(length > 0))')
        cookie_json=$(printf '%b' "$cookie_issues" | jq -Rsc 'split("\n") | map(select(length > 0))')
        finding_json=$(jq -nc --arg url "$url" --arg host "$host" --arg server "$server_banner" \
            --argjson score "$score" --argjson missing "$missing_json" --argjson cookies "$cookie_json" \
            '{url:$url,host:$host,security_header_score:$score,missing_headers:$missing,cookie_issues:$cookies,server_banner:$server}')
        printf '%s\n' "$finding_json" >> "$findings_file"
        update_manifest_bulk "$host" "$finding_json"
        
        header_scores=$((header_scores + score))
        ((hosts_analyzed++))

    done < "$urls_file"

    local avg_score=0
    [ $hosts_analyzed -gt 0 ] && avg_score=$((header_scores / hosts_analyzed))

    # ── API endpoint detection ──
    log_info "Running API endpoint detection..."
    local api_count=0
    api_count=$(python3 - "$http_confirmed" "$OUTPUT_DIR/09_crawling/all_urls.txt" "$MANIFEST_FILE" << 'APIDETECT_EOF'
import json, sys, re, os

httpx_file = sys.argv[1]
crawled_file = sys.argv[2]
manifest_file = sys.argv[3]

API_CONTENT_TYPES = {'application/json', 'application/xml', 'application/grpc',
                     'text/xml', 'application/soap+xml', 'application/graphql',
                     'application/vnd.api+json', 'application/hal+json',
                     'application/problem+json'}
API_PATH_RE = re.compile(r'/api/|/v[0-9]+/|/graphql|/rest/|/ws/|/rpc/|/oauth/|/token|/webhook', re.I)
API_SERVER_BANNERS = {'gunicorn', 'uvicorn', 'kestrel', 'fastapi', 'express',
                      'daphne', 'puma', 'thin', 'phusion', 'openresty'}
HTML_TECH = {'react', 'jquery', 'bootstrap', 'angular', 'vue', 'wordpress',
             'drupal', 'joomla', 'wix', 'squarespace', 'next.js', 'nuxt',
             'tailwind', 'materialize'}

# Parse httpx data per host
host_httpx = {}
if os.path.exists(httpx_file):
    with open(httpx_file, errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                host = e.get('input') or e.get('host', '')
                if not host:
                    continue
                host_httpx.setdefault(host, []).append(e)
            except Exception:
                continue

# Parse crawled URLs per host
host_crawled = {}
if os.path.exists(crawled_file):
    with open(crawled_file, errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            try:
                h = url.split('//')[1].split('/')[0].split(':')[0]
                host_crawled.setdefault(h, []).append(url)
            except Exception:
                continue

# Load manifest
manifest = {}
if os.path.exists(manifest_file):
    with open(manifest_file) as f:
        manifest = json.load(f)

api_hosts = {}

for host, entries in host_httpx.items():
    signals = []

    for e in entries:
        ct = (e.get('content_type') or '').lower().strip()
        path = e.get('path', '/')
        words = e.get('words', 0) or 0
        lines = e.get('lines', 0) or 0
        tech = [t.lower() for t in (e.get('tech') or [])]
        server = (e.get('webserver') or '').lower()

        # Tier 1: API content-type + API path pattern
        ct_base = ct.split(';')[0].strip()
        is_api_ct = ct_base in API_CONTENT_TYPES
        is_api_path = bool(API_PATH_RE.search(path))

        if is_api_ct and is_api_path:
            signals.append('content_type+path')

        # Tier 2: API content-type + compact response (JSON blob, not HTML)
        if is_api_ct and words > 0 and lines <= 3:
            signals.append('content_type+compact_response')

        # Tier 3: API content-type + no HTML framework in tech stack
        if is_api_ct:
            has_html_tech = any(t in HTML_TECH for t in tech)
            if not has_html_tech:
                signals.append('content_type+no_html_tech')

        # Tier 4: API server banner + API content-type
        if is_api_ct and any(b in server for b in API_SERVER_BANNERS):
            signals.append('api_server+content_type')

    # Tier 5: crawled URLs show API paths, and no crawled URL returned HTML for this host
    crawled = host_crawled.get(host, [])
    api_urls = [u for u in crawled if API_PATH_RE.search(u)]
    if api_urls:
        # Check if any httpx entry for this host had text/html as primary
        has_html_primary = any(
            (e.get('content_type') or '').startswith('text/html')
            and (e.get('words', 0) or 0) > 100
            for e in entries
        )
        if not has_html_primary:
            signals.append('crawled_api_paths+no_html')
        else:
            signals.append('crawled_api_paths_mixed')

    if signals:
        # Deduplicate
        unique_signals = list(dict.fromkeys(signals))
        # Definite API: tier 1 or 2 or (tier 3 + server banner)
        is_definite = any(s in unique_signals for s in
            ['content_type+path', 'content_type+compact_response', 'api_server+content_type'])
        is_api_host = any(s in unique_signals for s in
            ['content_type+no_html_tech', 'crawled_api_paths+no_html'])

        if is_definite or is_api_host:
            api_hosts[host] = {
                'is_api': True,
                'api_signals': unique_signals,
                'api_urls': api_urls[:10],
            }

# Write to manifest
count = 0
if api_hosts and manifest:
    for host, api_data in api_hosts.items():
        if host in manifest.get('hosts', {}):
            manifest['hosts'][host]['is_api'] = True
            manifest['hosts'][host]['api_signals'] = api_data['api_signals']
            count += 1
    with open(manifest_file, 'w') as f:
        json.dump(manifest, f, indent=2)

print(count)
APIDETECT_EOF
    ) || api_count=0

    log_info "API endpoints detected: $api_count hosts"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "header_analysis",
  "hosts_analyzed": $hosts_analyzed,
  "average_score": $avg_score,
  "api_hosts_detected": $api_count,
  "findings_file": "header_findings.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF

    log_info "Header analysis completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 7: SERVICE FINGERPRINTING (Non-HTTP)
###################################################################################################

module_service_fingerprint() {
    local target="$1"
    log_section "MODULE 7: Service Fingerprinting"
    
    local ports_file="$OUTPUT_DIR/14_port_scan/all_ports_list.txt"
    [ ! -s "$ports_file" ] && { log_info "No open ports from the full port scan"; return 0; }
    command -v "$NMAP" &>/dev/null || { log_warn "nmap is unavailable; service fingerprinting skipped"; return 0; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/07_service_fingerprint/$(make_iso_filename "$target" "service_fingerprint" "results")"
    
    log_info "Fingerprinting services discovered by the full port scan..."
    
    # Nmap requires targets and ports separately; host:port entries in -iL are invalid.
    sed -E 's/:[0-9]+$//' "$ports_file" | sort -u > "$OUTPUT_DIR/07_service_fingerprint/hosts.txt"
    local nmap_ports
    nmap_ports=$(sed -E 's/^.*:([0-9]+)$/\1/' "$ports_file" | sort -nu | paste -sd, -)
    [ -z "$nmap_ports" ] && { log_warn "No valid ports to fingerprint"; return 0; }
    
    # Run nmap service detection
    "$NMAP" -sV -Pn -iL "$OUTPUT_DIR/07_service_fingerprint/hosts.txt" -p "$nmap_ports" \
        --version-intensity 5 -oX "$OUTPUT_DIR/07_service_fingerprint/nmap_results.xml" \
        --max-retries 2 -T4 > /dev/null 2>&1
    
    # Parse nmap XML and update manifest
    if [ -f "$OUTPUT_DIR/07_service_fingerprint/nmap_results.xml" ]; then
        python3 - "$OUTPUT_DIR/07_service_fingerprint/nmap_results.xml" "$MANIFEST_FILE" \
            "$OUTPUT_DIR/07_service_fingerprint/services.json" << 'PYTHON_EOF'
import xml.etree.ElementTree as ET
import json
import sys

try:
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()
    
    # Read manifest
    try:
        with open(sys.argv[2], 'r') as f:
            manifest = json.load(f)
    except:
        manifest = {'hosts': {}}
    
    findings = []
    for host in root.findall('.//host'):
        addr = host.find('address[@addrtype="ipv4"]')
        if addr is None:
            continue
        ip = addr.get('addr')
        hostname_node = host.find('hostnames/hostname')
        hostname = hostname_node.get('name') if hostname_node is not None else ip
        host_services = []
        
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            port_num = port.get('portid')
            service = port.find('service')
            name = service.get('name', 'unknown') if service is not None else 'unknown'
            tunnel = service.get('tunnel', '') if service is not None else ''
            item = {
                'host': hostname,
                'ip': ip,
                'port': int(port_num),
                'protocol': port.get('protocol', 'tcp'),
                'name': name,
                'product': service.get('product', '') if service is not None else '',
                'version': service.get('version', '') if service is not None else '',
                'extrainfo': service.get('extrainfo', '') if service is not None else '',
                'tunnel': tunnel,
                'cpe': [cpe.text for cpe in service.findall('cpe')] if service is not None else [],
                'service_type': 'http' if 'http' in name.lower() else 'non_http'
            }
            findings.append(item)
            host_services.append(item)

        if host_services:
            manifest_key = hostname
            if manifest_key not in manifest.get('hosts', {}):
                manifest_key = next((key for key, value in manifest.get('hosts', {}).items() if value.get('ip') == ip), hostname)
            manifest.setdefault('hosts', {}).setdefault(manifest_key, {})
            manifest['hosts'][manifest_key]['ip'] = ip
            manifest['hosts'][manifest_key]['ports_open'] = sorted({item['port'] for item in host_services})
            manifest['hosts'][manifest_key]['services'] = host_services
    
    with open(sys.argv[2], 'w') as f:
        json.dump(manifest, f, indent=2)
    with open(sys.argv[3], 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"Parsed {len(findings)} open services")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    raise
PYTHON_EOF
    fi
    local service_count=$(jq 'length' "$OUTPUT_DIR/07_service_fingerprint/services.json" 2>/dev/null || echo 0)
    local non_http_count=$(jq '[.[] | select(.service_type == "non_http")] | length' "$OUTPUT_DIR/07_service_fingerprint/services.json" 2>/dev/null || echo 0)
    update_statistics "services_fingerprinted" "$service_count"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "service_fingerprint",
  "services_fingerprinted": $service_count,
  "non_http_services": $non_http_count,
  "services_file": "services.json",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Service fingerprinting completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 8: DIRECTORY DISCOVERY
###################################################################################################

module_directory_discovery() {
    local target="$1"
    log_section "MODULE 8: Directory Discovery"
    
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/08_directory_discovery/$(make_iso_filename "$target" "directory_discovery" "results")"

    mkdir -p "$OUTPUT_DIR/08_directory_discovery/results"

    log_info "Running directory discovery..."

    # Check if we have http hosts
    [ ! -f "$http_hosts_file" ] && { log_warn "No HTTP hosts file found"; return 0; }

    # Use all HTTP hosts including WAF-protected ones
    local safe_hosts_file="$OUTPUT_DIR/08_directory_discovery/safe_hosts.txt"
    grep -v '^$' "$http_hosts_file" > "$safe_hosts_file"

    local host_count=$(wc -l < "$safe_hosts_file" | tr -d ' ')
    [ "$host_count" -eq 0 ] && { log_warn "No HTTP hosts available for directory discovery"; return 0; }

    log_info "Running directory discovery on $host_count hosts"
    
    # Run dirsearch with plain text file input (Zero-Recon style)
    if command -v dirsearch &>/dev/null; then
        log_info "Running dirsearch on $host_count hosts..."
        
        # Create dirsearch output directory
        mkdir -p "$OUTPUT_DIR/08_directory_discovery/dirsearch"
        
        # dirsearch expects URLs with scheme
        # Convert host list to URL format if needed
        local urls_file="$OUTPUT_DIR/08_directory_discovery/urls_for_dirsearch.txt"
        > "$urls_file"
        
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Add https:// if not already present
            if [[ ! "$host" =~ ^https?:// ]]; then
                echo "https://$host" >> "$urls_file"
            else
                echo "$host" >> "$urls_file"
            fi
        done < "$safe_hosts_file"
        
        # Run dirsearch - output plain text for easy parsing
        dirsearch -l "$urls_file" \
            -w "$WORDLIST_DIR/common.txt" \
            -i 200,301,302,403,405,500 \
            -o "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" \
            -t 30 \
            -q 2>/dev/null || true
        
        # Parse results like Zero-Recon v1
        if [ -f "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" ]; then
            # Extract 200 responses
            awk '$1 == "200" && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt" || true
            
            # Extract 500 responses
            awk '$1 == "500" && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/500response.txt" || true
            
            # Extract 403/405 responses
            awk '($1 == "403" || $1 == "405") && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response.txt" || true
            
            # Verify 403 responses to filter out WAF false positives
            if [ -f "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response.txt" ]; then
                log_info "Verifying 403 responses against WAF signatures..."
                python3 - "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response.txt" "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response_verified.txt" << 'PYTHON_EOF'
import sys
import urllib.request
import concurrent.futures
import ssl

# Ignore SSL errors for verification
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

WAF_SIGNATURES = [
    "cf-ray", "cloudflare ray id",
    "_abck", "bm_sz", "ak_bmsc", "bm_sv", "x-akamai-request-id",
    "visid_incap_", "incap_ses_", "nlbi_", "x-iinfo", "reference #",
    "x-amz-cf-id", "x-amz-cf-pop",
    "x-azure-ref",
    "bigipserver", "mrhsession", "lastmrh_session", "support id",
    "bnes_", "barra_counter_session", "incident id",
    "fortiwafsid",
    "x-sucuri-id", "x-sucuri-cache",
    "datadome", "x-datadome",
    "x-sigsci-requestid", "x-sigsci-agentresponse",
    "nsc_", "nsc_aaac",
    "x-sl-compstate", "x-sl-gw-pt",
    "rbzid",
    "x-sp-waf",
    "x-served-by", "x-cache",
    "mod_security", "modsecurity action",
    "eagleeye-traceid",
    "x-nws-log-uuid",
    "x-hw-waf",
    "x-oracle-dms-ecid",
    "x-wallarm-block-reason",
    "x-apptrana-transaction-id",
    "x-naxsi-sig",
    "cloudbric request id",
    "x-dosarrest",
    "yundun", "yd-waf",
    "safe3waf",
    "ks-waf",
    "360wzws",
    "x-powered-by-anquanbao"
]

def is_waf_response(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            blob = (str(response.headers) + response.read().decode('utf-8', errors='ignore')).lower()
            return any(sig in blob for sig in WAF_SIGNATURES)
    except urllib.error.HTTPError as e:
        blob = (str(e.headers) + e.read().decode('utf-8', errors='ignore')).lower()
        return any(sig in blob for sig in WAF_SIGNATURES)
    except Exception:
        return False

input_file = sys.argv[1]
output_file = sys.argv[2]
try:
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
except Exception:
    sys.exit(0)

valid_urls = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    future_to_url = {executor.submit(is_waf_response, url): url for url in urls}
    for future in concurrent.futures.as_completed(future_to_url):
        url = future_to_url[future]
        try:
            if not future.result():
                valid_urls.append(url)
        except Exception:
            valid_urls.append(url)

with open(output_file, 'w') as f:
    for url in valid_urls:
        f.write(url + '\n')
PYTHON_EOF
                mv "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response_verified.txt" "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response.txt" 2>/dev/null || true
            fi
            
            # Combine all interesting paths
            cat "$OUTPUT_DIR/08_directory_discovery/dirsearch/"*response.txt 2>/dev/null | \
                sort -u > "$OUTPUT_DIR/08_directory_discovery/all_paths.txt" || true
            
            local total_hits=$(wc -l < "$OUTPUT_DIR/08_directory_discovery/all_paths.txt" 2>/dev/null | tr -d ' ' || echo 0)
            log_info "Directory discovery found $total_hits unique paths"
            
            # Store for manifest
            jq -n --arg paths "$OUTPUT_DIR/08_directory_discovery/all_paths.txt" \
                   --argjson count "$total_hits" \
                   '{"paths_file": $paths, "total_paths": $count}' \
                   > "$OUTPUT_DIR/08_directory_discovery/summary.json" 2>/dev/null || true
        fi
    else
        log_warn "dirsearch not installed, skipping"
    fi
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "directory_discovery",
  "duration_seconds": $((end_time - start_time)),
  "safe_hosts": $host_count
}
EOF
    
    log_info "Directory discovery completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 9: WEB CRAWLING AND URL HARVESTING
###################################################################################################

module_crawling() {
    local target="$1"
    log_section "MODULE 9: Web Crawling"
    
    # Preserve the scheme and port confirmed by httpx.
    local http_urls="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ ! -s "$http_urls" ] && { log_error "No HTTP URLs found"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/09_crawling/$(make_iso_filename "$target" "crawling" "results")"
    
    local all_urls="$OUTPUT_DIR/09_crawling/all_urls.txt"
    > "$all_urls"
    
    log_info "Building URL corpus from gau, gospider, katana, and directory findings..."

    # gau runs during asset discovery so its URLs can also contribute new hosts.
    local gau_urls="$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"
    [ -s "$gau_urls" ] && cat "$gau_urls" >> "$all_urls"
    local gau_count=$(count_lines "$gau_urls")
    local gospider_status="unavailable"
    local katana_status="unavailable"
    
    # Crawl each host (Zero-Recon style)
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host="${url#*://}"
        host="${host%%/*}"
        log_debug "Crawling: $url"
        
        # gospider stdout is noisy; extract URLs directly
        if command -v gospider &>/dev/null; then
            gospider_status="completed"
            $GOSPIDER -s "$url" -d 2 -t 5 --json 2>/dev/null | \
                jq -r '.output // empty' 2>/dev/null | grep -oE 'https?://[^[:space:]"<>]+' >> "$all_urls" || true
        fi
    done < "$http_urls"

    if command -v "$KATANA" &>/dev/null; then
        katana_status="completed"
        "$KATANA" -list "$http_urls" -silent -jc -d 3 -c 10 -p 10 2>/dev/null >> "$all_urls" || katana_status="failed"
    fi
    
    # Also crawl discovered directories from dirsearch
    local dirsearch_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt"
    if [ -f "$dirsearch_200" ] && command -v gospider &>/dev/null; then
        log_info "Crawling discovered directories..."
        "$GOSPIDER" -S "$dirsearch_200" --json 2>/dev/null | \
            jq -r '.output // empty' 2>/dev/null | grep -oE 'https?://[^[:space:]"<>]+' >> "$all_urls" || true
    fi
    
    # Deduplicate and filter
    # Keep only the target and its subdomains; archived sources can contain redirects off-scope.
    awk -F/ -v root="$target" 'NF >= 3 {h=$3; sub(/:.*/, "", h); if (h == root || substr(h, length(h)-length(root)) == "." root) print $0}' \
        "$all_urls" | sed 's/[),;]$//' | sort -u > "${all_urls}.tmp"
    mv "${all_urls}.tmp" "$all_urls"
    
    local total_urls=$(wc -l < "$all_urls" | tr -d ' ')
    log_info "Total URLs: $total_urls"
    
    # Extract JS files
    grep -Ei '\.(js|jsx|mjs)([?#].*)?$' "$all_urls" | sed 's/#.*$//' | sort -u > "$OUTPUT_DIR/09_crawling/js_urls.txt" 2>/dev/null || true
    local js_count=$(wc -l < "$OUTPUT_DIR/09_crawling/js_urls.txt" 2>/dev/null || echo 0)
    log_info "JS files: $js_count"
    
    # Download JS files
    mkdir -p "$OUTPUT_DIR/09_crawling/js_downloads"
    local downloaded=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        [ "$downloaded" -ge "$JS_DOWNLOAD_MAX" ] && break
        local filename=$(echo "$url" | md5sum | cut -d' ' -f1)
        if curl -fskL "$url" -o "$OUTPUT_DIR/09_crawling/js_downloads/${filename}.js" --max-time 10 2>/dev/null; then
            printf '%s\t%s.js\n' "$url" "$filename" >> "$OUTPUT_DIR/09_crawling/js_downloads/index.tsv"
            downloaded=$((downloaded + 1))
        else
            rm -f "$OUTPUT_DIR/09_crawling/js_downloads/${filename}.js"
        fi
    done < "$OUTPUT_DIR/09_crawling/js_urls.txt"
    
    log_info "JS files downloaded: $downloaded"
    update_statistics "total_urls" "$total_urls"
    update_statistics "total_js_files" "$js_count"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "crawling",
  "total_urls": $total_urls,
  "js_files": $js_count,
  "js_downloaded": $downloaded,
  "sources": {"gau": $gau_count, "gospider": "$gospider_status", "katana": "$katana_status"},
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Web crawling completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 10: SECRET SCANNING
###################################################################################################

module_secret_scanning() {
    local target="$1"
    log_section "MODULE 10: Secret Scanning"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/10_secret_scanning/$(make_iso_filename "$target" "secret_scanning" "results")"
    
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"
    [ ! -d "$js_dir" ] && mkdir -p "$js_dir"
    
    log_info "Scanning for secrets with trufflehog..."
    
    local secrets_file="$OUTPUT_DIR/10_secret_scanning/secrets.json"
    local secrets_jsonl="$OUTPUT_DIR/10_secret_scanning/secrets.jsonl"
    local scanner_status="unavailable"
    > "$secrets_jsonl"
    
    # Run trufflehog on JS files
    if command -v trufflehog &>/dev/null; then
        scanner_status="completed"
        $TRUFFLEHOG filesystem "$js_dir" \
            --json --no-verification > "$secrets_jsonl" 2>"$OUTPUT_DIR/10_secret_scanning/trufflehog.stderr" || scanner_status="completed_with_findings"
        jq -s '[.[] | select(type == "object")]' "$secrets_jsonl" > "$secrets_file" 2>/dev/null || echo '[]' > "$secrets_file"
    else
        log_warn "trufflehog not installed, skipping"
        echo '[]' > "$secrets_file"
    fi
    
    local total_secrets=0
    total_secrets=$(jq 'length' "$secrets_file" 2>/dev/null || echo 0)
    
    log_info "Secrets found: $total_secrets"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "secret_scanning",
  "secrets_found": $total_secrets,
  "scanner": "trufflehog",
  "scanner_status": "$scanner_status",
  "findings_file": "secrets.json",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Secret scanning completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 11: PARAMETER FUZZING
###################################################################################################

module_param_fuzzing() {
    local target="$1"
    log_section "MODULE 11: Parameter Fuzzing"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/11_param_fuzzing/$(make_iso_filename "$target" "param_fuzzing" "results")"
    
    local urls_file="$OUTPUT_DIR/09_crawling/all_urls.txt"
    [ ! -f "$urls_file" ] && { log_info "No URLs to fuzz"; return 0; }
    
    log_info "Extracting parameterized URLs..."
    
    # Find URLs with query parameters
    grep -F '?' "$urls_file" | grep -E '\?[^#]*=' | sort -u \
        > "$OUTPUT_DIR/11_param_fuzzing/param_urls.txt" 2>/dev/null || true
    
    local param_count=$(wc -l < "$OUTPUT_DIR/11_param_fuzzing/param_urls.txt" 2>/dev/null || echo 0)
    log_info "Parameterized URLs: $param_count"
    
    local candidates_file="$OUTPUT_DIR/11_param_fuzzing/fuzz_candidates.tsv"
    local results_json="$OUTPUT_DIR/11_param_fuzzing/lfi_results.json"
    local scanner_status="unavailable"
    python3 - "$OUTPUT_DIR/11_param_fuzzing/param_urls.txt" "$candidates_file" "$PARAM_FUZZ_MAX_URLS" << 'PYTHON_EOF'
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

source, output, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
written = 0
with open(output, "w") as dst:
    with open(source, errors="ignore") as src:
        for raw in src:
            url = raw.strip()
            if not url:
                continue
            parts = urlsplit(url)
            params = parse_qsl(parts.query, keep_blank_values=True)
            for index, (name, _) in enumerate(params):
                fuzzed = list(params)
                fuzzed[index] = (name, "FUZZ")
                fuzz_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(fuzzed), ""))
                dst.write(f"{name}\t{fuzz_url}\n")
                written += 1
                if written >= limit:
                    raise SystemExit
PYTHON_EOF

    # One parameter is changed per request, preserving the other parameter values.
    if command -v "$FFUF" &>/dev/null && [ -s "$WORDLIST_DIR/LFI-Jhaddix.txt" ] && [ -s "$candidates_file" ]; then
        log_info "Running ffuf LFI fuzzing..."
        scanner_status="completed"
        local ffuf_dir="$OUTPUT_DIR/11_param_fuzzing/ffuf"
        mkdir -p "$ffuf_dir"
        local result_files="$OUTPUT_DIR/11_param_fuzzing/result_files.txt"
        > "$result_files"
        while IFS=$'\t' read -r parameter fuzz_url; do
            [ -z "$fuzz_url" ] && continue
            local result_id=$(printf '%s' "$fuzz_url" | md5sum | cut -d' ' -f1)
            local result_file="$ffuf_dir/${result_id}.json"
            "$FFUF" -u "$fuzz_url" \
                -w "$WORDLIST_DIR/LFI-Jhaddix.txt" \
                -mr "root:|passwd:|etc/passwd" \
                -t 20 \
                -ac \
                -of json -o "$result_file" -s 2>/dev/null || true
            printf '%s\n' "$result_file" >> "$result_files"
        done < "$candidates_file"
        if [ -s "$result_files" ]; then
            python3 - "$result_files" "$results_json" << 'PYTHON_EOF'
import json
import sys
from pathlib import Path

result_files = [line.strip() for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
combined = []
for file_path in result_files:
    try:
        with open(file_path, "r", errors="ignore") as handle:
            payload = json.load(handle)
    except Exception:
        continue
    combined.extend(payload.get("results", []))

with open(sys.argv[2], "w") as out:
    json.dump(combined, out)
PYTHON_EOF
        else
            echo '[]' > "$results_json"
        fi
        local lfi_hits=$(jq 'length' "$results_json" 2>/dev/null || echo 0)
        log_info "LFI hits: $lfi_hits"
    else
        echo '[]' > "$results_json"
        log_warn "ffuf, LFI wordlist, or parameter candidates unavailable; active fuzzing skipped"
    fi
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "param_fuzzing",
  "parameterized_urls": $param_count,
  "fuzz_candidates": $(count_lines "$candidates_file"),
  "lfi_findings": $(jq 'length' "$results_json" 2>/dev/null || echo 0),
  "scanner_status": "$scanner_status",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Parameter fuzzing completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 12: NUCLEI VULNERABILITY SCANNING (Dual-Phase)
###################################################################################################

module_nuclei_scan() {
    local target="$1"
    log_section "MODULE 12: Nuclei Vulnerability Scanning"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/12_nuclei_scanning/$(make_iso_filename "$target" "nuclei_scan" "results")"
    
    # Use http_hosts.txt (now contains full URLs)
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ ! -f "$http_hosts_file" ] && { log_info "No HTTP hosts"; return 0; }
    
    local host_count=$(wc -l < "$http_hosts_file" | tr -d ' ')
    log_info "Scanning $host_count hosts with nuclei..."
    
    local nuclei_results="$OUTPUT_DIR/12_nuclei_scanning/nuclei_results.txt"
    > "$nuclei_results"
    
    # Nuclei scan - JSON output for dashboard, also show on CLI (Zero-Recon style)
    if command -v nuclei &>/dev/null; then
        # Check for templates directory
        local templates_dir="$PROJECT_ROOT/lists/nuclei-templates"
        [ ! -d "$templates_dir" ] && templates_dir="$HOME/nuclei-templates"
        [ ! -d "$templates_dir" ] && templates_dir="$HOME/recon/nuclei-templates"
        
        log_info "Running nuclei with templates from: $templates_dir"
        
        # Run nuclei - JSON lines output for easy parsing
        $NUCLEI -l "$http_hosts_file" \
            -tags exposure,panel,default-login,tech,misconfig,disclosure,ssl,tls \
            -severity low,medium,high,critical,unknown \
            -o "$nuclei_results" \
            -j \
            -rl 100 2>/dev/null || true
        
        # If we have templates, also run automatic web scan
        if [ -d "$templates_dir" ]; then
            log_info "Running intelligent Nuclei scan with automatic technology detection (-as)..."
            $NUCLEI -l "$http_hosts_file" \
                -t "$templates_dir" \
                -as \
                -severity low,medium,high,critical \
                -o "$OUTPUT_DIR/12_nuclei_scanning/full_results.txt" \
                -j \
                -rl 150 2>/dev/null || true
        fi
    else
        log_warn "nuclei not installed, skipping"
    fi
    
    # Count results
    local total_vulns=0
    [ -f "$nuclei_results" ] && total_vulns=$(wc -l < "$nuclei_results" 2>/dev/null | tr -d ' ')
    [ -f "$OUTPUT_DIR/12_nuclei_scanning/full_results.txt" ] && \
        total_vulns=$((total_vulns + $(wc -l < "$OUTPUT_DIR/12_nuclei_scanning/full_results.txt" 2>/dev/null | tr -d ' ')))
    
    log_info "Total vulnerabilities found: $total_vulns"
    
    # Show sample results on CLI
    if [ -f "$nuclei_results" ] && [ "$total_vulns" -gt 0 ]; then
        log_info "Sample vulnerabilities:"
        head -5 "$nuclei_results" | jq -r '"[\(.info.severity)] \(.info.name) - \(.host)"' 2>/dev/null || head -5 "$nuclei_results"
    fi
    
    update_statistics "total_vulnerabilities" "$total_vulns"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "nuclei_scan",
  "total_vulnerabilities": $total_vulns,
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Nuclei scanning completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 13: XSS-SPECIFIC TESTING
###################################################################################################

module_xss_testing() {
    local target="$1"
    log_section "MODULE 13: XSS Testing"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/13_xss_testing/$(make_iso_filename "$target" "xss_testing" "results")"
    
    local urls_file="$OUTPUT_DIR/09_crawling/all_urls.txt"
    [ ! -f "$urls_file" ] && { log_info "No URLs to test"; return 0; }
    
    log_info "Extracting XSS candidates with gf patterns..."
    
    local xss_candidates="$OUTPUT_DIR/13_xss_testing/xss_candidates.txt"
    > "$xss_candidates"
    
    if command -v gf &>/dev/null; then
        $GF xss "$urls_file" > "$xss_candidates" 2>/dev/null || true
    else
        # Fallback: grep for common XSS patterns
        grep -iE '(\?|&)(id|page|name|search|q|lang|input|text|value|src|url)=.*' "$urls_file" > "$xss_candidates" 2>/dev/null || true
    fi
    
    local candidate_count=$(wc -l < "$xss_candidates" 2>/dev/null || echo 0)
    log_info "XSS candidates: $candidate_count"
    
    # Run dalfox for XSS testing
    local xss_results="$OUTPUT_DIR/13_xss_testing/xss_results.txt"
    > "$xss_results"
    
    if command -v dalfox &>/dev/null && [ -s "$xss_candidates" ]; then
        log_info "Running dalfox XSS testing..."
        $DALFOX file "$xss_candidates" -o "$xss_results" -t 10 2>/dev/null || true
    else
        log_warn "dalfox not available or no candidates"
    fi
    
    local vulns_found=0
    [ -f "$xss_results" ] && vulns_found=$(wc -l < "$xss_results" 2>/dev/null || echo 0)
    
    log_info "XSS vulnerabilities found: $vulns_found"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "xss_testing",
  "candidates": $candidate_count,
  "vulnerabilities": $vulns_found,
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "XSS testing completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 15: SQL INJECTION TESTING (sqlmap — WAF-aware safe detection)
###################################################################################################

SQLI_MAX_URLS="${SQLI_MAX_URLS:-30}"

# Map WAF vendors to sqlmap tamper scripts that work best against them
_sqli_tamper_for_waf() {
    local waf="$1"
    case "$(echo "$waf" | tr '[:upper:]' '[:lower:]')" in
        cloudflare)    echo "between,randomcase,space2comment" ;;
        akamai)        echo "space2hash,between,randomcase" ;;
        imperva|incapsula) echo "space2mssqlhash,randomcase,charencode" ;;
        f5*|big-ip)    echo "space2mssqlblank,percentage,randomcase" ;;
        aws*|awswaf)   echo "space2comment,between,charencode" ;;
        barracuda)     echo "space2plus,randomcase,between" ;;
        fortinet|fortiweb) echo "space2morehash,randomcase,charencode" ;;
        modsecurity)   echo "space2comment,charencode,between" ;;
        sucuri)        echo "between,randomcase,space2comment" ;;
        envoy)         echo "between,randomcase" ;;
        *)             echo "between,randomcase,space2comment" ;;
    esac
}

# Run a single sqlmap pass; returns 0 if injection found
_sqli_run_sqlmap() {
    local url="$1" run_dir="$2" pass_name="$3"
    shift 3
    local extra_args=("$@")

    sqlmap -u "$url" \
        --batch \
        --level=1 \
        --risk=1 \
        --timeout=10 \
        --retries=1 \
        --threads=1 \
        --output-dir="$run_dir" \
        --flush-session \
        --drop-set-cookie \
        --random-agent \
        --fresh-queries \
        "${extra_args[@]}" \
        2>/dev/null > "$run_dir/${pass_name}.log"

    # Check for confirmed injection — sqlmap emits "the following injection point"
    # on a real find. NEVER match "injectable" alone: the negative output
    # "do not appear to be injectable" contains that word and causes false positives.
    local log="$run_dir/${pass_name}.log"
    if grep -q "the following injection point" "$log" 2>/dev/null \
       && ! grep -q "do not appear to be injectable" "$log" 2>/dev/null; then
        if ! grep -qi "WAF/IPS.*identified\|blocked by\|403 Forbidden.*protection" "$log" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Detect if a sqlmap log shows WAF interference
_sqli_waf_blocked() {
    local log_file="$1"
    [ ! -f "$log_file" ] && return 1
    grep -qiE "WAF/IPS|heuristic.*detected|403 Forbidden|406 Not Acceptable|429 Too Many|responded with 403|blocked|Access Denied" "$log_file" 2>/dev/null
}

module_sqli_testing() {
    local target="$1"
    log_section "MODULE 15: SQL Injection Testing (WAF-Aware)"

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/15_sqli_testing/$(make_iso_filename "$target" "sqli_testing" "results")"
    local results_jsonl="$OUTPUT_DIR/15_sqli_testing/sqli_results.jsonl"
    > "$results_jsonl"

    if ! command -v sqlmap &>/dev/null; then
        log_warn "sqlmap not installed, skipping SQL injection testing"
        cat > "$output_file" << EOF
{
  "module": "sqli_testing",
  "candidates": 0,
  "findings": 0,
  "waf_blocked": 0,
  "scanner_status": "unavailable",
  "duration_seconds": 0
}
EOF
        echo "$output_file"
        return 0
    fi

    # Gather SQLi candidate URLs from crawled URLs and param fuzzing
    local sqli_candidates="$OUTPUT_DIR/15_sqli_testing/sqli_candidates.txt"
    > "$sqli_candidates"

    local urls_file="$OUTPUT_DIR/09_crawling/all_urls.txt"

    if [ -f "$urls_file" ]; then
        if command -v gf &>/dev/null; then
            $GF sqli "$urls_file" >> "$sqli_candidates" 2>/dev/null || true
        fi
        grep -iE '(\?|&)(id|user|item|cat|order|sort|page|dir|file|report|type|name|query|field|row|table|from|sel|results|search|lang|keyword|year|view|val|token|num|key|pid|uid|gid)=' \
            "$urls_file" >> "$sqli_candidates" 2>/dev/null || true
    fi

    local dir_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt"
    [ -f "$dir_200" ] && grep -F '?' "$dir_200" >> "$sqli_candidates" 2>/dev/null || true

    sort -u "$sqli_candidates" -o "$sqli_candidates"
    local total_candidates=$(wc -l < "$sqli_candidates" 2>/dev/null | tr -d ' ')
    log_info "SQLi candidates found: $total_candidates"

    if [ "$total_candidates" -eq 0 ]; then
        log_info "No parameterized URLs to test for SQL injection"
        cat > "$output_file" << EOF
{
  "module": "sqli_testing",
  "candidates": 0,
  "findings": 0,
  "waf_blocked": 0,
  "scanner_status": "no_candidates",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
        echo "$output_file"
        return 0
    fi

    local capped_file="$OUTPUT_DIR/15_sqli_testing/sqli_capped.txt"
    head -n "$SQLI_MAX_URLS" "$sqli_candidates" > "$capped_file"
    local test_count=$(wc -l < "$capped_file" | tr -d ' ')
    log_info "Testing $test_count URLs (capped at $SQLI_MAX_URLS)"

    # Build a host→waf lookup from the manifest
    local waf_lookup_file="$OUTPUT_DIR/15_sqli_testing/waf_lookup.tsv"
    jq -r '.hosts | to_entries[] | select(.value.waf_vendor != null and .value.waf_vendor != "none") | "\(.key)\t\(.value.waf_vendor)"' \
        "$MANIFEST_FILE" > "$waf_lookup_file" 2>/dev/null || true

    local sqli_dir="$OUTPUT_DIR/15_sqli_testing/sqlmap_output"
    mkdir -p "$sqli_dir"
    local findings=0
    local waf_blocked_count=0

    while IFS= read -r url; do
        [ -z "$url" ] && continue

        local host
        host=$(printf '%s' "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        local url_hash
        url_hash=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
        local run_dir="$sqli_dir/$url_hash"
        mkdir -p "$run_dir"

        # Look up WAF vendor for this host
        local host_waf=""
        host_waf=$(grep -F "$host" "$waf_lookup_file" 2>/dev/null | head -1 | cut -f2)

        if [ -n "$host_waf" ]; then
            log_info "  sqlmap [WAF: $host_waf]: $url"
        else
            log_info "  sqlmap [no WAF]: $url"
        fi

        local found="false"
        local pass_log=""
        local pass_used=""

        # ── Pass 1: clean baseline (no tamper, fresh session, drop cookies) ──
        if _sqli_run_sqlmap "$url" "$run_dir" "pass1_baseline" \
            --technique=BEU; then
            found="true"
            pass_log="$run_dir/pass1_baseline.log"
            pass_used="baseline"
        fi

        # ── Pass 2: if WAF blocked pass 1, retry with WAF-tuned tamper scripts ──
        if [ "$found" = "false" ] && _sqli_waf_blocked "$run_dir/pass1_baseline.log"; then
            log_info "    WAF block detected, retrying with tamper scripts..."
            local tamper_chain
            tamper_chain=$(_sqli_tamper_for_waf "$host_waf")

            if _sqli_run_sqlmap "$url" "$run_dir" "pass2_tamper" \
                --technique=BEU \
                --tamper="$tamper_chain" \
                --delay=1; then
                found="true"
                pass_log="$run_dir/pass2_tamper.log"
                pass_used="waf_tamper"
            fi
        fi

        # ── Pass 3: if still blocked, try chunked encoding + different technique ──
        if [ "$found" = "false" ] && _sqli_waf_blocked "$run_dir/pass2_tamper.log" 2>/dev/null; then
            log_info "    Still blocked, trying chunked + error-based only..."

            if _sqli_run_sqlmap "$url" "$run_dir" "pass3_chunked" \
                --technique=E \
                --tamper="chardoubleencode,between" \
                --delay=2 \
                --chunked; then
                found="true"
                pass_log="$run_dir/pass3_chunked.log"
                pass_used="chunked_bypass"
            fi
        fi

        # ── Record result ──
        if [ "$found" = "true" ] && [ -f "$pass_log" ]; then
            local sqli_type sqli_param confidence
            sqli_type=$(grep -oP "Type: \K[^,]+" "$pass_log" 2>/dev/null | head -1)
            [ -z "$sqli_type" ] && sqli_type="unknown"
            sqli_param=$(grep -oP "Parameter: \K\S+" "$pass_log" 2>/dev/null | head -1)
            [ -z "$sqli_param" ] && sqli_param="unknown"

            # Confidence based on technique and WAF context
            confidence="high"
            echo "$sqli_type" | grep -qi "union" && confidence="medium"
            echo "$sqli_type" | grep -qi "time\|blind" && confidence="medium"
            # Finding through WAF bypass = lower confidence
            [ "$pass_used" = "waf_tamper" ] && [ "$confidence" = "high" ] && confidence="medium"
            [ "$pass_used" = "chunked_bypass" ] && confidence="low"

            local finding_json
            finding_json=$(jq -nc \
                --arg url "$url" \
                --arg host "$host" \
                --arg sqli_type "$sqli_type" \
                --arg param "$sqli_param" \
                --arg confidence "$confidence" \
                --arg waf "$host_waf" \
                --arg pass "$pass_used" \
                '{url:$url,host:$host,type:$sqli_type,parameter:$param,confidence:$confidence,waf_vendor:$waf,detection_pass:$pass}')
            printf '%s\n' "$finding_json" >> "$results_jsonl"
            ((findings++))
            log_warn "  VULNERABLE: $host param=$sqli_param type=$sqli_type confidence=$confidence (pass=$pass_used)"

        elif _sqli_waf_blocked "$run_dir/pass1_baseline.log" 2>/dev/null; then
            ((waf_blocked_count++))
            log_info "    WAF-blocked after all passes: $host"
        fi

    done < "$capped_file"

    log_info "SQL injection testing completed: $findings findings, $waf_blocked_count WAF-blocked, from $test_count URLs"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "sqli_testing",
  "candidates": $total_candidates,
  "tested": $test_count,
  "findings": $findings,
  "waf_blocked": $waf_blocked_count,
  "scanner_status": "completed",
  "duration_seconds": $((end_time - start_time))
}
EOF

    echo "$output_file"
}

###################################################################################################
# MODULE 16: API SECURITY TESTING (Autoswagger + RESTler, deduplicated)
#
# Two tools, two distinct purposes, one merged-but-deduplicated view:
#   - Autoswagger -> authentication / authorization exposure (broken auth, BOLA, data leak)
#   - RESTler     -> robustness / input handling (500s, input validation, stateful bugs)
# Findings are tagged by tool; identical endpoint+issue pairs collapse into a single row.
###################################################################################################

APISEC_MAX_HOSTS="${APISEC_MAX_HOSTS:-10}"
APISEC_RESTLER_TIME_BUDGET="${APISEC_RESTLER_TIME_BUDGET:-5}"   # minutes of fuzzing per spec (fuzz mode only)
AUTOSWAGGER_BIN="${AUTOSWAGGER_BIN:-autoswagger}"
AUTOSWAGGER_EXTRA_ARGS="${AUTOSWAGGER_EXTRA_ARGS:-}"
RESTLER_BIN="${RESTLER_BIN:-restler}"
APISEC_AUTH_TOKEN_CMD="${APISEC_AUTH_TOKEN_CMD:-}"
APISEC_AUTH_REFRESH_SEC="${APISEC_AUTH_REFRESH_SEC:-300}"

# Well-known OpenAPI / Swagger document locations to probe on each API host.
APISEC_SPEC_PATHS=(
    "/swagger.json" "/openapi.json" "/v2/api-docs" "/v3/api-docs"
    "/swagger/v1/swagger.json" "/api-docs" "/api/swagger.json"
    "/api/v1/swagger.json" "/api/openapi.json" "/openapi/v3.json"
    "/.well-known/openapi.json" "/api/docs/swagger.json"
    "/swagger-resources" "/api-docs/swagger.json" "/docs/swagger.json"
)

# Resolve the base URL (scheme + host) for an API host, preferring the scheme
# recorded during HTTP discovery; default to https.
_apisec_base_url() {
    local host="$1"
    local http_file="$OUTPUT_DIR/04_http_discovery/http_confirmed.json"
    local url=""
    if [ -f "$http_file" ]; then
        url=$(grep -F "\"$host\"" "$http_file" 2>/dev/null | head -1 \
            | jq -r '.url // empty' 2>/dev/null)
    fi
    if [ -n "$url" ]; then
        printf '%s' "${url%/}"
    else
        printf 'https://%s' "$host"
    fi
}

# Probe well-known OpenAPI locations. On the first spec-like response, save it
# and echo the spec URL. Return 1 if none found.
_apisec_discover_spec() {
    local base="$1" host_spec_dir="$2"
    local p url body
    for p in "${APISEC_SPEC_PATHS[@]}"; do
        url="${base%/}${p}"
        body=$(curl -sk --max-time 8 -H 'Accept: application/json' "$url" 2>/dev/null)
        [ -z "$body" ] && continue
        if printf '%s' "$body" | grep -qiE '"(swagger|openapi)"[[:space:]]*:' \
           && printf '%s' "$body" | grep -qi '"paths"'; then
            printf '%s' "$body" > "$host_spec_dir/spec.json"
            printf '%s' "$url"
            return 0
        fi
    done
    return 1
}

# Autoswagger: authentication / authorization surface testing. Auto-discovers
# specs from the base URL; we also hand it the spec we found when available.
_apisec_run_autoswagger() {
    local base_url="$1" spec_url="$2" out_json="$3" host="$4"
    log_info "  [autoswagger] $base_url"
    local -a args=("$base_url")
    [ -n "$spec_url" ] && args+=("$spec_url")
    args+=(-risk -json)
    [ -n "$AUTOSWAGGER_EXTRA_ARGS" ] && args+=($AUTOSWAGGER_EXTRA_ARGS)
    "$AUTOSWAGGER_BIN" "${args[@]}" \
        > "$out_json" 2>"${out_json%.json}.log" \
        || log_warn "  [autoswagger] non-zero exit for $host (see ${out_json%.json}.log)"
}

# RESTler: robustness / input-handling fuzzing. Standard compile -> fuzz-lean
# flow against the discovered spec, bounded by a time budget.
_apisec_run_restler() {
    local spec_file="$1" out_dir="$2" host="$3"
    [ ! -f "$spec_file" ] && { log_info "  [restler] no spec for $host, skipping"; return 0; }
    log_info "  [restler] fuzzing $host (fuzz-lean)"

    mkdir -p "$out_dir"

    "$RESTLER_BIN" --workingDirPath "$out_dir" compile --api_spec "$spec_file" \
        > "$out_dir/compile.log" 2>&1 || {
        log_warn "  [restler] compile failed for $host (see compile.log)"; return 0; }

    local grammar="$out_dir/Compile/grammar.py"
    local dict="$out_dir/Compile/dict.json"
    [ ! -f "$grammar" ] && { log_warn "  [restler] no grammar produced for $host"; return 0; }

    local -a fuzz_args=(--grammar_file "$grammar")
    [ -f "$dict" ] && fuzz_args+=(--dictionary_file "$dict")
    fuzz_args+=(--enable_checkers namespacerule)

    if [ -n "$APISEC_AUTH_TOKEN_CMD" ]; then
        fuzz_args+=(--token_refresh_command "$APISEC_AUTH_TOKEN_CMD"
                    --token_refresh_interval "$APISEC_AUTH_REFRESH_SEC")
    fi

    "$RESTLER_BIN" --workingDirPath "$out_dir" fuzz-lean \
        "${fuzz_args[@]}" \
        > "$out_dir/fuzz.log" 2>&1 \
        || log_warn "  [restler] fuzz non-zero exit for $host (see fuzz.log)"
}

# Parse both tools' native output, normalize into a shared taxonomy, template
# paths, and deduplicate on (method, path, issue_class). Writes api_findings.jsonl.
_apisec_normalize_and_dedup() {
    local autoswagger_dir="$1" restler_dir="$2" findings_file="$3"
    python3 - "$autoswagger_dir" "$restler_dir" "$findings_file" << 'PYEOF'
import json, os, re, sys, glob

autoswagger_dir, restler_dir, out_file = sys.argv[1], sys.argv[2], sys.argv[3]

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Category -> which tool "owns" it when the same endpoint+issue is seen by both.
CATEGORY_OWNER = {
    "authn": "autoswagger", "authz": "autoswagger", "exposure": "autoswagger",
    "robustness": "restler", "input_validation": "restler", "state": "restler",
}

_ID_SEG = re.compile(r'^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$')

def template_path(path):
    """Collapse concrete identifiers so /users/123 and /users/456 dedupe.
    Strips scheme+host so autoswagger's full URLs match restler's relative paths."""
    path = path or ''
    path = re.sub(r'^https?://[^/]+', '', path)
    path = re.sub(r'\?.*$', '', path)
    parts = []
    for seg in path.split('/'):
        parts.append('{id}' if seg and _ID_SEG.match(seg) else seg)
    tp = '/'.join(parts)
    return tp if tp.startswith('/') or tp == '' else '/' + tp

def host_from_url(url):
    m = re.match(r'https?://([^/]+)', url or '')
    return m.group(1) if m else ''

# ---- Autoswagger: authentication / authorization findings ----------------
AS_ISSUE = {
    "unauthenticated": ("broken_authentication", "authn", "high"),
    "no_auth":         ("broken_authentication", "authn", "high"),
    "broken_auth":     ("broken_authentication", "authn", "high"),
    "bola":            ("broken_object_authorization", "authz", "high"),
    "idor":            ("broken_object_authorization", "authz", "high"),
    "authorization":   ("broken_object_authorization", "authz", "high"),
    "data_exposure":   ("sensitive_data_exposure", "exposure", "medium"),
    "sensitive":       ("sensitive_data_exposure", "exposure", "medium"),
}

def classify_autoswagger(raw_type, accessible):
    key = (raw_type or "").lower()
    for k, v in AS_ISSUE.items():
        if k in key:
            return v
    # Default: an endpoint reachable without auth is a broken-auth finding.
    if accessible:
        return ("broken_authentication", "authn", "high")
    return ("api_exposure", "exposure", "low")

def parse_autoswagger(d):
    out = []
    for jf in glob.glob(os.path.join(d, "*.json")):
        try:
            with open(jf) as f:
                data = json.load(f)
        except Exception:
            continue
        items = data if isinstance(data, list) else data.get("findings", data.get("results", []))
        if isinstance(items, dict):
            items = [items]
        for it in items or []:
            if not isinstance(it, dict):
                continue
            method = (it.get("method") or it.get("http_method") or "GET").upper()
            url = it.get("url") or it.get("endpoint") or it.get("path") or ""
            path = it.get("path") or url
            status = it.get("status") or it.get("status_code") or it.get("response_code")
            accessible = bool(it.get("accessible", it.get("unauthenticated", status in (200, 201, 202, 204))))
            issue_class, category, base_sev = classify_autoswagger(
                it.get("type") or it.get("issue") or it.get("finding"), accessible)
            sev = (it.get("severity") or base_sev).lower()
            out.append({
                "method": method,
                "path": template_path(path),
                "host": host_from_url(url) or it.get("host", ""),
                "issue_class": issue_class,
                "category": category,
                "severity": sev if sev in SEV_RANK else base_sev,
                "tool": "autoswagger",
                "evidence": (it.get("evidence") or it.get("detail")
                             or f"{method} reachable, status {status}")[:300],
                "status_code": status,
                "remediation": it.get("remediation")
                    or "Enforce authentication and per-object authorization on this endpoint.",
            })
    return out

# ---- RESTler: robustness / input-handling findings -----------------------
RS_ISSUE = {
    "500":              ("server_error", "robustness", "high"),
    "main_driver_500":  ("server_error", "robustness", "high"),
    "internalservererror": ("server_error", "robustness", "high"),
    "payloadbody":      ("input_validation", "input_validation", "medium"),
    "invaliddynamicobject": ("input_validation", "input_validation", "medium"),
    "usedafterfree":    ("stateful_resource_bug", "state", "medium"),
    "namespacerule":    ("broken_object_authorization", "authz", "high"),
    "leakagerule":      ("resource_leak", "state", "medium"),
}

def classify_restler(bug_type):
    key = re.sub(r'[^a-z0-9]', '', (bug_type or "").lower())
    for k, v in RS_ISSUE.items():
        if k.replace('_', '') in key:
            return v
    return ("robustness_bug", "robustness", "medium")

def parse_restler(d):
    out = []
    found_json = False

    # Primary: parse stable JSON from ResponseBuckets (runSummary.json + errorBuckets.json)
    for summary_f in glob.glob(os.path.join(d, "**", "runSummary.json"), recursive=True):
        try:
            with open(summary_f) as f:
                summary = json.load(f)
        except Exception:
            continue
        found_json = True
        bucket_dir = os.path.dirname(summary_f)
        err_file = os.path.join(bucket_dir, "errorBuckets.json")
        err_data = {}
        if os.path.exists(err_file):
            try:
                with open(err_file) as f:
                    err_data = json.load(f)
            except Exception:
                pass
        for bucket_id, info in (summary if isinstance(summary, dict) else {}).items():
            bug_type = err_data.get(bucket_id, {}).get("type", bucket_id)
            issue_class, category, sev = classify_restler(bug_type)
            method = info.get("method", "GET").upper() if isinstance(info, dict) else "GET"
            path = info.get("endpoint", "/unknown") if isinstance(info, dict) else "/unknown"
            out.append({
                "method": method,
                "path": template_path(path),
                "host": "",
                "issue_class": issue_class,
                "category": category,
                "severity": sev,
                "tool": "restler",
                "evidence": f"RESTler JSON bucket '{bug_type}' on {method} {path}"[:300],
                "status_code": 500 if issue_class == "server_error" else None,
                "remediation": "Add server-side input validation and handle malformed/edge-case payloads.",
            })

    # Also parse per-bug files for reproducibility info
    for bug_file in glob.glob(os.path.join(d, "**", "bug_buckets", "*.txt"), recursive=True):
        if os.path.basename(bug_file) == "bug_buckets.txt":
            continue
        try:
            with open(bug_file, errors="ignore") as f:
                text = f.read()
        except Exception:
            continue
        bug_type = os.path.basename(bug_file).rsplit("_", 1)[0]
        for m in re.finditer(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', text, re.M):
            issue_class, category, sev = classify_restler(bug_type)
            key = (m.group(1).upper(), template_path(m.group(2)), issue_class)
            if not any((r["method"], r["path"], r["issue_class"]) == key for r in out):
                out.append({
                    "method": m.group(1).upper(),
                    "path": template_path(m.group(2)),
                    "host": "",
                    "issue_class": issue_class,
                    "category": category,
                    "severity": sev,
                    "tool": "restler",
                    "evidence": f"RESTler per-bug file '{bug_type}' on {m.group(1)} {m.group(2)}"[:300],
                    "status_code": 500 if issue_class == "server_error" else None,
                    "remediation": "Add server-side input validation and handle malformed/edge-case payloads.",
                })

    # Fallback: text-parse bug_buckets.txt only if no JSON was found
    if not found_json:
        for bb in glob.glob(os.path.join(d, "**", "bug_buckets.txt"), recursive=True):
            try:
                with open(bb, errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            cur_type = None
            for line in text.splitlines():
                s = line.strip()
                if not s:
                    continue
                if not s.startswith(("Received", "PUT", "POST", "GET", "DELETE",
                                     "PATCH", "HEAD", "OPTIONS")) and s.endswith(":"):
                    cur_type = s.rstrip(":")
                    continue
                m2 = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', s)
                if m2 and cur_type:
                    issue_class, category, sev = classify_restler(cur_type)
                    out.append({
                        "method": m2.group(1).upper(),
                        "path": template_path(m2.group(2)),
                        "host": "",
                        "issue_class": issue_class,
                        "category": category,
                        "severity": sev,
                        "tool": "restler",
                        "evidence": f"RESTler bucket '{cur_type}' on {m2.group(1)} {m2.group(2)}"[:300],
                        "status_code": 500 if issue_class == "server_error" else None,
                        "remediation": "Add server-side input validation and handle malformed/edge-case payloads.",
                    })
    return out

# ---- Merge + dedup on (method, path, issue_class) -------------------------
def merge(records):
    merged = {}
    for r in records:
        key = (r["method"], r["path"], r["issue_class"])
        if key not in merged:
            r["tools"] = [r["tool"]]
            merged[key] = r
            continue
        m = merged[key]
        if r["tool"] not in m["tools"]:
            m["tools"].append(r["tool"])
        # keep the highest severity
        if SEV_RANK.get(r["severity"], 0) > SEV_RANK.get(m["severity"], 0):
            m["severity"] = r["severity"]
        # primary tool = the one that owns this category
        owner = CATEGORY_OWNER.get(m["category"], m["tool"])
        if owner in m["tools"]:
            m["tool"] = owner
        # keep host if we learned one
        if not m.get("host") and r.get("host"):
            m["host"] = r["host"]
        # append distinct evidence
        if r["evidence"] and r["evidence"] not in m["evidence"]:
            m["evidence"] = (m["evidence"] + " | " + r["evidence"])[:500]
    return list(merged.values())

all_findings = parse_autoswagger(autoswagger_dir) + parse_restler(restler_dir)
final = merge(all_findings)
final.sort(key=lambda x: (-SEV_RANK.get(x["severity"], 0), x["path"]))

with open(out_file, "w") as f:
    for r in final:
        r["endpoint"] = f'{r["method"]} {r["path"]}'
        f.write(json.dumps(r) + "\n")

print(f"{len(final)} deduplicated API findings written")
PYEOF
}

module_api_security() {
    local target="$1"
    log_section "MODULE 16: API Security Testing (Autoswagger + RESTler)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/16_api_security"
    local autoswagger_dir="$base_dir/autoswagger"
    local restler_dir="$base_dir/restler"
    local spec_dir="$base_dir/specs"
    local findings_file="$base_dir/api_findings.jsonl"
    local output_file="$base_dir/$(make_iso_filename "$target" "api_security" "results")"
    mkdir -p "$autoswagger_dir" "$restler_dir" "$spec_dir"
    > "$findings_file"

    # Pull API hosts tagged by module 6 detection.
    local api_hosts_file="$base_dir/api_hosts.txt"
    jq -r '.hosts | to_entries[] | select(.value.is_api == true) | .key' \
        "$MANIFEST_FILE" 2>/dev/null | sort -u > "$api_hosts_file"
    local api_host_count=$(wc -l < "$api_hosts_file" 2>/dev/null | tr -d ' ')
    log_info "API hosts tagged for security testing: $api_host_count"

    if [ "$api_host_count" -eq 0 ]; then
        cat > "$output_file" << EOF
{
  "module": "api_security",
  "api_hosts": 0,
  "findings": 0,
  "autoswagger_findings": 0,
  "restler_findings": 0,
  "scanner_status": "no_targets",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
        echo "$output_file"
        return 0
    fi

    local have_autoswagger=false have_restler=false
    command -v "$AUTOSWAGGER_BIN" &>/dev/null && have_autoswagger=true
    command -v "$RESTLER_BIN" &>/dev/null && have_restler=true

    if [ "$have_autoswagger" = false ] && [ "$have_restler" = false ]; then
        log_warn "Neither autoswagger nor restler installed; skipping API security testing"
        cat > "$output_file" << EOF
{
  "module": "api_security",
  "api_hosts": $api_host_count,
  "findings": 0,
  "autoswagger_findings": 0,
  "restler_findings": 0,
  "scanner_status": "unavailable",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
        echo "$output_file"
        return 0
    fi

    log_info "Tools available -> autoswagger: $have_autoswagger, restler: $have_restler"

    local tested=0 specs_found=0
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        [ "$tested" -ge "$APISEC_MAX_HOSTS" ] && { log_info "Reached APISEC_MAX_HOSTS cap ($APISEC_MAX_HOSTS)"; break; }

        local host_hash
        host_hash=$(printf '%s' "$host" | md5sum | cut -d' ' -f1)
        local base_url
        base_url=$(_apisec_base_url "$host")
        local host_spec_dir="$spec_dir/$host_hash"
        mkdir -p "$host_spec_dir"

        local spec_url=""
        spec_url=$(_apisec_discover_spec "$base_url" "$host_spec_dir") || true
        if [ -n "$spec_url" ]; then
            log_info "  [$host] OpenAPI spec: $spec_url"
            ((specs_found++))
        else
            log_info "  [$host] no OpenAPI spec discovered"
        fi

        # Autoswagger -> auth/authz surface (can run without a discovered spec).
        if [ "$have_autoswagger" = true ]; then
            _apisec_run_autoswagger "$base_url" "$spec_url" "$autoswagger_dir/$host_hash.json" "$host"
        fi

        # RESTler -> robustness fuzzing (requires a spec to build a grammar).
        if [ "$have_restler" = true ]; then
            if [ -f "$host_spec_dir/spec.json" ]; then
                _apisec_run_restler "$host_spec_dir/spec.json" "$restler_dir/$host_hash" "$host"
            else
                log_info "  [$host] skipping RESTler (no spec to fuzz)"
            fi
        fi

        ((tested++))
    done < "$api_hosts_file"

    # Normalize + dedup across both tools.
    _apisec_normalize_and_dedup "$autoswagger_dir" "$restler_dir" "$findings_file"

    local total_findings as_count rs_count both_count
    total_findings=$(wc -l < "$findings_file" 2>/dev/null | tr -d ' ')
    as_count=$(grep -c '"tool": "autoswagger"' "$findings_file" 2>/dev/null || echo 0)
    rs_count=$(grep -c '"tool": "restler"' "$findings_file" 2>/dev/null || echo 0)
    both_count=$(grep -c '"autoswagger".*"restler"\|"restler".*"autoswagger"' "$findings_file" 2>/dev/null || echo 0)
    log_info "API security testing complete: $total_findings findings (autoswagger:$as_count restler:$rs_count multi-tool:$both_count) across $tested hosts, $specs_found specs"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "api_security",
  "api_hosts": $api_host_count,
  "tested": $tested,
  "specs_found": $specs_found,
  "findings": ${total_findings:-0},
  "autoswagger_findings": ${as_count:-0},
  "restler_findings": ${rs_count:-0},
  "multi_tool_findings": ${both_count:-0},
  "scanner_status": "completed",
  "duration_seconds": $((end_time - start_time))
}
EOF

    echo "$output_file"
}

###################################################################################################
# MODULE 14: FULL PORT SCANNING
###################################################################################################

module_full_port_scan() {
    local target="$1"
    log_section "MODULE 14: Full Port Scanning (All Services)"

    local resolved_file="$OUTPUT_DIR/04_http_discovery/resolved_unique.txt"
    [ ! -f "$resolved_file" ] && { log_error "No unique resolved hosts found"; return 1; }

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/14_port_scan/$(make_iso_filename "$target" "full_port_scan" "results")"
    command -v "$NAABU" &>/dev/null || { log_error "naabu is required for full port scanning"; return 1; }

    log_info "Starting comprehensive port scan on unique domains (excluding full scans on CDN IPs)..."
    local unique_count=$(wc -l < "$resolved_file" | tr -d ' ')
    log_info "Targets: $unique_count unique domains"

    # Determine port range based on mode
    local -a port_args
    case "$PORT_SCAN_MODE" in
        full)
            port_args=(-p -)
            log_info "Scanning all 65,535 ports (this will take time...)"
            ;;
        fast)
            port_args=(-top-ports 1000)
            log_info "Scanning top 1000 ports"
            ;;
        *)
            port_args=(-top-ports 100)
            log_info "Scanning top 100 ports"
            ;;
    esac

    # Cap threads on macOS to avoid pthread_create crashes
    local naabu_threads="$NAABU_THREADS"
    local naabu_rate="$NAABU_RATE"
    if [ "$(uname -s)" = "Darwin" ] && [ "$naabu_threads" -gt 25 ] 2>/dev/null; then
        log_warn "macOS detected: capping naabu threads to 25 (was $naabu_threads) to avoid thread limit crashes"
        naabu_threads=25
    fi

    _run_naabu() {
        local _threads="$1" _rate="$2"
        shift 2
        local -a _port_args=("$@")
        local stderr_file="$OUTPUT_DIR/14_port_scan/naabu.stderr"
        log_info "naabu: threads=$_threads rate=$_rate ports=${_port_args[*]}"
        "$NAABU" -l "$resolved_file" "${_port_args[@]}" \
            -rate "$_rate" -c "$_threads" -s c -exclude-cdn -json \
            -o "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" \
            -silent 2> >(head -c 200000 > "$stderr_file")
    }

    # Primary run
    log_info "Running naabu port scan..."
    _run_naabu "$naabu_threads" "$naabu_rate" "${port_args[@]}"

    # Crash detection + retry with reduced settings
    local naabu_crashed=false
    if [ ! -s "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ]; then
        if grep -qE 'pthread_create failed|SIGABRT|runtime/cgo' "$OUTPUT_DIR/14_port_scan/naabu.stderr" 2>/dev/null; then
            naabu_crashed=true
            log_error "naabu crashed (thread limit exceeded). Retrying with reduced settings..."
            local retry_threads=$(( naabu_threads / 2 ))
            [ "$retry_threads" -lt 5 ] && retry_threads=5
            local retry_rate=$(( naabu_rate / 2 ))
            [ "$retry_rate" -lt 200 ] && retry_rate=200
            mv "$OUTPUT_DIR/14_port_scan/naabu.stderr" "$OUTPUT_DIR/14_port_scan/naabu_crash.stderr"
            _run_naabu "$retry_threads" "$retry_rate" -top-ports 1000
            if [ -s "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ]; then
                log_info "Retry succeeded with threads=$retry_threads rate=$retry_rate"
                naabu_crashed=false
            else
                log_error "naabu retry also failed. Port data will be empty."
            fi
        fi
    fi

    # Extract all open ports
    [ -f "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && \
        jq -r 'select(.host != null and .port != null) | .host+":"+(.port|tostring)' "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" | \
        sort -u > "$OUTPUT_DIR/14_port_scan/all_ports_list.txt"

    local total_ports=$(count_lines "$OUTPUT_DIR/14_port_scan/all_ports_list.txt")
    log_info "Total open ports discovered: $total_ports"

    # Identify non-HTTP services (exclude 80, 443, 8080, 8443, etc.)
    [ -f "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && \
        jq -r 'select(.port != 80 and .port != 443 and .port != 8080 and .port != 8443 and .port != 8000 and .port != 3000) | .host+":"+(.port|tostring)' \
        "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" | \
        sort -u > "$OUTPUT_DIR/14_port_scan/non_http_ports.txt"

    local non_web=$(count_lines "$OUTPUT_DIR/14_port_scan/non_http_ports.txt")
    log_info "Non-web services found: $non_web"

    # Group by service type (common ports)
    [ -f "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && \
        jq -r 'select(.port == 22 or .port == 21 or .port == 3389 or .port == 1433 or .port == 3306 or .port == 5432 or .port == 6379 or .port == 27017 or .port == 9200 or .port == 5984) | "\(.host):\(.port)"' \
        "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" | \
        sort -u > "$OUTPUT_DIR/14_port_scan/interesting_services.txt"

    local interesting=$(count_lines "$OUTPUT_DIR/14_port_scan/interesting_services.txt")

    if [ $interesting -gt 0 ]; then
        log_info "Found $interesting potentially sensitive services:"
        echo ""
        head -20 "$OUTPUT_DIR/14_port_scan/interesting_services.txt"
        echo ""
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    update_statistics "open_ports" "$total_ports"

    # Determine scan status for dashboard
    local scan_status="ok"
    if [ "$naabu_crashed" = "true" ]; then
        scan_status="crashed"
    elif [ "$total_ports" -eq 0 ]; then
        scan_status="no_open_ports"
    fi
    update_statistics "port_scan_status" "\"$scan_status\""

    # Feed the dashboard immediately; nmap enriches these entries in the next module.
    python3 - "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" "$MANIFEST_FILE" << 'PYTHON_EOF'
import json
import sys
from collections import defaultdict

ports = defaultdict(set)
try:
    with open(sys.argv[1]) as source:
        for line in source:
            try:
                item = json.loads(line)
                ports[item['host']].add(int(item['port']))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
except FileNotFoundError:
    pass

with open(sys.argv[2]) as source:
    manifest = json.load(source)
for host, values in ports.items():
    manifest.setdefault('hosts', {}).setdefault(host, {})['ports_open'] = sorted(values)
with open(sys.argv[2], 'w') as destination:
    json.dump(manifest, destination, indent=2)
PYTHON_EOF

    cat > "$output_file" << EOF
{
  "module": "full_port_scan",
  "targets_scanned": $unique_count,
  "total_ports": $total_ports,
  "non_web_ports": $non_web,
  "interesting_services": $interesting,
  "scan_mode": "$PORT_SCAN_MODE",
  "scan_status": "$scan_status",
  "duration_seconds": $duration,
  "duration_minutes": $((duration / 60))
}
EOF

    log_info "Full port scan completed in $((duration / 60)) minutes (status: $scan_status)"
    log_info "Results saved to: $OUTPUT_DIR/14_port_scan/"

    # Fail the module if naabu crashed and retry failed
    [ "$naabu_crashed" = "true" ] && return 1
    echo "$output_file"
}
###################################################################################################
# MODULE 17: CLOUD ATTACK SURFACE EXPOSURE
#
# Detects cloud-native external exposures using existing tools + nuclei, with
# custom ARISE templates for the gaps, then scores every finding with a weighted
# model: weighted_score = base_weight x exploitability x exposure.
#
#   base_weight  - blast radius of the finding class (see BASE_WEIGHT table below)
#   exploitability - detection confidence: 1.0 confirmed unauth access,
#                    0.7 reachable/auth-unknown, 0.4 indicator only (port/DNS)
#   exposure     - internet reachability: 1.0 direct, 0.85 behind CDN (bypassable),
#                    0.6 behind WAF/auth-gated
###################################################################################################

# SPF / DKIM / DMARC posture for the apex domain (native, dig-based).
_cloud_check_email_auth() {
    local domain="$1" out="$2"
    command -v dig &>/dev/null || { echo '{}' > "$out"; return 0; }

    local spf dmarc dkim_found="false" dmarc_policy="none"
    spf=$(dig +short TXT "$domain" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' | head -1)
    dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"' | grep -i 'v=DMARC1' | head -1)
    if [ -n "$dmarc" ]; then
        dmarc_policy=$(printf '%s' "$dmarc" | grep -oiE 'p=[a-zA-Z]+' | head -1 | cut -d= -f2)
        [ -z "$dmarc_policy" ] && dmarc_policy="none"
    fi
    local sel
    for sel in default google selector1 selector2 k1 mail dkim s1 s2 smtp; do
        if dig +short TXT "${sel}._domainkey.$domain" 2>/dev/null | grep -qiE 'v=DKIM1|k=rsa|p='; then
            dkim_found="true"; break
        fi
    done
    jq -nc --arg spf "$spf" --arg dmarc "$dmarc" --arg policy "$dmarc_policy" --argjson dkim "$dkim_found" \
        '{spf_present:($spf|length>0), spf:$spf, dmarc_present:($dmarc|length>0), dmarc_policy:$policy, dkim_present:$dkim}' \
        > "$out" 2>/dev/null || echo '{}' > "$out"
}

# CDN/WAF origin-bypass test: can a protected host be reached directly on its
# origin IP with the correct Host header, returning the same application?
_cloud_origin_bypass() {
    local out="$1"
    local dns_json="$OUTPUT_DIR/03_dns_resolution/dns_results.json"
    [ ! -f "$dns_json" ] && return 0
    [ ! -f "$MANIFEST_FILE" ] && return 0

    local max="${CLOUD_ORIGIN_MAX:-25}" tested=0
    local protected
    protected=$(jq -r '.hosts | to_entries[]
        | select(.value.cdn==true or (.value.waf_vendor!=null and .value.waf_vendor!="none"))
        | .key' "$MANIFEST_FILE" 2>/dev/null)
    [ -z "$protected" ] && return 0

    while IFS= read -r host; do
        [ -z "$host" ] && continue
        [ "$tested" -ge "$max" ] && break
        local ips
        ips=$(jq -r --arg h "$host" 'select(.host==$h) | .a[]?' "$dns_json" 2>/dev/null | sort -u)
        [ -z "$ips" ] && continue

        local base_len
        base_len=$(curl -sk --max-time 8 "https://$host/" 2>/dev/null | wc -c | tr -d ' ')
        [ "${base_len:-0}" -lt 200 ] && { tested=$((tested+1)); continue; }

        local ip
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            local direct_code direct_len diff pct
            direct_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
                --resolve "$host:443:$ip" "https://$host/" 2>/dev/null)
            [ "$direct_code" != "200" ] && continue
            direct_len=$(curl -sk --max-time 8 --resolve "$host:443:$ip" "https://$host/" 2>/dev/null | wc -c | tr -d ' ')
            diff=$(( base_len > direct_len ? base_len - direct_len : direct_len - base_len ))
            pct=$(( diff * 100 / (base_len + 1) ))
            if [ "$pct" -lt 15 ]; then
                jq -nc --arg host "$host" --arg ip "$ip" --argjson blen "$base_len" --argjson dlen "$direct_len" \
                    '{host:$host, origin_ip:$ip, cdn_body_len:$blen, direct_body_len:$dlen}' >> "$out"
                break
            fi
        done <<< "$ips"
        tested=$((tested+1))
    done <<< "$protected"
}

# Leaked cloud credentials: reuse trufflehog output, then regex-sweep served JS.
_cloud_credentials() {
    local out="$1"
    local secrets="$OUTPUT_DIR/10_secret_scanning/secrets.json"
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"

    if [ -f "$secrets" ]; then
        jq -c '.[]
            | select((.DetectorName // "") | test("AWS|GCP|Google|Azure|Cloud|S3|Gcs|PrivateKey";"i"))
            | {tool:"trufflehog", detector:(.DetectorName//"unknown"),
               file:((.SourceMetadata.Data.Filesystem.file)//""), redacted:(.Redacted//"")}' \
            "$secrets" 2>/dev/null >> "$out" || true
    fi

    if [ -d "$js_dir" ]; then
        python3 - "$js_dir" "$out" << 'CREDEOF'
import sys, os, re, json
js_dir, out = sys.argv[1], sys.argv[2]
patterns = {
    "aws_access_key_id": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    "google_api_key": re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    "gcp_service_account": re.compile(r'"type":\s*"service_account"'),
    "azure_storage_key": re.compile(r'AccountKey=[A-Za-z0-9+/=]{80,}'),
    "private_key_block": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
}
seen = set()
with open(out, "a") as w:
    for root, _, files in os.walk(js_dir):
        for fn in files:
            if not fn.endswith(".js"):
                continue
            fp = os.path.join(root, fn)
            try:
                data = open(fp, errors="ignore").read()
            except Exception:
                continue
            for name, rx in patterns.items():
                m = rx.search(data)
                if not m:
                    continue
                key = (name, fn)
                if key in seen:
                    continue
                seen.add(key)
                w.write(json.dumps({"tool": "arise-regex", "detector": name,
                                    "file": fp, "redacted": m.group(0)[:12] + "..."}) + "\n")
CREDEOF
    fi
}

# ---------------------------------------------------------------------------
# Phase 2 — external, unauthenticated cloud storage enumeration.
# CloudEnum brute-forces bucket/blob names from the target keyword across AWS,
# GCP and Azure; S3Scanner then checks anonymous access on the AWS hits and
# lists contents where the ACL permits. No credentials required — pure recon.
# Writes cloud_buckets.jsonl: {name, provider, access, url, files, note}
# ---------------------------------------------------------------------------
_cloud_bucket_enum() {
    local target="$1"
    local out="$2"
    : > "$out"

    if [ "$CLOUD_BUCKET_ENUM_ENABLED" != "true" ]; then
        log_info "  Bucket enumeration disabled (CLOUD_BUCKET_ENUM_ENABLED=false)"
        return 0
    fi

    # Keyword = the registrable label (howzat from howzat.com) plus any operator
    # mutations. CloudEnum permutes these with common bucket affixes internally.
    local keyword="${target%%.*}"
    local raw_dir; raw_dir="$(dirname "$out")"
    local cloudenum_raw="$raw_dir/cloudenum_raw.txt"
    local s3_targets="$raw_dir/s3_candidate_buckets.txt"
    : > "$s3_targets"

    if command -v "$CLOUDENUM" &>/dev/null; then
        log_info "  CloudEnum: enumerating AWS/GCP/Azure storage for '$keyword'..."
        local kw_args=("-k" "$keyword" "-k" "$target")
        if [ -n "$CLOUD_BUCKET_MUTATIONS" ]; then
            local IFS_OLD="$IFS"; IFS=','
            for m in $CLOUD_BUCKET_MUTATIONS; do
                [ -n "$m" ] && kw_args+=("-k" "$m")
            done
            IFS="$IFS_OLD"
        fi
        "$CLOUDENUM" "${kw_args[@]}" --disable-azure --quickscan -l "$cloudenum_raw" \
            &>/dev/null || "$CLOUDENUM" "${kw_args[@]}" -l "$cloudenum_raw" &>/dev/null || true

        # CloudEnum log lines look like: "OPEN S3 BUCKET: http://name.s3..."
        if [ -f "$cloudenum_raw" ]; then
            python3 - "$cloudenum_raw" "$out" "$s3_targets" << 'CEEOF' || true
import sys, re, json
raw, out, s3t = sys.argv[1], sys.argv[2], sys.argv[3]
def provider(line):
    l = line.lower()
    if "s3" in l or "aws" in l: return "aws"
    if "google" in l or "gcp" in l or "storage.googleapis" in l: return "gcp"
    if "azure" in l or "blob.core" in l or "windows.net" in l: return "azure"
    return "aws"
def access(line):
    l = line.lower()
    if "open" in l or "public" in l or "listable" in l: return "public"
    if "protected" in l or "forbidden" in l or "private" in l: return "private"
    if "exists" in l or "found" in l: return "exists"
    return "unknown"
url_rx = re.compile(r'https?://[^\s]+')
seen = set()
with open(out, "a") as w, open(s3t, "a") as s:
    for line in open(raw, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        m = url_rx.search(line)
        if not m:
            continue
        url = m.group(0).rstrip(".,")
        # bucket name = host label before .s3 / .storage / .blob
        host = url.split("//",1)[-1].split("/",1)[0]
        name = host.split(".")[0]
        prov = provider(line)
        acc = access(line)
        key = (name, prov)
        if key in seen:
            continue
        seen.add(key)
        w.write(json.dumps({"name": name, "provider": prov, "access": acc,
                            "url": url, "files": 0,
                            "note": "cloud_enum: %s" % acc}) + "\n")
        if prov == "aws":
            s.write(name + "\n")
CEEOF
        fi
    else
        log_warn "  CloudEnum not installed ($CLOUDENUM); skipping bucket enumeration"
    fi

    # S3Scanner: deep anonymous-access check + object listing on AWS candidates.
    if command -v "$S3SCANNER" &>/dev/null && [ -s "$s3_targets" ]; then
        log_info "  S3Scanner: checking anonymous access on $(count_lines "$s3_targets") AWS buckets..."
        local s3_json="$raw_dir/s3scanner_raw.jsonl"
        "$S3SCANNER" -bucket-file "$s3_targets" -enumerate -json 2>/dev/null > "$s3_json" || \
            "$S3SCANNER" scan -f "$s3_targets" --json 2>/dev/null > "$s3_json" || true
        if [ -s "$s3_json" ]; then
            python3 - "$s3_json" "$out" << 'S3EOF' || true
import sys, json
raw, out = sys.argv[1], sys.argv[2]
rows = []
for line in open(raw, errors="ignore"):
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    name = d.get("name") or d.get("bucket") or d.get("Bucket") or ""
    if not name:
        continue
    perms = d.get("permissions") or d.get("perms") or {}
    exists = d.get("exists", d.get("found", True))
    readable = False
    if isinstance(perms, dict):
        readable = any("read" in str(k).lower() and v for k, v in perms.items())
    acc = "public" if readable else ("exists" if exists else "private")
    files = d.get("num_objects") or d.get("objects") or d.get("files") or 0
    rows.append({"name": name, "provider": "aws", "access": acc,
                 "url": "https://%s.s3.amazonaws.com" % name,
                 "files": files, "note": "s3scanner: %s" % acc})
# S3Scanner rows override cloud_enum rows for the same bucket (deeper signal).
with open(out, "a") as w:
    for r in rows:
        w.write(json.dumps(r) + "\n")
S3EOF
        fi
    elif [ -s "$s3_targets" ]; then
        log_warn "  S3Scanner not installed ($S3SCANNER); reporting CloudEnum results only"
    fi

    log_info "  Bucket enumeration: $(count_lines "$out") storage findings"
}

# ---------------------------------------------------------------------------
# Phase 3 — authenticated cloud compliance audit (Prowler / ScoutSuite).
# This scans the target's cloud ACCOUNT from the inside via cloud APIs and
# therefore needs the target's own credentials. It is OFF by default and only
# runs when the operator sets CLOUD_AUDIT_ENABLED=true AND has credentials in
# the environment (auditing your own estate, or authorized post-compromise).
# Writes cloud_compliance.jsonl: {tool, check_id, title, service, severity,
# status, region, resource, framework, remediation}
# ---------------------------------------------------------------------------
_cloud_compliance_audit() {
    local out="$1"
    : > "$out"

    if [ "$CLOUD_AUDIT_ENABLED" != "true" ]; then
        log_info "  Compliance audit disabled (CLOUD_AUDIT_ENABLED=false) — external scan"
        return 0
    fi

    # Refuse to run without credentials rather than emit a misleading empty audit.
    local have_creds="false"
    case "$CLOUD_AUDIT_PROVIDER" in
        aws)   { [ -n "$AWS_ACCESS_KEY_ID" ] || [ -n "$AWS_PROFILE" ]; } && have_creds="true" ;;
        gcp)   [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ] && have_creds="true" ;;
        azure) { [ -n "$AZURE_CLIENT_ID" ] || [ -n "$AZURE_SUBSCRIPTION_ID" ]; } && have_creds="true" ;;
    esac
    if [ "$have_creds" != "true" ]; then
        log_warn "  CLOUD_AUDIT_ENABLED=true but no $CLOUD_AUDIT_PROVIDER credentials in env; skipping audit"
        return 0
    fi

    local raw_dir; raw_dir="$(dirname "$out")"
    log_warn "  Running AUTHENTICATED compliance audit ($CLOUD_AUDIT_TOOL / $CLOUD_AUDIT_PROVIDER) — ensure you are authorized"

    if [ "$CLOUD_AUDIT_TOOL" = "prowler" ] && command -v "$PROWLER" &>/dev/null; then
        local prowler_json="$raw_dir/prowler_output.json"
        "$PROWLER" "$CLOUD_AUDIT_PROVIDER" -M json-ocsf -o "$raw_dir" -F prowler_output \
            &>/dev/null || "$PROWLER" "$CLOUD_AUDIT_PROVIDER" &>/dev/null || true
        # Prowler v4 writes prowler_output.ocsf.json; normalize whatever we find.
        local found; found="$(ls "$raw_dir"/prowler_output*.json 2>/dev/null | head -1)"
        if [ -n "$found" ]; then
            python3 - "$found" "$out" << 'PROWEOF' || true
import sys, json
raw, out = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(raw, errors="ignore"))
except Exception:
    data = []
if isinstance(data, dict):
    data = data.get("findings", [])
sev_map = {"critical":"critical","high":"high","medium":"medium","low":"low",
           "informational":"info","info":"info"}
with open(out, "a") as w:
    for f in data if isinstance(data, list) else []:
        status = (f.get("status_code") or f.get("status") or "").upper()
        if status in ("PASS", "MANUAL"):
            continue
        sev = str(f.get("severity") or f.get("severity_id") or "medium").lower()
        finding = f.get("finding_info", {}) if isinstance(f.get("finding_info"), dict) else {}
        res = f.get("resources", [{}])
        res0 = res[0] if isinstance(res, list) and res else {}
        w.write(json.dumps({
            "tool": "prowler",
            "check_id": f.get("check_id") or finding.get("uid") or "",
            "title": f.get("check_title") or finding.get("title") or f.get("message",""),
            "service": (f.get("service_name") or f.get("cloud",{}).get("provider") or "general"),
            "severity": sev_map.get(sev, "medium"),
            "status": status or "FAIL",
            "region": f.get("region") or res0.get("region",""),
            "resource": res0.get("name") or res0.get("uid",""),
            "framework": "CIS",
            "remediation": (f.get("remediation") or {}).get("desc","") if isinstance(f.get("remediation"),dict) else "",
        }) + "\n")
PROWEOF
        fi
    elif [ "$CLOUD_AUDIT_TOOL" = "scoutsuite" ] && command -v "$SCOUTSUITE" &>/dev/null; then
        "$SCOUTSUITE" "$CLOUD_AUDIT_PROVIDER" --report-dir "$raw_dir/scoutsuite" \
            --no-browser &>/dev/null || true
        local scout_js; scout_js="$(ls "$raw_dir"/scoutsuite/scoutsuite-results/scoutsuite_results_*.js 2>/dev/null | head -1)"
        if [ -n "$scout_js" ]; then
            python3 - "$scout_js" "$out" << 'SCOUTEOF' || true
import sys, json, re
raw, out = sys.argv[1], sys.argv[2]
txt = open(raw, errors="ignore").read()
txt = re.sub(r'^scoutsuite_results\s*=\s*', '', txt.strip())
try:
    data = json.loads(txt)
except Exception:
    data = {}
services = data.get("services", {})
sev_map = {"danger":"high","warning":"medium","good":"info"}
with open(out, "a") as w:
    for svc, sdata in services.items():
        findings = sdata.get("findings", {})
        for fid, f in findings.items():
            flagged = f.get("flagged_items", 0)
            if not flagged:
                continue
            lvl = (f.get("level") or "warning").lower()
            w.write(json.dumps({
                "tool": "scoutsuite", "check_id": fid,
                "title": f.get("description", fid), "service": svc,
                "severity": sev_map.get(lvl, "medium"), "status": "FAIL",
                "region": "", "resource": "%d flagged" % flagged,
                "framework": "ScoutSuite", "remediation": f.get("rationale",""),
            }) + "\n")
SCOUTEOF
        fi
    else
        log_warn "  Audit tool '$CLOUD_AUDIT_TOOL' not installed; skipping compliance audit"
    fi

    log_info "  Compliance audit: $(count_lines "$out") findings"
}

module_cloud_exposure() {
    local target="$1"
    log_section "MODULE 17: Cloud Attack Surface Exposure"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/17_cloud_exposure"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "cloud_exposure" "results")"

    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    local nuclei_out="$base_dir/cloud_nuclei.jsonl"
    local email_file="$base_dir/email_auth.json"
    local origin_file="$base_dir/origin_bypass.jsonl"
    local cred_file="$base_dir/cloud_credentials.jsonl"
    local buckets_file="$base_dir/cloud_buckets.jsonl"
    local compliance_file="$base_dir/cloud_compliance.jsonl"
    local findings_file="$base_dir/cloud_findings.jsonl"
    : > "$nuclei_out"; : > "$origin_file"; : > "$cred_file"

    # 1. Curated nuclei pass: custom ARISE templates + official cloud tags.
    local tmpl_dir="$PROJECT_ROOT/cloud-templates"
    [ ! -d "$tmpl_dir" ] && tmpl_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cloud-templates"
    local cloud_tags="aws,s3,bucket,gcs,azure,kubernetes,k8s,kubelet,etcd,elasticsearch,opensearch,kibana,redis,mongodb,memcached,grafana,prometheus,jenkins,gitlab,argocd,teamcity,drone,ssrf,metadata,exposure,debug,config"

    if command -v "$NUCLEI" &>/dev/null && [ -s "$http_hosts_file" ]; then
        if [ -d "$tmpl_dir" ]; then
            log_info "Running ARISE custom cloud templates ($tmpl_dir)..."
            "$NUCLEI" -l "$http_hosts_file" -t "$tmpl_dir" -j -silent -rl 100 -nc 2>/dev/null >> "$nuclei_out" || true
        else
            log_warn "Custom cloud-templates directory not found; using tags only"
        fi
        log_info "Running official nuclei cloud-tagged templates..."
        "$NUCLEI" -l "$http_hosts_file" -tags "$cloud_tags" \
            -severity low,medium,high,critical,unknown -j -silent -rl 100 -nc 2>/dev/null >> "$nuclei_out" || true
    else
        log_warn "nuclei unavailable or no HTTP hosts; skipping cloud nuclei pass"
    fi
    log_info "Cloud nuclei findings: $(count_lines "$nuclei_out")"

    # 2. Email authentication posture (SPF/DKIM/DMARC).
    log_info "Checking email authentication records (SPF/DKIM/DMARC)..."
    _cloud_check_email_auth "$target" "$email_file"

    # 3. CDN/WAF origin-bypass heuristic.
    log_info "Testing protected hosts for CDN/WAF origin bypass..."
    _cloud_origin_bypass "$origin_file"

    # 4. Leaked cloud credentials.
    log_info "Correlating leaked cloud credentials..."
    _cloud_credentials "$cred_file"

    # 5. Phase 2 — external cloud storage enumeration (CloudEnum + S3Scanner).
    log_info "Enumerating public cloud storage (CloudEnum + S3Scanner)..."
    _cloud_bucket_enum "$target" "$buckets_file"

    # 6. Phase 3 — authenticated compliance audit (off unless creds supplied).
    log_info "Cloud compliance audit (authenticated)..."
    _cloud_compliance_audit "$compliance_file"

    # 7. Weighted scoring model.
    log_info "Scoring cloud findings (severity x exploitability x exposure)..."
    python3 - "$MANIFEST_FILE" "$nuclei_out" "$email_file" "$origin_file" "$cred_file" \
        "$OUTPUT_DIR/14_port_scan/all_ports_list.txt" "$findings_file" "$base_dir/cloud_summary.json" \
        "$buckets_file" << 'CLOUDSCORE_EOF'
import sys, os, json

(manifest_file, nuclei_file, email_file, origin_file, cred_file, ports_file,
 out_file, summary_file, buckets_file) = sys.argv[1:10]

BASE_WEIGHT = {
    "public_cloud_storage": 100, "public_kubernetes_api": 100,
    "metadata_service_exposure": 100, "leaked_cloud_credentials": 100,
    "terraform_state_exposed": 95, "public_elasticsearch": 95,
    "public_cicd": 90, "public_redis_mongo": 90,
    "grafana_prometheus_exposed": 80, "cdn_origin_bypass": 60,
    "missing_waf": 40, "missing_email_auth": 25,
    "debug_endpoint": 20, "information_disclosure": 15,
}
LABEL = {
    "public_cloud_storage": "Public cloud storage",
    "public_kubernetes_api": "Public Kubernetes API",
    "metadata_service_exposure": "Metadata service exposure",
    "leaked_cloud_credentials": "Leaked cloud credentials",
    "terraform_state_exposed": "Exposed Terraform state",
    "public_elasticsearch": "Public Elasticsearch/OpenSearch",
    "public_cicd": "Public Jenkins/CI-CD",
    "public_redis_mongo": "Public Redis/MongoDB",
    "grafana_prometheus_exposed": "Exposed Grafana/Prometheus",
    "cdn_origin_bypass": "CDN origin bypass",
    "missing_waf": "Missing WAF",
    "missing_email_auth": "Missing SPF/DKIM/DMARC",
    "debug_endpoint": "Debug endpoint",
    "information_disclosure": "Information disclosure",
}
REMEDIATION = {
    "public_cloud_storage": "Disable public bucket ACLs; enforce Block Public Access and least-privilege IAM.",
    "public_kubernetes_api": "Require authN/authZ on the API server and kubelet; restrict by network policy/firewall.",
    "metadata_service_exposure": "Enforce IMDSv2, block egress to 169.254.169.254, and fix the SSRF/proxy allowing relay.",
    "leaked_cloud_credentials": "Rotate the credential immediately, review CloudTrail/audit logs, and remove it from client code.",
    "terraform_state_exposed": "Remove the state file from the web root; store state in an access-controlled backend.",
    "public_elasticsearch": "Enable authentication and TLS; bind to private networks only.",
    "public_cicd": "Require SSO/authentication, disable anonymous access, and restrict network reachability.",
    "public_redis_mongo": "Enable authentication, bind to localhost/private nets, and firewall the port.",
    "grafana_prometheus_exposed": "Disable anonymous access, require login, and place behind authenticated proxy.",
    "cdn_origin_bypass": "Restrict origin to CDN/WAF egress IP ranges (ACL/security group/mTLS).",
    "missing_waf": "Place internet-facing web apps behind a WAF/CDN with rules enabled.",
    "missing_email_auth": "Publish SPF, DKIM, and a DMARC policy of quarantine or reject.",
    "debug_endpoint": "Disable debug/introspection endpoints in production or require authentication.",
    "information_disclosure": "Remove exposed internal information and restrict access.",
}

def sev_from_score(s):
    if s >= 90: return "critical"
    if s >= 60: return "high"
    if s >= 30: return "medium"
    if s >= 10: return "low"
    return "info"

def classify(tid, name, tags, arise_cat):
    if arise_cat and arise_cat in BASE_WEIGHT:
        return arise_cat
    blob = " ".join([tid or "", name or "", " ".join(tags or [])]).lower()
    rules = [
        (("s3", "bucket", "gcs", "google-storage", "azure-blob", "blob-container", "object-storage"), "public_cloud_storage"),
        (("kubernetes", "kubelet", "kube-", "k8s", "etcd", "kubeconfig", "kube-api"), "public_kubernetes_api"),
        (("metadata", "instance-metadata", "imds"), "metadata_service_exposure"),
        (("terraform", "tfstate"), "terraform_state_exposed"),
        (("elasticsearch", "opensearch", "kibana"), "public_elasticsearch"),
        (("jenkins", "gitlab", "teamcity", "argocd", "drone", "circleci", "bamboo", "gocd", "concourse"), "public_cicd"),
        (("redis", "mongodb", "mongo", "memcached", "couchdb", "cassandra"), "public_redis_mongo"),
        (("grafana", "prometheus", "alertmanager", "node-exporter"), "grafana_prometheus_exposed"),
        (("actuator", "phpinfo", "werkzeug", "debug", "expvar", "heapdump"), "debug_endpoint"),
    ]
    for kws, cat in rules:
        if any(k in blob for k in kws):
            return cat
    if "ssrf" in blob and "metadata" in blob:
        return "metadata_service_exposure"
    if any(k in blob for k in ("disclosure", "exposure", "exposed", "leak")):
        return "information_disclosure"
    return None

manifest = {}
if os.path.exists(manifest_file):
    try:
        manifest = json.load(open(manifest_file))
    except Exception:
        manifest = {}
hosts_meta = manifest.get("hosts", {})

def host_exposure(host):
    hd = hosts_meta.get(host, {})
    waf = (hd.get("waf_vendor") or "none").lower()
    if waf not in ("none", ""):
        return 0.6, "behind_waf"
    if hd.get("cdn"):
        return 0.85, "behind_cdn"
    return 1.0, "direct"

def host_from_url(u):
    try:
        return u.split("//")[1].split("/")[0].split(":")[0]
    except Exception:
        return u

findings = []
seen_host_cat = set()

def add(cat, host, url, expl, tool, template, evidence, nuclei_sev=None, exposure_override=None):
    exposure, note = host_exposure(host)
    if exposure_override is not None:
        exposure, note = exposure_override
    base = BASE_WEIGHT[cat]
    score = round(min(base * expl * exposure, 100.0), 1)
    findings.append({
        "cloud_category": cat, "category_label": LABEL[cat],
        "source": "Cloud Exposure", "tool": tool,
        "template": template, "host": host or "Unknown", "url": url,
        "severity": sev_from_score(score), "nuclei_severity": nuclei_sev,
        "base_weight": base, "exploitability": round(expl, 2),
        "exposure": round(exposure, 2), "exposure_note": note,
        "weighted_score": score, "evidence": (evidence or "")[:220],
        "remediation": REMEDIATION[cat],
    })

# ---- nuclei findings ----
if os.path.exists(nuclei_file):
    for line in open(nuclei_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info", {})
        tid = d.get("template-id", "")
        name = info.get("name", "")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        arise_cat = (info.get("metadata") or {}).get("arise-category")
        cat = classify(tid, name, tags, arise_cat)
        if not cat:
            continue
        sev = (info.get("severity", "info") or "info").lower()
        url = d.get("matched-at") or d.get("url") or d.get("host", "")
        host = host_from_url(d.get("host") or url)
        extracted = d.get("extracted-results") or []
        if sev in ("critical", "high") or extracted:
            expl = 1.0
        elif sev == "medium":
            expl = 0.7
        else:
            expl = 0.5
        evidence = ", ".join(extracted) if isinstance(extracted, list) else str(extracted)
        add(cat, host, url, expl, "nuclei", name or tid, evidence, nuclei_sev=sev)
        seen_host_cat.add((host, cat))

# ---- port-scan inference (indicator only: exploitability 0.4) ----
PORT_CAT = {
    9200: "public_elasticsearch", 9300: "public_elasticsearch", 5601: "public_elasticsearch",
    6379: "public_redis_mongo", 27017: "public_redis_mongo", 27018: "public_redis_mongo",
    11211: "public_redis_mongo", 5984: "public_redis_mongo",
    6443: "public_kubernetes_api", 10250: "public_kubernetes_api", 2379: "public_kubernetes_api",
    9090: "grafana_prometheus_exposed", 3000: "grafana_prometheus_exposed",
}
if os.path.exists(ports_file):
    for line in open(ports_file, errors="ignore"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        try:
            port = int(port)
        except ValueError:
            continue
        cat = PORT_CAT.get(port)
        if not cat or (host, cat) in seen_host_cat:
            continue
        seen_host_cat.add((host, cat))
        add(cat, host, "%s:%d" % (host, port), 0.4, "naabu",
            "Open %d/tcp" % port, "port %d open (service/auth unconfirmed)" % port,
            exposure_override=(1.0, "direct"))

# ---- email authentication ----
apex = manifest.get("pipeline_info", {}).get("target", "")
if os.path.exists(email_file):
    try:
        ea = json.load(open(email_file))
    except Exception:
        ea = {}
    if ea:
        gaps = []
        if not ea.get("spf_present"):
            gaps.append("no SPF")
        if not ea.get("dmarc_present"):
            gaps.append("no DMARC")
        elif ea.get("dmarc_policy", "none").lower() == "none":
            gaps.append("DMARC p=none (monitor only)")
        if not ea.get("dkim_present"):
            gaps.append("no DKIM selector found")
        if gaps:
            add("missing_email_auth", apex, apex, 0.5, "dig",
                "Email authentication gaps", "; ".join(gaps),
                exposure_override=(1.0, "domain"))

# ---- origin bypass ----
if os.path.exists(origin_file):
    for line in open(origin_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        host = o.get("host", "")
        add("cdn_origin_bypass", host, "https://%s (origin %s)" % (host, o.get("origin_ip", "")),
            0.7, "arise", "Origin reachable directly",
            "origin IP %s serves the app directly, bypassing CDN/WAF" % o.get("origin_ip", ""),
            exposure_override=(0.85, "origin_reachable"))

# ---- leaked cloud credentials ----
if os.path.exists(cred_file):
    cred_seen = set()
    for line in open(cred_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            c = json.loads(line)
        except Exception:
            continue
        det = c.get("detector", "credential")
        f = os.path.basename(c.get("file", ""))
        key = (det, f)
        if key in cred_seen:
            continue
        cred_seen.add(key)
        add("leaked_cloud_credentials", apex, c.get("file", ""), 1.0,
            c.get("tool", "arise"), det,
            "%s in served asset (%s)" % (det, c.get("redacted", "")),
            exposure_override=(1.0, "public_asset"))

# ---- Phase 2: enumerated storage buckets (CloudEnum + S3Scanner) ----
# A publicly readable/listable bucket is a confirmed exposure; a bucket that
# merely exists is recon only and is surfaced in the dashboard recon panel, not
# scored as a vulnerability here.
if os.path.exists(buckets_file):
    bkt_seen = set()
    for line in open(buckets_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            b = json.loads(line)
        except Exception:
            continue
        name = b.get("name", "")
        access = (b.get("access") or "unknown").lower()
        if not name or access not in ("public", "open", "listable"):
            continue
        if name in bkt_seen:
            continue
        bkt_seen.add(name)
        files = b.get("files", 0)
        expl = 1.0 if files else 0.85
        evidence = "%s bucket '%s' publicly readable" % (b.get("provider", "aws").upper(), name)
        if files:
            evidence += " (%s objects listed)" % files
        add("public_cloud_storage", name, b.get("url", name), expl,
            b.get("note", "").split(":")[0] or "cloud_enum", "Public storage bucket",
            evidence, exposure_override=(1.0, "public_internet"))

# ---- missing WAF (control gap; cap to limit noise) ----
missing_waf = []
for host, hd in hosts_meta.items():
    if not hd.get("http_status"):
        continue
    waf = (hd.get("waf_vendor") or "none").lower()
    if waf in ("none", "") and not hd.get("cdn"):
        missing_waf.append(host)
for host in missing_waf[:50]:
    add("missing_waf", host, "https://%s" % host, 0.4, "arise",
        "No WAF/CDN in front of web app", "internet-facing host without WAF or CDN",
        exposure_override=(1.0, "direct"))

# ---- write outputs ----
findings.sort(key=lambda x: x["weighted_score"], reverse=True)
with open(out_file, "w") as w:
    for f in findings:
        w.write(json.dumps(f) + "\n")

by_cat = {}
for f in findings:
    c = f["cloud_category"]
    by_cat.setdefault(c, {"label": LABEL[c], "count": 0, "max_score": 0})
    by_cat[c]["count"] += 1
    by_cat[c]["max_score"] = max(by_cat[c]["max_score"], f["weighted_score"])

sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
for f in findings:
    sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

summary = {
    "total_findings": len(findings),
    "by_category": by_cat,
    "by_severity": sev_counts,
    "top_finding_score": findings[0]["weighted_score"] if findings else 0,
}
json.dump(summary, open(summary_file, "w"), indent=2)
print(len(findings))
CLOUDSCORE_EOF

    local total=$(count_lines "$findings_file")
    log_info "Cloud attack surface findings: $total (scored)"
    if [ "$total" -gt 0 ]; then
        log_info "Top cloud exposures:"
        head -5 "$findings_file" | jq -r '"  [\(.weighted_score)] \(.category_label) - \(.host) (\(.severity))"' 2>/dev/null || true
    fi

    update_statistics "cloud_findings" "$total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "cloud_exposure",
  "cloud_findings": $total,
  "nuclei_findings": $(count_lines "$nuclei_out"),
  "buckets_enumerated": $(count_lines "$buckets_file"),
  "compliance_findings": $(count_lines "$compliance_file"),
  "findings_file": "cloud_findings.jsonl",
  "buckets_file": "cloud_buckets.jsonl",
  "compliance_file": "cloud_compliance.jsonl",
  "summary_file": "cloud_summary.json",
  "duration_seconds": $((end_time - start_time))
}
EOF

    log_info "Cloud attack surface exposure completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 19: EXTENDED VULNERABILITY VERIFICATION (production-safe: confirm, never exploit)
###################################################################################################

# Collect candidate URLs that carry query parameters, from crawling + param
# fuzzing. SAFE: we only keep GET-style URLs and cap the count.
_ext_collect_param_urls() {
    local out="$1"
    : > "$out"
    local sources=(
        "$OUTPUT_DIR/06_crawling/all_urls.txt"
        "$OUTPUT_DIR/09_crawling/all_urls.txt"
        "$OUTPUT_DIR/11_param_fuzzing/param_urls.txt"
        "$OUTPUT_DIR/10_param_fuzzing/param_urls.txt"
    )
    for s in "${sources[@]}"; do
        [ -f "$s" ] && grep -E '\?[^=]+=' "$s" 2>/dev/null
    done | grep -Ev '\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|webp|mp4|pdf)(\?|$)' \
         | sort -u | head -n "$EXTENDED_MAX_URLS" > "$out"
    count_lines "$out"
}

# Start the interactsh OOB oracle in the background. Prints the registered
# payload domain to stdout; callbacks stream as JSON into $2.
_ext_start_interactsh() {
    local domain_out="$1"
    local callbacks="$2"
    : > "$callbacks"; : > "$domain_out"
    command -v "$INTERACTSH_CLIENT" &>/dev/null || { log_warn "  interactsh-client not installed; blind-SSRF confirmation disabled"; return 1; }
    local server_arg=()
    [ -n "$INTERACTSH_SERVER" ] && server_arg=(-s "$INTERACTSH_SERVER")
    # -json streams callback records; -o persists them; -v keeps the domain line.
    "$INTERACTSH_CLIENT" "${server_arg[@]}" -json -o "$callbacks" > "$domain_out.raw" 2>&1 &
    INTERACTSH_PID=$!
    # The client prints the payload domain within the first couple seconds.
    local tries=0
    while [ $tries -lt 10 ]; do
        local dom
        dom=$(grep -oE '[a-z0-9]+\.oast\.[a-z]+' "$domain_out.raw" 2>/dev/null | head -1)
        [ -z "$dom" ] && dom=$(grep -oE '[a-z0-9]+\.[a-z0-9.-]*interact[a-z0-9.-]*' "$domain_out.raw" 2>/dev/null | head -1)
        if [ -n "$dom" ]; then echo "$dom" > "$domain_out"; return 0; fi
        sleep 1; tries=$((tries+1))
    done
    log_warn "  interactsh did not register a domain in time; SSRF confirmation degraded"
    return 1
}

_ext_stop_interactsh() {
    [ -n "$INTERACTSH_PID" ] && kill "$INTERACTSH_PID" 2>/dev/null
    INTERACTSH_PID=""
}

# SSRF (blind, OOB-confirmed). SAFE: injects an interactsh URL into SSRF-sink
# params; a callback proves the server made an outbound request. No internal
# resource is read or returned — confirmation only.
_ext_ssrf() {
    local urls="$1" oob_domain="$2" probe_map="$3" out="$4"
    : > "$out"
    [ "$CHECK_SSRF" = "true" ] || { log_info "  SSRF check disabled"; return 0; }
    [ -s "$oob_domain" ] || { log_warn "  No OOB domain; skipping SSRF confirmation"; return 0; }
    local dom; dom=$(cat "$oob_domain")
    python3 - "$urls" "$dom" "$probe_map" "$EXTENDED_RATE" << 'SSRFEOF'
import sys, urllib.parse, urllib.request, json, time, uuid
urls_file, oob, mapfile, rate = sys.argv[1:5]
delay = 1.0 / max(1, int(rate))
SINKS = {"url","uri","link","src","dest","destination","redirect","redirect_uri","next",
         "continue","path","domain","host","feed","site","callback","webhook","proxy",
         "fetch","file","page","out","to","view","image","img","load","ref","return",
         "u","r","target","open","window","dataurl","source","remote"}
probes = {}
sent = 0
with open(mapfile, "w") as mf:
    for line in open(urls_file, errors="ignore"):
        u = line.strip()
        if not u or sent >= 400:
            continue
        try:
            parts = urllib.parse.urlsplit(u)
            qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        except Exception:
            continue
        if not qs:
            continue
        for i,(k,v) in enumerate(qs):
            if k.lower() not in SINKS:
                continue
            token = uuid.uuid4().hex[:12]
            payload = "http://%s.%s" % (token, oob)
            newqs = qs[:i] + [(k, payload)] + qs[i+1:]
            probe_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                                 urllib.parse.urlencode(newqs), parts.fragment))
            probes[token] = {"url": u, "param": k, "host": parts.netloc}
            mf.write(json.dumps({"token": token, **probes[token]}) + "\n")
            try:
                req = urllib.request.Request(probe_url, headers={"User-Agent": "ARISE-SafeVerify/1.0"})
                urllib.request.urlopen(req, timeout=8).read(1024)
            except Exception:
                pass
            sent += 1
            time.sleep(delay)
print(sent)
SSRFEOF
    log_info "  SSRF probes sent (awaiting OOB callbacks)"
}

# CRLF injection — crlfuzz detection mode. SAFE: detects header-injection
# reflection; does not chain to XSS/cache poisoning.
_ext_crlf() {
    local urls="$1" out="$2"
    : > "$out"
    [ "$CHECK_CRLF" = "true" ] || { log_info "  CRLF check disabled"; return 0; }
    command -v "$CRLFUZZ" &>/dev/null || { log_warn "  crlfuzz not installed; skipping CRLF"; return 0; }
    [ -s "$urls" ] || return 0
    "$CRLFUZZ" -l "$urls" -s -c 25 -o "$out.raw" 2>/dev/null || true
    if [ -f "$out.raw" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local host; host=$(printf '%s' "$line" | awk -F/ '{print $3}')
            jq -cn --arg url "$line" --arg host "$host" \
                '{check:"crlf",tool:"crlfuzz",severity:"medium",template:"CRLF header injection",
                  host:$host,url:$url,parameter:"",evidence:"CRLF payload reflected into response headers",
                  confidence:"confirmed",verification:"response-reflection",
                  remediation:"URL-encode CR/LF in header-reflected values; validate redirect/location inputs.",safe_mode:true}' >> "$out"
        done < "$out.raw"
    fi
    log_info "  CRLF findings: $(count_lines "$out")"
}

# JWT weaknesses — 100% OFFLINE. SAFEST check: extracts tokens from crawled
# responses/JS and analyzes them locally. No requests to production, no forged
# tokens sent, so no possibility of auth bypass.
_ext_jwt() {
    local out="$1"
    : > "$out"
    [ "$CHECK_JWT" = "true" ] || { log_info "  JWT check disabled"; return 0; }
    local resp_dir="$OUTPUT_DIR/04_http_discovery/responses"
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"
    [ -d "$js_dir" ] || js_dir="$OUTPUT_DIR/06_crawling/js_downloads"
    local wordlist="$HOME/recon/lists/jwt-secrets.txt"
    [ -f "$wordlist" ] || wordlist=""
    python3 - "$out" "$resp_dir" "$js_dir" "$wordlist" << 'JWTEOF'
import sys, os, re, json, base64, hmac, hashlib
out, resp_dir, js_dir, wordlist = sys.argv[1:5]
JWT_RX = re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}')
COMMON = ["secret","password","123456","changeme","admin","key","jwt","token","private",
          "secretkey","supersecret","qwerty","test","dev","default","your-256-bit-secret",
          "your_jwt_secret","jwtsecret","s3cr3t","P@ssw0rd"]
def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())
def scan_files(root):
    toks = set()
    if not os.path.isdir(root):
        return toks
    for r,_,files in os.walk(root):
        for fn in files:
            try:
                data = open(os.path.join(r,fn), errors="ignore").read()
            except Exception:
                continue
            for m in JWT_RX.findall(data):
                toks.add(m)
    return toks
tokens = scan_files(resp_dir) | scan_files(js_dir)
words = COMMON[:]
if wordlist and os.path.exists(wordlist):
    words += [w.strip() for w in open(wordlist, errors="ignore") if w.strip()][:5000]
seen = set()
with open(out, "w") as w:
    for tok in tokens:
        parts = tok.split(".")
        if len(parts) < 2:
            continue
        try:
            hdr = json.loads(b64d(parts[0]))
        except Exception:
            continue
        alg = str(hdr.get("alg","")).lower()
        try:
            payload = json.loads(b64d(parts[1])) if len(parts) > 1 else {}
        except Exception:
            payload = {}
        fp = (parts[0], parts[1][:16])
        if fp in seen:
            continue
        seen.add(fp)
        issues, sev = [], "info"
        if alg == "none":
            issues.append("alg:none — signature not enforced"); sev = "high"
        # Offline HMAC secret crack (no network).
        cracked = None
        if alg in ("hs256","hs384","hs512") and len(parts) == 3:
            digestmod = {"hs256":hashlib.sha256,"hs384":hashlib.sha384,"hs512":hashlib.sha512}[alg]
            signing_input = (parts[0] + "." + parts[1]).encode()
            try:
                sig = b64d(parts[2])
                for cand in words:
                    if hmac.compare_digest(hmac.new(cand.encode(), signing_input, digestmod).digest(), sig):
                        cracked = cand; break
            except Exception:
                pass
            if cracked:
                issues.append("weak HMAC secret cracked offline: '%s'" % cracked); sev = "critical"
        sensitive = [k for k in payload if k.lower() in ("role","roles","admin","is_admin","scope","permissions","email","user","uid")]
        if sensitive and not issues:
            issues.append("carries privileged claims: %s" % ", ".join(sensitive[:5])); sev = "low"
        if not issues:
            continue
        host = ""
        for c in ("iss","aud"):
            if isinstance(payload.get(c), str) and "//" in payload[c]:
                host = payload[c].split("//")[1].split("/")[0]; break
        w.write(json.dumps({
            "check":"jwt","tool":"jwt_tool","severity":sev,
            "template":"JWT weakness (%s)" % alg.upper(),
            "host":host or "token", "url":"", "parameter":"Authorization",
            "evidence":"; ".join(issues),
            "confidence":"confirmed","verification":"offline-analysis",
            "remediation":"Use a strong random secret / asymmetric keys; reject alg:none; validate signature server-side.",
            "safe_mode":True}) + "\n")
JWTEOF
    log_info "  JWT findings: $(count_lines "$out")"
}

# SSTI — SSTImap detection only. SAFE: arithmetic marker payloads to identify a
# vulnerable engine; never --os-shell / -X (no code execution).
_ext_ssti() {
    local urls="$1" out="$2"
    : > "$out"
    [ "$CHECK_SSTI" = "true" ] || { log_info "  SSTI check disabled"; return 0; }
    command -v "$SSTIMAP" &>/dev/null || { log_warn "  sstimap not installed; skipping SSTI"; return 0; }
    [ -s "$urls" ] || return 0
    local n=0
    while IFS= read -r u && [ $n -lt 60 ]; do
        [ -z "$u" ] && continue
        n=$((n+1))
        # --detect stops at engine identification; no exploitation flags passed.
        local res; res=$("$SSTIMAP" -u "$u" --detect --forms 2>/dev/null || true)
        if printf '%s' "$res" | grep -qiE 'plugin .* detected|engine: |is vulnerable|template injection'; then
            local engine; engine=$(printf '%s' "$res" | grep -oiE 'engine: [A-Za-z0-9_.]+' | head -1 | awk '{print $2}')
            [ -z "$engine" ] && engine="unknown"
            local host; host=$(printf '%s' "$u" | awk -F/ '{print $3}')
            jq -cn --arg url "$u" --arg host "$host" --arg eng "$engine" \
                '{check:"ssti",tool:"sstimap",severity:"high",template:("SSTI ("+$eng+")"),
                  host:$host,url:$url,parameter:"",evidence:("template engine "+$eng+" reflects injected expression"),
                  confidence:"probable",verification:"expression-eval",
                  remediation:"Never render user input as a template; use logic-less templates or strict sandboxing.",safe_mode:true}' >> "$out"
        fi
    done < "$urls"
    log_info "  SSTI findings: $(count_lines "$out")"
}

# GraphQL — graphw00f fingerprint + introspection check. SAFE: read-only
# detection queries; no mutations.
_ext_graphql() {
    local out="$1"
    : > "$out"
    [ "$CHECK_GRAPHQL" = "true" ] || { log_info "  GraphQL check disabled"; return 0; }
    command -v "$GRAPHW00F" &>/dev/null || { log_warn "  graphw00f not installed; skipping GraphQL"; return 0; }
    # Candidate endpoints: known paths on each confirmed web host.
    local hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ -s "$hosts_file" ] || return 0
    local paths=("/graphql" "/graphql/console" "/api/graphql" "/v1/graphql" "/query" "/gql")
    local n=0
    while IFS= read -r base && [ $n -lt 40 ]; do
        base="${base%/}"
        for p in "${paths[@]}"; do
            n=$((n+1))
            local ep="$base$p"
            local res; res=$("$GRAPHW00F" -d -t "$ep" 2>/dev/null || true)
            if printf '%s' "$res" | grep -qiE 'Discovered GraphQL Engine|Attack Surface|seems to be running'; then
                local engine; engine=$(printf '%s' "$res" | grep -oiE 'Engine: [A-Za-z0-9_.-]+' | head -1 | cut -d' ' -f2)
                [ -z "$engine" ] && engine="unknown"
                local introspect="unknown"
                printf '%s' "$res" | grep -qiE 'introspection.*enabled|Introspection is enabled' && introspect="enabled"
                local sev="info"; [ "$introspect" = "enabled" ] && sev="medium"
                local host; host=$(printf '%s' "$ep" | awk -F/ '{print $3}')
                jq -cn --arg url "$ep" --arg host "$host" --arg eng "$engine" --arg intro "$introspect" --arg sev "$sev" \
                    '{check:"graphql",tool:"graphw00f",severity:$sev,template:("GraphQL endpoint ("+$eng+")"),
                      host:$host,url:$url,parameter:"",evidence:("GraphQL engine "+$eng+", introspection "+$intro),
                      confidence:"informational",verification:"fingerprint",
                      remediation:"Disable introspection in production; enforce query depth/cost limits and authz per field.",safe_mode:true}' >> "$out"
                break
            fi
        done
    done < "$hosts_file"
    log_info "  GraphQL findings: $(count_lines "$out")"
}

# HTTP request smuggling — GATED OFF. Desync probes can corrupt other users'
# in-flight requests on shared production frontends, so this only runs when the
# operator explicitly opts in.
_ext_smuggling() {
    local out="$1"
    : > "$out"
    if [ "$CHECK_SMUGGLING" != "true" ]; then
        log_info "  Smuggling check disabled (CHECK_SMUGGLING=false) — production-safe default"
        return 0
    fi
    command -v "$SMUGGLER" &>/dev/null || { log_warn "  smuggler not installed; skipping"; return 0; }
    local hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ -s "$hosts_file" ] || return 0
    log_warn "  Running HTTP smuggling detection (opt-in) — timing-based probes only"
    local n=0
    while IFS= read -r u && [ $n -lt 20 ]; do
        [ -z "$u" ] && continue
        n=$((n+1))
        local res; res=$("$SMUGGLER" -u "$u" -q --timeout 6 2>/dev/null || true)
        if printf '%s' "$res" | grep -qiE 'POTENTIALLY VULNERABLE|CL\.TE|TE\.CL'; then
            local host; host=$(printf '%s' "$u" | awk -F/ '{print $3}')
            local variant; variant=$(printf '%s' "$res" | grep -oiE 'CL\.TE|TE\.CL|TE\.TE' | head -1)
            jq -cn --arg url "$u" --arg host "$host" --arg var "$variant" \
                '{check:"smuggling",tool:"smuggler",severity:"high",template:("HTTP request smuggling ("+$var+")"),
                  host:$host,url:$url,parameter:"",evidence:("desync timing signature: "+$var),
                  confidence:"probable",verification:"timing-differential",
                  remediation:"Normalize Content-Length/Transfer-Encoding at the edge; reject ambiguous framing; use HTTP/2 end-to-end.",safe_mode:true}' >> "$out"
        fi
    done < "$hosts_file"
    log_info "  Smuggling findings: $(count_lines "$out")"
}

# Correlate interactsh callbacks back to the SSRF probe that triggered them.
_ext_ssrf_correlate() {
    local callbacks="$1" probe_map="$2" out="$3"
    : > "$out"
    [ -f "$callbacks" ] || return 0
    python3 - "$callbacks" "$probe_map" "$out" << 'CORREOF'
import sys, json
cb, mapfile, out = sys.argv[1:4]
probes = {}
try:
    for line in open(mapfile, errors="ignore"):
        line=line.strip()
        if line:
            d=json.loads(line); probes[d["token"]]=d
except Exception:
    pass
hit = {}
for line in open(cb, errors="ignore"):
    line=line.strip()
    if not line:
        continue
    try:
        rec=json.loads(line)
    except Exception:
        continue
    fqdn=(rec.get("full-id") or rec.get("unique-id") or rec.get("full_id") or "").lower()
    raw=json.dumps(rec).lower()
    proto=rec.get("protocol","dns")
    for token, meta in probes.items():
        if token in fqdn or token in raw:
            key=(token,)
            if key in hit:
                continue
            hit[key]=True
            with open(out,"a") as w:
                w.write(json.dumps({
                    "check":"ssrf","tool":"interactsh","severity":"high",
                    "template":"Blind SSRF (OOB confirmed)",
                    "host":meta.get("host",""),"url":meta.get("url",""),
                    "parameter":meta.get("param",""),
                    "evidence":"server made an out-of-band %s callback to the injected URL" % proto,
                    "confidence":"confirmed","verification":"oob-callback",
                    "remediation":"Validate/allowlist outbound URLs; block link-local & metadata ranges; enforce IMDSv2.",
                    "safe_mode":True})+"\n")
CORREOF
    log_info "  SSRF confirmed (OOB): $(count_lines "$out")"
}

module_extended_checks() {
    local target="$1"
    log_section "MODULE 19: Extended Vulnerability Verification (safe mode)"

    if [ "$EXTENDED_CHECKS_ENABLED" != "true" ]; then
        log_warn "Extended checks disabled (EXTENDED_CHECKS_ENABLED=false)"
        return 0
    fi
    log_info "Mode: $([ "$EXTENDED_SAFE_MODE" = "true" ] && echo "SAFE (confirm only, no exploitation)" || echo "AGGRESSIVE")"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/19_extended_checks"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "extended_checks" "results")"
    local urls_file="$base_dir/param_urls.txt"
    local findings_file="$base_dir/extended_findings.jsonl"
    : > "$findings_file"

    local n_urls; n_urls=$(_ext_collect_param_urls "$urls_file")
    log_info "Candidate parameterized URLs: $n_urls"

    # Per-check output shards.
    local f_ssrf="$base_dir/ssrf.jsonl" f_crlf="$base_dir/crlf.jsonl"
    local f_jwt="$base_dir/jwt.jsonl"   f_ssti="$base_dir/ssti.jsonl"
    local f_gql="$base_dir/graphql.jsonl" f_smug="$base_dir/smuggling.jsonl"

    # 1. SSRF — start OOB oracle, fire probes, correlate.
    if [ "$CHECK_SSRF" = "true" ]; then
        log_info "[1/6] Blind SSRF (interactsh OOB confirmation)..."
        local oob_domain="$base_dir/oob_domain.txt" callbacks="$base_dir/oob_callbacks.jsonl"
        local probe_map="$base_dir/ssrf_probes.jsonl"
        if _ext_start_interactsh "$oob_domain" "$callbacks"; then
            _ext_ssrf "$urls_file" "$oob_domain" "$probe_map" "$f_ssrf"
            log_info "  Waiting ${EXTENDED_OOB_WAIT}s for out-of-band callbacks..."
            sleep "$EXTENDED_OOB_WAIT"
            _ext_stop_interactsh
            _ext_ssrf_correlate "$callbacks" "$probe_map" "$f_ssrf"
        fi
    fi

    # 2-6.
    log_info "[2/6] CRLF injection (crlfuzz)...";       _ext_crlf "$urls_file" "$f_crlf"
    log_info "[3/6] JWT weakness (offline analysis)..."; _ext_jwt "$f_jwt"
    log_info "[4/6] SSTI (sstimap detection)...";        _ext_ssti "$urls_file" "$f_ssti"
    log_info "[5/6] GraphQL (graphw00f)...";             _ext_graphql "$f_gql"
    log_info "[6/6] HTTP smuggling (gated)...";          _ext_smuggling "$f_smug"

    # Merge all shards into the normalized findings file.
    for shard in "$f_ssrf" "$f_crlf" "$f_jwt" "$f_ssti" "$f_gql" "$f_smug"; do
        [ -f "$shard" ] && cat "$shard" >> "$findings_file"
    done

    local total; total=$(count_lines "$findings_file")
    log_info "Extended verification findings: $total (confirmed/probable, safe mode)"
    [ "$total" -gt 0 ] && jq -r '"  [\(.severity)] \(.template) — \(.host) (\(.confidence))"' "$findings_file" 2>/dev/null | head -8 || true
    update_statistics "extended_findings" "$total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "extended_checks",
  "safe_mode": $EXTENDED_SAFE_MODE,
  "extended_findings": $total,
  "checks_run": {"ssrf": "$CHECK_SSRF", "crlf": "$CHECK_CRLF", "jwt": "$CHECK_JWT", "ssti": "$CHECK_SSTI", "graphql": "$CHECK_GRAPHQL", "smuggling": "$CHECK_SMUGGLING"},
  "findings_file": "extended_findings.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Extended vulnerability verification completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 14: REPORTING
###################################################################################################

module_reporting() {
    local target="$1"
    log_section "MODULE 14: Reporting"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/reports/$(make_iso_filename "$target" "report" "final")"
    
    log_info "Generating comprehensive reports..."
    
    # Generate JSON report
    python3 << PYTHON_EOF
import json
import os
import sys
from datetime import datetime

target = "$target"
output_dir = "$OUTPUT_DIR"
reports_dir = "$OUTPUT_DIR/reports"

# Read manifest
manifest = {}
try:
    with open("$MANIFEST_FILE", 'r') as f:
        manifest = json.load(f)
except:
    manifest = {}

# Collect module results from the numbered pipeline directories.
modules = {}
for module_dir in os.listdir(output_dir):
    module_path = os.path.join(output_dir, module_dir)
    if not os.path.isdir(module_path) or module_dir in ('logs', 'reports'):
        continue
    for fname in os.listdir(module_path):
        if fname.endswith('_results.json'):
            with open(os.path.join(module_path, fname), 'r') as f:
                try:
                    data = json.load(f)
                    if isinstance(data, dict):
                        modules[data.get('module', module_dir)] = data
                    else:
                        modules[module_dir] = data
                except (OSError, json.JSONDecodeError):
                    pass

# Build report
report = {
    "report_info": {
        "title": "External Attack Surface Report",
        "target": target,
        "generated": datetime.now().isoformat(),
        "version": "$VERSION"
    },
    "statistics": manifest.get('statistics', {}),
    "modules": modules,
    "hosts_summary": {}
}

# Build hosts summary
for host, data in manifest.get('hosts', {}).items():
    summary = {}
    if 'ip' in data:
        summary['ip'] = data['ip']
    if 'http_status' in data:
        summary['http_status'] = data['http_status']
    if 'waf_vendor' in data:
        summary['waf_vendor'] = data['waf_vendor']
    if 'security_header_score' in data:
        summary['security_score'] = data['security_header_score']
    if 'skip_bruteforce' in data:
        summary['bruteforce_blocked'] = data['skip_bruteforce']
    report['hosts_summary'][host] = summary

# Write report
with open(os.path.join(reports_dir, "report.json"), 'w') as f:
    json.dump(report, f, indent=2)

# Write HTML summary
html = f"""<!DOCTYPE html>
<html><head><title>Attack Surface Report - {target}</title>
<style>
body{{font-family:Arial;margin:20px}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#4CAF50;color:white}}.critical{{color:red}}.warning{{color:orange}}
</style></head><body>
<h1>Attack Surface Report - {target}</h1>
<p>Generated: {datetime.now().isoformat()}</p>
<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Hosts</td><td>{len(manifest.get('hosts', {}))}</td></tr>
<tr><td>Resolved Hosts</td><td>{manifest.get('statistics', {}).get('resolved_hosts', 0)}</td></tr>
<tr><td>HTTP Hosts</td><td>{manifest.get('statistics', {}).get('http_hosts', 0)}</td></tr>
<tr><td>WAF Protected</td><td class="warning">{manifest.get('statistics', {}).get('waf_hosts', 0)}</td></tr>
</table>
<h2>Modules Completed</h2>
<ul>
{"".join(f"<li>{m}</li>" for m in modules.keys())}
</ul>
</body></html>"""

with open(os.path.join(reports_dir, "report.html"), 'w') as f:
    f.write(html)

print("Reports generated successfully")
PYTHON_EOF
    
    # Generate final output filename
    local end_time=$(date +%s)
    
    log_info "Reports generated: report.json, report.html"
    echo "$OUTPUT_DIR/reports"
}
###################################################################################################
# MAIN ORCHESTRATOR
###################################################################################################

usage() {
    echo "Usage: $0 <target_domain> [options]"
    echo ""
    echo "Options:"
    echo "  -s, --skip MODULE   Skip specified module (can be used multiple times)"
    echo "  -o, --output DIR    Output directory"
    echo "  -d, --debug         Enable debug mode"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  PORT_SCAN_MODE      Port scanning mode (default: full)"
    echo "                      - fast: top 1000 ports (recommended, ~5-10 min)"
    echo "                      - default: top 100 ports (fastest, ~2-5 min)"
    echo "                      - full: all 65535 ports (slow, ~1-2 hours)"
    echo "  NAABU_RATE          Packets per second (default: 3000)"
    echo "  NAABU_THREADS       Concurrent threads (default: 100)"
    echo "  PUREDNS_ENABLED     Run active puredns bruteforce (default: true; set false to skip)"
    echo "  PUREDNS_RATE_LIMIT  Public resolver DNS queries/sec (default: 100)"
    echo "  PUREDNS_TRUSTED_RATE_LIMIT Trusted resolver queries/sec (default: 25)"
    echo "  PUREDNS_WORDLIST_LIMIT Max puredns brute-force words (default: 5000)"
    echo "  PUREDNS_RESOLVER_LIMIT Max public resolvers to use (default: 50)"
    echo "  PUREDNS_THREADS     Wildcard filtering threads (default: 10)"
    echo ""
    echo "  CLOUD_ORIGIN_MAX    Max protected hosts to test for origin bypass (default: 25)"
    echo ""
    echo "Modules: asset_discovery, subdomain_enum, dns_resolution, http_discovery,"
    echo "         waf_detection, header_analysis, service_fingerprint, directory_discovery,"
    echo "         crawling, secret_scanning, param_fuzzing, nuclei_scan, xss_testing,"
    echo "         sqli_testing, api_security, full_port_scan, cloud_exposure, reporting"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com -s waf_detection -s param_fuzzing"
    echo "  PORT_SCAN_MODE=full $0 example.com    # Full port scan"
    echo "  NAABU_RATE=5000 $0 example.com        # Faster scanning"
    echo "  PUREDNS_ENABLED=false $0 example.com  # Passive enum only, no DNS bruteforce"
    echo "  PUREDNS_RATE_LIMIT=50 $0 example.com  # Lower Wi-Fi bandwidth usage"
}

main() {
    local target=""
    local skip_modules=()
    local start_time=$(date +%s)
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -s|--skip)
                skip_modules+=("$2")
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -d|--debug)
                DEBUG=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                target="$1"
                shift
                ;;
        esac
    done
    
    # Validate target
    if [ -z "$target" ]; then
        log_error "Target domain required"
        usage
        exit 1
    fi
    if ! printf '%s' "$target" | grep -Eq '^([A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,63}$'; then
        log_error "Invalid target domain: $target"
        exit 1
    fi
    
    log_section "ARISE - Summon Every Hidden Exposure. (v$VERSION)"
    log_info "Target: $target"
    log_info "Start time: $(date)"
    validate_runtime_limits
    
    # Create directories
    create_directories "$target"
    
    # Check dependencies
    check_dependencies || exit 1
    
    # Download wordlists if needed
    download_wordlists
    
    # Initialize manifest
    init_manifest "$target" "$(date +%Y%m%d_%H%M%S)"
    
    # Execute modules
    local module_order=("asset_discovery" "subdomain_enum" "dns_resolution" "http_discovery" \
                       "waf_detection" "crawling" "header_analysis" "directory_discovery" \
                       "secret_scanning" "param_fuzzing" "nuclei_scan" "xss_testing" \
                       "sqli_testing" "api_security" "full_port_scan" "service_fingerprint" \
                       "cloud_exposure" "extended_checks" "reporting")
    
    local pipeline_failed=false
    for module in "${module_order[@]}"; do
        # Check if module should be skipped
        local should_skip=false
        for skip in "${skip_modules[@]}"; do
            if [ "$module" == "$skip" ]; then
                should_skip=true
                break
            fi
        done
        
        if [ "$should_skip" == "true" ]; then
            log_warn "Skipping module: $module"
            continue
        fi
        
        # Execute module
        log_section "EXECUTING: $module"
        
        case $module in
            asset_discovery)
                module_asset_discovery "$target"
                ;;
            subdomain_enum)
                module_subdomain_enum "$target"
                ;;
            dns_resolution)
                module_dns_resolution "$target"
                ;;
            http_discovery)
                module_http_discovery "$target"
                ;;
            waf_detection)
                module_waf_detection "$target"
                ;;
            header_analysis)
                module_header_analysis "$target"
                ;;
            service_fingerprint)
                module_service_fingerprint "$target"
                ;;
            directory_discovery)
                module_directory_discovery "$target"
                ;;
            crawling)
                module_crawling "$target"
                ;;
            secret_scanning)
                module_secret_scanning "$target"
                ;;
            param_fuzzing)
                module_param_fuzzing "$target"
                ;;
            nuclei_scan)
                module_nuclei_scan "$target"
                ;;
            xss_testing)
                module_xss_testing "$target"
                ;;
            sqli_testing)
                module_sqli_testing "$target"
                ;;
            api_security)
                module_api_security "$target"
                ;;
            full_port_scan)
                module_full_port_scan "$target"
                ;;
            cloud_exposure)
                module_cloud_exposure "$target"
                ;;
            extended_checks)
                module_extended_checks "$target"
                ;;
            reporting)
                module_reporting "$target"
                ;;
        esac
        local module_status=$?
        if [ "$module_status" -ne 0 ]; then
            pipeline_failed=true
            log_error "Module failed: $module (exit $module_status)"
        fi
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_section "PIPELINE COMPLETE"
    log_info "Target: $target"
    log_info "Duration: $duration seconds"
    log_info "Results: $OUTPUT_DIR/reports/"
    
    # Update manifest with completion. The dashboard reads this field directly.
    update_statistics "end_time" "\"$(date -Iseconds)\""
    update_statistics "duration_seconds" "$duration"
    local final_status="completed"
    [ "$pipeline_failed" = "true" ] && final_status="completed_with_errors"
    jq --arg status "$final_status" --arg endtime "$(date -Iseconds)" \
        '.pipeline_info.status = $status | .pipeline_info.end_time = $endtime' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && \
        mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
}

# Run main
main "$@"
