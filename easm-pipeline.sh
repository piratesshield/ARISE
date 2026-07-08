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
        jq -r 'select(.status_code != null) | "\(.host)|\(.status_code)"' "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" | \
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
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "header_analysis",
  "hosts_analyzed": $hosts_analyzed,
  "average_score": $avg_score,
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
# MODULE 8: DIRECTORY DISCOVERY WITH WAF-AWARE GATING
###################################################################################################

module_directory_discovery() {
    local target="$1"
    log_section "MODULE 8: Directory Discovery"
    
    local skip_file="$OUTPUT_DIR/05_waf_detection/skip_bruteforce.txt"
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/08_directory_discovery/$(make_iso_filename "$target" "directory_discovery" "results")"
    
    mkdir -p "$OUTPUT_DIR/08_directory_discovery/results"
    
    log_info "Running directory discovery..."
    
    # Check if we have http hosts
    [ ! -f "$http_hosts_file" ] && { log_warn "No HTTP hosts file found"; return 0; }
    
    # Filter out WAF-protected hosts
    local safe_hosts_file="$OUTPUT_DIR/08_directory_discovery/safe_hosts.txt"
    > "$safe_hosts_file"
    
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        local plain_host=$(url_host "$host")
        # Skip if in skip_bruteforce list
        if [ -f "$skip_file" ] && grep -Fqx "$plain_host" "$skip_file" 2>/dev/null; then
            log_debug "Skipping WAF-protected: $host"
            continue
        fi
        echo "$host" >> "$safe_hosts_file"
    done < "$http_hosts_file"
    
    local host_count=$(wc -l < "$safe_hosts_file" | tr -d ' ')
    [ "$host_count" -eq 0 ] && { log_info "All hosts are WAF-protected, skipping directory discovery"; return 0; }
    
    log_info "Found $host_count hosts safe for bruteforce"
    
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
    echo "Modules: asset_discovery, subdomain_enum, dns_resolution, http_discovery,"
    echo "         waf_detection, header_analysis, service_fingerprint, directory_discovery,"
    echo "         crawling, secret_scanning, param_fuzzing, nuclei_scan, xss_testing,"
    echo "         full_port_scan, reporting"
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
                       "waf_detection" "header_analysis" "directory_discovery" "crawling" \
                       "secret_scanning" "param_fuzzing" "nuclei_scan" "xss_testing" \
                       "full_port_scan" "service_fingerprint" "reporting")
    
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
            full_port_scan)
                module_full_port_scan "$target"
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
    jq --arg status "$final_status" --arg end "$(date -Iseconds)" \
        '.pipeline_info.status = $status | .pipeline_info.end_time = $end' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && \
        mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
}

# Run main
main "$@"
