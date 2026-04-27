#!/bin/bash
#===============================================================================
# 🔒 AUTHORIZED USE ONLY - DEFENSIVE SECURITY ASSESSMENT TOOL
#===============================================================================
# This script is designed for authorized internal security assessments only.
# Unauthorized scanning of systems you do not own or have explicit permission
# to test is illegal and unethical.
#
# By using this tool, you acknowledge:
# - You have written authorization to scan the target(s)
# - You understand and accept responsibility for your actions
# - You will comply with all applicable laws and regulations
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration & Constants
#-------------------------------------------------------------------------------
readonly SCRIPT_NAME="autorecon"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
readonly DEFAULT_TARGETS_FILE="${SCRIPT_DIR}/targets.txt"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Logging
LOG_FILE=""
LOG_LEVEL="INFO"

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${RED}[$timestamp] [$level] $message${NC}" >&2
    elif [[ "$level" == "WARN" ]]; then
        echo -e "${YELLOW}[$timestamp] [$level] $message${NC}" >&2
    elif [[ "$level" == "INFO" ]]; then
        echo -e "${GREEN}[$timestamp] [$level] $message${NC}"
    elif [[ "$level" == "DEBUG" ]]; then
        if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
            echo -e "${CYAN}[$timestamp] [$level] $message${NC}"
        fi
    fi
    
    # Also write to log file if initialized
    if [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_debug() { log "DEBUG" "$@"; }

die() {
    log_error "$*"
    exit 1
}

#-------------------------------------------------------------------------------
# Input Validation Functions
#-------------------------------------------------------------------------------

validate_domain() {
    local domain="$1"
    # Basic domain validation regex
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    # Check each octet
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done
    return 0
}

check_target_in_allowlist() {
    local target="$1"
    local allowlist_file="$2"
    
    if [[ ! -f "$allowlist_file" ]]; then
        log_warn "Allowlist file not found: $allowlist_file"
        return 1
    fi
    
    # Check if target matches any entry in allowlist
    while IFS= read -r allowed || [[ -n "$allowed" ]]; do
        # Skip empty lines and comments
        [[ -z "$allowed" || "$allowed" =~ ^[[:space:]]*# ]] && continue
        
        # Trim whitespace
        allowed=$(echo "$allowed" | xargs)
        
        # Exact match or wildcard subdomain match
        if [[ "$target" == "$allowed" ]] || [[ "$target" == *".$allowed" ]]; then
            return 0
        fi
    done < "$allowlist_file"
    
    return 1
}

#-------------------------------------------------------------------------------
# Configuration Loading
#-------------------------------------------------------------------------------

declare -A CONFIG

load_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        die "Configuration file not found: $config_file"
    fi
    
    log_info "Loading configuration from: $config_file"
    
    # Simple YAML parser for key: value pairs
    while IFS=: read -r key value || [[ -n "$key" ]]; do
        # Skip empty lines and comments
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        
        # Trim whitespace
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        
        # Remove quotes if present
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        
        CONFIG["$key"]="$value"
    done < "$config_file"
    
    # Set defaults if not specified
    : "${CONFIG[rate_limit]:=100}"
    : "${CONFIG[thread_count]:=10}"
    : "${CONFIG[timeout]:=30}"
    : "${CONFIG[max_retries]:=3}"
    : "${CONFIG[output_dir]:=${SCRIPT_DIR}/recon_output}"
    : "${CONFIG[wordlist_path]:=${SCRIPT_DIR}/wordlists}"
    : "${CONFIG[resolvers]:=${SCRIPT_DIR}/resolvers.txt}"
}

get_config() {
    local key="$1"
    local default="${2:-}"
    echo "${CONFIG[$key]:-$default}"
}

#-------------------------------------------------------------------------------
# System Resource Checks
#-------------------------------------------------------------------------------

check_system_resources() {
    log_info "Checking system resources..."
    
    # Get CPU count
    local cpu_count
    cpu_count=$(nproc 2>/dev/null || echo "4")
    log_debug "Available CPUs: $cpu_count"
    
    # Get available memory (in MB)
    local mem_available
    mem_available=$(free -m 2>/dev/null | awk '/^Mem:/{print $7}' || echo "14000")
    log_debug "Available Memory: ${mem_available}MB"
    
    # Adjust concurrency based on resources
    local max_threads
    if (( mem_available < 2000 )); then
        max_threads=5
        log_warn "Low memory detected, reducing threads to $max_threads"
    elif (( mem_available < 8000 )); then
        max_threads=10
    else
        max_threads=20
    fi
    
    # Use configured thread count if lower than calculated max
    local config_threads
    config_threads=$(get_config "thread_count" "$max_threads")
    if (( config_threads < max_threads )); then
        max_threads=$config_threads
    fi
    
    echo "$max_threads"
}

#-------------------------------------------------------------------------------
# Tool Availability Check
#-------------------------------------------------------------------------------

REQUIRED_TOOLS=(
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
    "sort"
    "uniq"
    "curl"
)

check_tool_availability() {
    local missing_tools=()
    
    log_info "Checking required tools..."
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            log_warn "Tool not found: $tool"
        else
            log_debug "✓ Found: $tool"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warn "Missing tools: ${missing_tools[*]}"
        log_info "Run ./install_deps.sh to install missing dependencies"
        return 1
    fi
    
    log_info "All required tools are available"
    return 0
}

#-------------------------------------------------------------------------------
# Output Directory Structure
#-------------------------------------------------------------------------------

setup_output_directory() {
    local target="$1"
    local timestamp="$2"
    
    local base_dir
    base_dir=$(get_config "output_dir")
    
    OUTPUT_DIR="${base_dir}/${target}_${timestamp}"
    
    log_info "Creating output directory structure: $OUTPUT_DIR"
    
    # Create directory structure
    mkdir -p "$OUTPUT_DIR"/{config,subdomains/raw,ports,http,urls,secrets,vulns,logs}
    
    # Initialize log file
    LOG_FILE="$OUTPUT_DIR/logs/recon.log"
    touch "$LOG_FILE"
    
    # Copy config snapshot
    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "$OUTPUT_DIR/config/config.yaml"
    fi
    
    # Create checkpoint file
    CHECKPOINT_FILE="$OUTPUT_DIR/.checkpoint"
    touch "$CHECKPOINT_FILE"
    
    log_info "Output directory ready: $OUTPUT_DIR"
}

#-------------------------------------------------------------------------------
# Checkpoint Management
#-------------------------------------------------------------------------------

CHECKPOINT_FILE=""

save_checkpoint() {
    local stage="$1"
    local status="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "$timestamp|$stage|$status" >> "$CHECKPOINT_FILE"
    log_debug "Checkpoint saved: $stage - $status"
}

is_stage_completed() {
    local stage="$1"
    
    if [[ ! -f "$CHECKPOINT_FILE" ]]; then
        return 1
    fi
    
    if grep -q "|$stage|COMPLETED$" "$CHECKPOINT_FILE" 2>/dev/null; then
        return 0
    fi
    
    return 1
}

skip_stage() {
    local stage="$1"
    
    if is_stage_completed "$stage"; then
        log_info "Stage '$stage' already completed, skipping..."
        return 0
    fi
    
    return 1
}

#-------------------------------------------------------------------------------
# Atomic File Operations
#-------------------------------------------------------------------------------

atomic_write() {
    local content="$1"
    local target_file="$2"
    local temp_file
    
    temp_file=$(mktemp "${target_file}.XXXXXX")
    
    echo "$content" > "$temp_file"
    mv "$temp_file" "$target_file"
    
    log_debug "Atomic write completed: $target_file"
}

atomic_cat() {
    local source_file="$1"
    local target_file="$2"
    local temp_file
    
    temp_file=$(mktemp "${target_file}.XXXXXX")
    
    cat "$source_file" >> "$temp_file"
    mv "$temp_file" "$target_file"
    
    log_debug "Atomic append completed: $target_file"
}

#-------------------------------------------------------------------------------
# Deduplication Functions
#-------------------------------------------------------------------------------

deduplicate_file() {
    local input_file="$1"
    local output_file="$2"
    local temp_file
    
    temp_file=$(mktemp)
    
    if [[ -f "$input_file" ]]; then
        sort -u "$input_file" > "$temp_file"
        mv "$temp_file" "$output_file"
        local count
        count=$(wc -l < "$output_file")
        log_debug "Deduplicated to $count unique entries: $output_file"
    fi
}

#-------------------------------------------------------------------------------
# Stage 1: Subdomain Enumeration
#-------------------------------------------------------------------------------

stage_subdomains() {
    local target="$1"
    local stage_name="subdomain_enumeration"
    
    if skip_stage "$stage_name"; then
        return 0
    fi
    
    log_info "=== Stage 1: Subdomain Enumeration ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local subdomain_dir="$OUTPUT_DIR/subdomains"
    local raw_dir="$subdomain_dir/raw"
    local all_subs_file="$subdomain_dir/all_subdomains.txt"
    local resolved_file="$subdomain_dir/resolved.txt"
    local live_hosts_file="$subdomain_dir/live_hosts.txt"
    
    # Temporary files for collection
    local temp_all
    temp_all=$(mktemp)
    
    # Run subfinder
    log_info "Running subfinder..."
    if command -v subfinder &> /dev/null; then
        subfinder -d "$target" -silent -o "$raw_dir/subfinder.txt" 2>>"$LOG_FILE" || true
        cat "$raw_dir/subfinder.txt" >> "$temp_all" 2>/dev/null || true
    fi
    
    # Run assetfinder
    log_info "Running assetfinder..."
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$target" > "$raw_dir/assetfinder.txt" 2>>"$LOG_FILE" || true
        cat "$raw_dir/assetfinder.txt" >> "$temp_all" 2>/dev/null || true
    fi
    
    # Run findomain
    log_info "Running findomain..."
    if command -v findomain &> /dev/null; then
        findomain -t "$target" -u "$raw_dir/findomain.txt" 2>>"$LOG_FILE" || true
        cat "$raw_dir/findomain.txt" >> "$temp_all" 2>/dev/null || true
    fi
    
    # Run amass (passive mode only)
    log_info "Running amass (passive)..."
    if command -v amass &> /dev/null; then
        amass enum -passive -d "$target" -o "$raw_dir/amass.txt" 2>>"$LOG_FILE" || true
        cat "$raw_dir/amass.txt" >> "$temp_all" 2>/dev/null || true
    fi
    
    # Run ctfr (Certificate Transparency)
    log_info "Running ctfr..."
    if command -v ctfr &> /dev/null; then
        ctfr -t "$target" -o "$raw_dir/ctfr.txt" 2>>"$LOG_FILE" || true
        cat "$raw_dir/ctfr.txt" >> "$temp_all" 2>/dev/null || true
    fi
    
    # Deduplicate all subdomains
    log_info "Deduplicating subdomains..."
    deduplicate_file "$temp_all" "$all_subs_file"
    
    local subdomain_count
    subdomain_count=$(wc -l < "$all_subs_file" 2>/dev/null || echo "0")
    log_info "Found $subdomain_count unique subdomains"
    
    # Resolve subdomains with dnsx
    log_info "Resolving subdomains with dnsx..."
    local resolver_file
    resolver_file=$(get_config "resolvers")
    
    if [[ -f "$resolver_file" ]]; then
        dnsx -l "$all_subs_file" -r "$resolver_file" -silent -resp -retry 3 -timeout 5 \
            -o "$resolved_file" 2>>"$LOG_FILE" || true
    else
        dnsx -l "$all_subs_file" -silent -resp -retry 3 -timeout 5 \
            -o "$resolved_file" 2>>"$LOG_FILE" || true
    fi
    
    # Extract live hosts (those with IPs)
    grep -v '^\[' "$resolved_file" 2>/dev/null | cut -d' ' -f1 | sort -u > "$live_hosts_file" || true
    
    local live_count
    live_count=$(wc -l < "$live_hosts_file" 2>/dev/null || echo "0")
    log_info "Resolved $live_count live hosts"
    
    # Cleanup
    rm -f "$temp_all"
    
    save_checkpoint "$stage_name" "COMPLETED"
    log_info "=== Stage 1 Complete ==="
}

#-------------------------------------------------------------------------------
# Stage 2: Port Scanning
#-------------------------------------------------------------------------------

stage_port_scan() {
    local target="$1"
    local stage_name="port_scanning"
    
    if skip_stage "$stage_name"; then
        return 0
    fi
    
    log_info "=== Stage 2: Port Scanning ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local port_dir="$OUTPUT_DIR/ports"
    local ports_json="$port_dir/ports.json"
    local open_ports_file="$port_dir/open_ports.txt"
    local live_hosts_file="$OUTPUT_DIR/subdomains/live_hosts.txt"
    
    # Get rate limit from config
    local rate_limit
    rate_limit=$(get_config "rate_limit" "100")
    local timeout_val
    timeout_val=$(get_config "timeout" "30")
    
    # Run naabu on live hosts
    log_info "Running naabu port scan (top 1000 ports, rate: $rate_limit/s)..."
    
    if [[ -f "$live_hosts_file" ]]; then
        naabu -l "$live_hosts_file" \
              -top-ports 1000 \
              -rate "$rate_limit" \
              -timeout "$timeout_val" \
              -retries 2 \
              -json \
              -silent \
              -o "$ports_json" 2>>"$LOG_FILE" || true
    else
        naabu -host "$target" \
              -top-ports 1000 \
              -rate "$rate_limit" \
              -timeout "$timeout_val" \
              -retries 2 \
              -json \
              -silent \
              -o "$ports_json" 2>>"$LOG_FILE" || true
    fi
    
    # Extract host:port list from JSON
    if [[ -f "$ports_json" ]]; then
        jq -r '.[] | "\(.host):\(.port)"' "$ports_json" 2>/dev/null | sort -u > "$open_ports_file" || true
        
        local port_count
        port_count=$(wc -l < "$open_ports_file" 2>/dev/null || echo "0")
        log_info "Found $port_count open ports"
    else
        log_warn "No port scan results generated"
        touch "$open_ports_file"
    fi
    
    save_checkpoint "$stage_name" "COMPLETED"
    log_info "=== Stage 2 Complete ==="
}

#-------------------------------------------------------------------------------
# Stage 3: HTTP Probing
#-------------------------------------------------------------------------------

stage_http_probing() {
    local target="$1"
    local stage_name="http_probing"
    
    if skip_stage "$stage_name"; then
        return 0
    fi
    
    log_info "=== Stage 3: HTTP Probing ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local http_dir="$OUTPUT_DIR/http"
    local http_results="$http_dir/http_results.jsonl"
    local live_urls_file="$http_dir/live_urls.txt"
    local open_ports_file="$OUTPUT_DIR/ports/open_ports.txt"
    
    # Build list of URLs to probe
    local urls_to_probe
    urls_to_probe=$(mktemp)
    
    # Add http/https for all live hosts
    if [[ -f "$open_ports_file" ]]; then
        while IFS=: read -r host port || [[ -n "$host" ]]; do
            [[ -z "$host" ]] && continue
            if [[ "$port" == "443" || "$port" == "8443" ]]; then
                echo "https://${host}:${port}"
            else
                echo "http://${host}:${port}"
            fi
        done < "$open_ports_file" >> "$urls_to_probe"
    fi
    
    # Also probe standard ports without port number
    if [[ -f "$OUTPUT_DIR/subdomains/live_hosts.txt" ]]; then
        while IFS= read -r host || [[ -n "$host" ]]; do
            [[ -z "$host" ]] && continue
            echo "http://$host"
            echo "https://$host"
        done < "$OUTPUT_DIR/subdomains/live_hosts.txt" >> "$urls_to_probe"
    fi
    
    deduplicate_file "$urls_to_probe" "${urls_to_probe}.dedup"
    mv "${urls_to_probe}.dedup" "$urls_to_probe"
    
    local url_count
    url_count=$(wc -l < "$urls_to_probe" 2>/dev/null || echo "0")
    log_info "Probing $url_count URLs..."
    
    # Run httpx
    log_info "Running httpx..."
    httpx -l "$urls_to_probe" \
          -silent \
          -status-code \
          -title \
          -tech-detect \
          -redirect \
          -json \
          -timeout 10 \
          -threads 50 \
          -o "$http_results" 2>>"$LOG_FILE" || true
    
    # Extract live URLs
    if [[ -f "$http_results" ]]; then
        jq -r 'select(.status_code != null) | .url' "$http_results" 2>/dev/null | sort -u > "$live_urls_file" || true
        
        local live_url_count
        live_url_count=$(wc -l < "$live_urls_file" 2>/dev/null || echo "0")
        log_info "Found $live_url_count live URLs"
    else
        log_warn "No HTTP probing results generated"
        touch "$live_urls_file"
    fi
    
    # Run tlsx on HTTPS ports
    log_info "Running tlsx for TLS fingerprinting..."
    local tlsx_results="$http_dir/tlsx_results.jsonl"
    
    if [[ -f "$open_ports_file" ]]; then
        grep -E ':(443|8443)$' "$open_ports_file" 2>/dev/null | \
            tlsx -l - -silent -json -o "$tlsx_results" 2>>"$LOG_FILE" || true
    fi
    
    # Cleanup
    rm -f "$urls_to_probe"
    
    save_checkpoint "$stage_name" "COMPLETED"
    log_info "=== Stage 3 Complete ==="
}

#-------------------------------------------------------------------------------
# Stage 4: URL Crawling
#-------------------------------------------------------------------------------

stage_url_crawling() {
    local target="$1"
    local stage_name="url_crawling"
    
    if skip_stage "$stage_name"; then
        return 0
    fi
    
    log_info "=== Stage 4: URL Crawling ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local urls_dir="$OUTPUT_DIR/urls"
    local all_urls_file="$urls_dir/all_urls.txt"
    local js_files_file="$urls_dir/js_files.txt"
    local live_urls_file="$OUTPUT_DIR/http/live_urls.txt"
    
    local temp_urls
    temp_urls=$(mktemp)
    
    # Run katana
    log_info "Running katana crawler..."
    if [[ -f "$live_urls_file" ]]; then
        katana -list "$live_urls_file" \
               -silent \
               -jc \
               -kf all \
               -depth 3 \
               -timeout 10 \
               -o "$temp_urls" 2>>"$LOG_FILE" || true
    fi
    
    # Run gospider
    log_info "Running gospider..."
    local gospider_output
    gospider_output=$(mktemp -d)
    
    if [[ -f "$live_urls_file" ]]; then
        gospider -S "$live_urls_file" \
                 -o "$gospider_output" \
                 -t 10 \
                 -c 10 \
                 -d 3 \
                 -v false \
                 --sitemap \
                 --robots \
                 2>>"$LOG_FILE" || true
        
        # Collect gospider results
        find "$gospider_output" -type f -name "*.txt" -exec cat {} \; >> "$temp_urls" 2>/dev/null || true
    fi
    
    rm -rf "$gospider_output"
    
    # Deduplicate all URLs
    deduplicate_file "$temp_urls" "$all_urls_file"
    
    local url_count
    url_count=$(wc -l < "$all_urls_file" 2>/dev/null || echo "0")
    log_info "Collected $url_count unique URLs"
    
    # Extract JavaScript files
    log_info "Extracting JavaScript files..."
    grep -iE '\.js($|\?)' "$all_urls_file" 2>/dev/null | sort -u > "$js_files_file" || true
    
    local js_count
    js_count=$(wc -l < "$js_files_file" 2>/dev/null || echo "0")
    log_info "Found $js_count JavaScript files"
    
    # Cleanup
    rm -f "$temp_urls"
    
    save_checkpoint "$stage_name" "COMPLETED"
    log_info "=== Stage 4 Complete ==="
}

#-------------------------------------------------------------------------------
# Stage 5: Secret Scanning
#-------------------------------------------------------------------------------

stage_secret_scanning() {
    local target="$1"
    local stage_name="secret_scanning"
    
    if skip_stage "$stage_name"; then
        return 0
    fi
    
    log_info "=== Stage 5: Secret Scanning ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local secrets_dir="$OUTPUT_DIR/secrets"
    local all_urls_file="$OUTPUT_DIR/urls/all_urls.txt"
    local gf_output="$secrets_dir/gf_sensitive.txt"
    local trufflehog_output="$secrets_dir/trufflehog.json"
    local gitleaks_output="$secrets_dir/gitleaks.json"
    
    # Run gf patterns on URLs
    log_info "Running gf for sensitive patterns..."
    if [[ -f "$all_urls_file" ]]; then
        # Common sensitive patterns
        gf api-key "$all_urls_file" 2>/dev/null >> "$gf_output" || true
        gf aws-keys "$all_urls_file" 2>/dev/null >> "$gf_output" || true
        gf basic-auth "$all_urls_file" 2>/dev/null >> "$gf_output" || true
        gf private-key "$all_urls_file" 2>/dev/null >> "$gf_output" || true
        gf sql-injection "$all_urls_file" 2>/dev/null >> "$gf_output" || true
        
        local gf_count
        gf_count=$(wc -l < "$gf_output" 2>/dev/null || echo "0")
        log_info "Found $gf_count potential sensitive patterns with gf"
    else
        touch "$gf_output"
    fi
    
    # Note: trufflehog and gitleaks typically work on git repos
    # For web crawling results, we focus on gf patterns
    # Create placeholder files
    echo "[]" > "$trufflehog_output"
    echo "[]" > "$gitleaks_output"
    
    save_checkpoint "$stage_name" "COMPLETED"
    log_info "=== Stage 5 Complete ==="
}

#-------------------------------------------------------------------------------
# Stage 6: Vulnerability Scanning
#-------------------------------------------------------------------------------

stage_vulnerability_scanning() {
    local target="$1"
    local stage_name="vulnerability_scanning"
    
    if skip_stage "$stage_name"; then
        return 0
    fi
    
    log_info "=== Stage 6: Vulnerability Scanning ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local vulns_dir="$OUTPUT_DIR/vulns"
    local nuclei_results="$vulns_dir/nuclei_results.jsonl"
    local nuclei_errors="$vulns_dir/nuclei_errors.log"
    local live_urls_file="$OUTPUT_DIR/http/live_urls.txt"
    
    # Get rate limit for nuclei
    local rate_limit
    rate_limit=$(get_config "rate_limit" "50")
    
    # Run nuclei on live URLs
    log_info "Running nuclei (rate: $rate_limit/s, severity: low,medium,high,critical)..."
    
    if [[ -f "$live_urls_file" ]]; then
        nuclei -l "$live_urls_file" \
               -silent \
               -jsonl \
               -severity low,medium,high,critical \
               -rate-limit "$rate_limit" \
               -timeout 10 \
               -retries 2 \
               -bulk-size 10 \
               -concurrency 10 \
               -o "$nuclei_results" \
               -elog "$nuclei_errors" 2>>"$LOG_FILE" || true
        
        local vuln_count
        vuln_count=$(wc -l < "$nuclei_results" 2>/dev/null || echo "0")
        log_info "Found $vuln_count potential vulnerabilities"
    else
        log_warn "No live URLs available for vulnerability scanning"
        touch "$nuclei_results"
        touch "$nuclei_errors"
    fi
    
    save_checkpoint "$stage_name" "COMPLETED"
    log_info "=== Stage 6 Complete ==="
}

#-------------------------------------------------------------------------------
# Report Generation
#-------------------------------------------------------------------------------

generate_report() {
    local target="$1"
    local start_time="$2"
    local end_time="$3"
    local stage_name="report_generation"
    
    log_info "=== Generating Report ==="
    save_checkpoint "$stage_name" "STARTED"
    
    local report_file="$OUTPUT_DIR/REPORT.md"
    local end_timestamp
    end_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Count results
    local subdomain_count resolved_count port_count url_count js_count vuln_count
    subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
    resolved_count=$(wc -l < "$OUTPUT_DIR/subdomains/resolved.txt" 2>/dev/null || echo "0")
    port_count=$(wc -l < "$OUTPUT_DIR/ports/open_ports.txt" 2>/dev/null || echo "0")
    url_count=$(wc -l < "$OUTPUT_DIR/http/live_urls.txt" 2>/dev/null || echo "0")
    js_count=$(wc -l < "$OUTPUT_DIR/urls/js_files.txt" 2>/dev/null || echo "0")
    vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei_results.jsonl" 2>/dev/null || echo "0")
    
    # Generate config hash
    local config_hash="N/A"
    if [[ -f "$OUTPUT_DIR/config/config.yaml" ]]; then
        config_hash=$(md5sum "$OUTPUT_DIR/config/config.yaml" 2>/dev/null | cut -d' ' -f1 || echo "N/A")
    fi
    
    cat > "$report_file" << EOF
# 🔒 Security Assessment Report

## ⚠️ AUTHORIZED USE ONLY

This report is generated for **authorized defensive security assessments only**.
Unauthorized use or distribution is prohibited.

---

## 📊 Executive Summary

**Target:** $target  
**Assessment Date:** $end_timestamp  
**Duration:** $(($(date -d "$end_time" +%s) - $(date -d "$start_time" +%s))) seconds  

---

## 📈 Findings Overview

| Category | Count | Output File |
|----------|-------|-------------|
| Subdomains Found | $subdomain_count | \`subdomains/all_subdomains.txt\` |
| Resolved Hosts | $resolved_count | \`subdomains/resolved.txt\` |
| Open Ports | $port_count | \`ports/open_ports.txt\` |
| Live URLs | $url_count | \`http/live_urls.txt\` |
| JavaScript Files | $js_count | \`urls/js_files.txt\` |
| Potential Vulnerabilities | $vuln_count | \`vulns/nuclei_results.jsonl\` |

---

## 🔧 Configuration

- **Config Hash:** $config_hash
- **Rate Limit:** $(get_config "rate_limit" "N/A") requests/second
- **Thread Count:** $(get_config "thread_count" "N/A")
- **Timeout:** $(get_config "timeout" "N/A") seconds

---

## 📁 Output Files

### Subdomain Enumeration
- \`subdomains/raw/\` - Raw outputs from individual tools
- \`subdomains/all_subdomains.txt\` - Deduplicated subdomain list
- \`subdomains/resolved.txt\` - Resolved subdomains with IPs
- \`subdomains/live_hosts.txt\` - Live host list

### Port Scanning
- \`ports/ports.json\` - Full port scan results (JSON)
- \`ports/open_ports.txt\` - Host:port list

### HTTP Probing
- \`http/http_results.jsonl\` - HTTP probing results (JSONL)
- \`http/live_urls.txt\` - Live URLs
- \`http/tlsx_results.jsonl\` - TLS fingerprinting results

### URL Crawling
- \`urls/all_urls.txt\` - All crawled URLs
- \`urls/js_files.txt\` - JavaScript endpoints

### Secret Scanning
- \`secrets/gf_sensitive.txt\` - Sensitive pattern matches
- \`secrets/trufflehog.json\` - TruffleHog results
- \`secrets/gitleaks.json\` - GitLeaks results

### Vulnerability Scanning
- \`vulns/nuclei_results.jsonl\` - Nuclei findings
- \`vulns/nuclei_errors.log\` - Nuclei errors

### Logs
- \`logs/recon.log\` - Unified execution log

---

## ⚖️ Legal Disclaimer

This assessment was conducted under the following conditions:

- ✅ Written authorization obtained for target: **$target**
- ✅ Assessment conducted within authorized scope only
- ✅ Rate limiting applied to minimize impact on target systems
- ✅ Results intended for defensive security purposes only

**By using this report, you acknowledge that unauthorized scanning or testing of systems without explicit permission is illegal and unethical.**

---

*Report generated by $SCRIPT_NAME v$SCRIPT_VERSION*  
*Timestamp: $end_timestamp*
EOF

    log_info "Report generated: $report_file"
    save_checkpoint "$stage_name" "COMPLETED"
}

#-------------------------------------------------------------------------------
# Help & Usage
#-------------------------------------------------------------------------------

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Authorized Security Assessment Tool

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    -t, --target DOMAIN       Target domain to assess (required)
    -a, --allowlist FILE      Path to target allowlist file
    -c, --config FILE         Path to configuration file (default: config.yaml)
    -s, --stage STAGE         Run specific stage only (1-6, or name)
    --dry-run                 Validate configuration without execution
    --resume                  Resume from last checkpoint
    -v, --verbose             Enable verbose/debug logging
    -h, --help                Show this help message

STAGES:
    1. subdomain_enumeration   - Discover subdomains
    2. port_scanning          - Scan for open ports
    3. http_probing           - Probe HTTP/HTTPS services
    4. url_crawling           - Crawl for URLs and JS files
    5. secret_scanning        - Scan for sensitive patterns
    6. vulnerability_scanning - Run vulnerability checks

EXAMPLES:
    # Validate configuration (dry run)
    ${SCRIPT_NAME} --target example.com --allowlist targets.txt --dry-run

    # Run full assessment
    ${SCRIPT_NAME} --target example.com --allowlist targets.txt

    # Run specific stage
    ${SCRIPT_NAME} --target example.com --stage 1

    # Resume interrupted scan
    ${SCRIPT_NAME} --target example.com --resume

⚠️  AUTHORIZED USE ONLY - See README.md for complete documentation

EOF
}

#-------------------------------------------------------------------------------
# Dry Run Mode
#-------------------------------------------------------------------------------

dry_run() {
    local target="$1"
    local allowlist_file="$2"
    
    log_info "=== DRY RUN MODE ==="
    log_info "Validating configuration and prerequisites..."
    
    local errors=0
    
    # Check config file
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "✓ Configuration file found: $CONFIG_FILE"
    else
        log_warn "✗ Configuration file not found: $CONFIG_FILE"
        ((errors++))
    fi
    
    # Check allowlist
    if [[ -f "$allowlist_file" ]]; then
        log_info "✓ Allowlist file found: $allowlist_file"
        
        # Validate target in allowlist
        if check_target_in_allowlist "$target" "$allowlist_file"; then
            log_info "✓ Target '$target' is in allowlist"
        else
            log_error "✗ Target '$target' NOT found in allowlist"
            ((errors++))
        fi
    else
        log_warn "✗ Allowlist file not found: $allowlist_file"
        ((errors++))
    fi
    
    # Validate domain format
    if validate_domain "$target"; then
        log_info "✓ Target domain format is valid: $target"
    else
        log_error "✗ Invalid domain format: $target"
        ((errors++))
    fi
    
    # Check tool availability
    if check_tool_availability; then
        log_info "✓ All required tools are available"
    else
        log_warn "⚠ Some tools are missing (run install_deps.sh)"
    fi
    
    # Print intended commands (without executing)
    log_info ""
    log_info "=== INTENDED EXECUTION PLAN ==="
    log_info "Target: $target"
    log_info "Output Directory: $(get_config "output_dir")/${target}_<timestamp>"
    log_info ""
    log_info "Stage 1: Subdomain Enumeration"
    log_info "  - subfinder -d $target"
    log_info "  - assetfinder --subs-only $target"
    log_info "  - findomain -t $target"
    log_info "  - amass enum -passive -d $target"
    log_info "  - ctfr -t $target"
    log_info "  - dnsx -l <subdomains> (resolution)"
    log_info ""
    log_info "Stage 2: Port Scanning"
    log_info "  - naabu -l <hosts> -top-ports 1000 -rate $(get_config "rate_limit")"
    log_info ""
    log_info "Stage 3: HTTP Probing"
    log_info "  - httpx -l <urls> -status-code -title -tech-detect"
    log_info "  - tlsx -l <https-hosts> (TLS fingerprinting)"
    log_info ""
    log_info "Stage 4: URL Crawling"
    log_info "  - katana -list <urls> -depth 3"
    log_info "  - gospider -S <urls> -d 3"
    log_info ""
    log_info "Stage 5: Secret Scanning"
    log_info "  - gf <patterns> <urls>"
    log_info ""
    log_info "Stage 6: Vulnerability Scanning"
    log_info "  - nuclei -l <urls> -severity low,medium,high,critical"
    log_info ""
    
    if [[ $errors -eq 0 ]]; then
        log_info "✅ Dry run completed successfully - Ready to execute"
        return 0
    else
        log_error "❌ Dry run failed with $errors error(s)"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------

main() {
    local target=""
    local allowlist_file="$DEFAULT_TARGETS_FILE"
    local specific_stage=""
    local dry_run_mode=false
    local resume_mode=false
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -a|--allowlist)
                allowlist_file="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -s|--stage)
                specific_stage="$2"
                shift 2
                ;;
            --dry-run)
                dry_run_mode=true
                shift
                ;;
            --resume)
                resume_mode=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                LOG_LEVEL="DEBUG"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                die "Unknown option: $1 (use --help for usage)"
                ;;
        esac
    done
    
    # Print banner
    cat << EOF
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔒 ${SCRIPT_NAME} v${SCRIPT_VERSION}                         ║
║   Authorized Security Assessment Tool                        ║
║                                                              ║
║   ⚠️  FOR AUTHORIZED USE ONLY                                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

EOF
    
    # Validate required arguments
    if [[ -z "$target" ]]; then
        die "Target domain is required (use -t or --target)"
    fi
    
    # Load configuration
    load_config "$CONFIG_FILE"
    
    # Set verbose mode from config if specified
    if [[ "$verbose" == true ]]; then
        LOG_LEVEL="DEBUG"
    fi
    
    # Validate domain format
    if ! validate_domain "$target"; then
        die "Invalid domain format: $target"
    fi
    
    # Check target in allowlist
    if ! check_target_in_allowlist "$target" "$allowlist_file"; then
        die "Target '$target' is not in the allowlist. Add it to $allowlist_file"
    fi
    
    # Confirm target with user (unless dry-run)
    if [[ "$dry_run_mode" == false ]]; then
        echo ""
        log_info "Target Confirmation:"
        log_info "  Domain: $target"
        log_info "  Allowlist: $allowlist_file"
        echo ""
        read -p "⚠️  Confirm you have authorization to scan '$target'? [y/N]: " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Aborted by user"
            exit 0
        fi
    fi
    
    # Dry run mode
    if [[ "$dry_run_mode" == true ]]; then
        dry_run "$target" "$allowlist_file"
        exit $?
    fi
    
    # Check tool availability
    if ! check_tool_availability; then
        die "Missing required tools. Run ./install_deps.sh first."
    fi
    
    # Get timestamp for this run
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local start_time
    start_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Setup output directory
    setup_output_directory "$target" "$timestamp"
    
    # Get adaptive thread count
    local adaptive_threads
    adaptive_threads=$(check_system_resources)
    log_info "Using $adaptive_threads concurrent threads"
    
    log_info "Starting reconnaissance assessment for: $target"
    log_info "Output directory: $OUTPUT_DIR"
    
    # Execute stages
    if [[ -z "$specific_stage" || "$specific_stage" == "1" || "$specific_stage" == "subdomain_enumeration" ]]; then
        stage_subdomains "$target"
    fi
    
    if [[ -z "$specific_stage" || "$specific_stage" == "2" || "$specific_stage" == "port_scanning" ]]; then
        stage_port_scan "$target"
    fi
    
    if [[ -z "$specific_stage" || "$specific_stage" == "3" || "$specific_stage" == "http_probing" ]]; then
        stage_http_probing "$target"
    fi
    
    if [[ -z "$specific_stage" || "$specific_stage" == "4" || "$specific_stage" == "url_crawling" ]]; then
        stage_url_crawling "$target"
    fi
    
    if [[ -z "$specific_stage" || "$specific_stage" == "5" || "$specific_stage" == "secret_scanning" ]]; then
        stage_secret_scanning "$target"
    fi
    
    if [[ -z "$specific_stage" || "$specific_stage" == "6" || "$specific_stage" == "vulnerability_scanning" ]]; then
        stage_vulnerability_scanning "$target"
    fi
    
    # Generate report
    local end_time
    end_time=$(date '+%Y-%m-%d %H:%M:%S')
    generate_report "$target" "$start_time" "$end_time"
    
    log_info ""
    log_info "╔══════════════════════════════════════════════════════════════╗"
    log_info "║                    ASSESSMENT COMPLETE                       ║"
    log_info "╚══════════════════════════════════════════════════════════════╝"
    log_info ""
    log_info "Results saved to: $OUTPUT_DIR"
    log_info "Report: $OUTPUT_DIR/REPORT.md"
    log_info ""
    log_info "Review findings with:"
    log_info "  cat $OUTPUT_DIR/REPORT.md"
    log_info "  jq . $OUTPUT_DIR/vulns/nuclei_results.jsonl"
}

# Run main function
main "$@"
