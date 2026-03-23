#!/usr/bin/env bash
# ioc_enrichment.sh — Enrich IPs, domains, and file hashes via VirusTotal API
#
# Designed for SOC analysts triaging alerts from this portfolio:
# - DET-001, DET-002, DET-006: IP address enrichment
# - DET-003, DET-005: hash enrichment for suspicious processes
# - DET-007, DET-009: domain enrichment for LLM/tunnel infrastructure
#
# Usage:
#   export VT_API_KEY="your_virustotal_api_key"
#   ./ioc_enrichment.sh --ip 198.51.100.42
#   ./ioc_enrichment.sh --hash d41d8cd98f00b204e9800998ecf8427e
#   ./ioc_enrichment.sh --domain suspicious-domain.com
#   ./ioc_enrichment.sh --file iocs.txt         # Bulk from file (one IOC per line)
#
# Requirements: curl, jq
# Free VT API: 4 lookups/min, 500/day. Rate limiting is handled automatically.
#
# Output: JSON summary to stdout + enriched_iocs.json for downstream use.

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
VT_API_KEY="${VT_API_KEY:-}"
VT_BASE="https://www.virustotal.com/api/v3"
RATE_LIMIT_SLEEP=16   # seconds between requests (free tier: 4/min = 15s + buffer)
OUTPUT_FILE="enriched_iocs.json"

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No color

# ── Helpers ────────────────────────────────────────────────────────────────────
log()  { echo -e "${BLUE}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

check_deps() {
    local missing=()
    for dep in curl jq; do
        command -v "$dep" &>/dev/null || missing+=("$dep")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required tools: ${missing[*]}"
        err "Install with: brew install ${missing[*]}"
        exit 1
    fi
}

check_api_key() {
    if [[ -z "$VT_API_KEY" ]]; then
        err "VT_API_KEY environment variable not set."
        err "Get a free key at https://www.virustotal.com/gui/join-us"
        err "Then: export VT_API_KEY='your_key_here'"
        exit 1
    fi
}

# ── VT API Calls ───────────────────────────────────────────────────────────────
vt_get() {
    local endpoint="$1"
    curl -s --max-time 30 \
        -H "x-apikey: ${VT_API_KEY}" \
        "${VT_BASE}/${endpoint}"
}

# ── Enrichment Functions ───────────────────────────────────────────────────────
enrich_ip() {
    local ip="$1"
    log "Enriching IP: ${ip}"

    local response
    response=$(vt_get "ip_addresses/${ip}")

    if echo "$response" | jq -e '.error' &>/dev/null; then
        err "VT error for IP ${ip}: $(echo "$response" | jq -r '.error.message')"
        return 1
    fi

    local malicious harmless suspicious undetected reputation country asn
    malicious=$(echo "$response"    | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    harmless=$(echo "$response"     | jq -r '.data.attributes.last_analysis_stats.harmless // 0')
    suspicious=$(echo "$response"   | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
    undetected=$(echo "$response"   | jq -r '.data.attributes.last_analysis_stats.undetected // 0')
    reputation=$(echo "$response"   | jq -r '.data.attributes.reputation // 0')
    country=$(echo "$response"      | jq -r '.data.attributes.country // "Unknown"')
    asn=$(echo "$response"          | jq -r '.data.attributes.asn // "Unknown"')
    as_owner=$(echo "$response"     | jq -r '.data.attributes.as_owner // "Unknown"')

    local verdict
    if [[ "$malicious" -gt 5 ]]; then
        verdict="${RED}MALICIOUS${NC}"
    elif [[ "$malicious" -gt 0 ]] || [[ "$suspicious" -gt 0 ]]; then
        verdict="${YELLOW}SUSPICIOUS${NC}"
    else
        verdict="${GREEN}CLEAN${NC}"
    fi

    echo -e "  IP:           ${ip}"
    echo -e "  Verdict:      ${verdict} (${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless)"
    echo -e "  Reputation:   ${reputation}"
    echo -e "  Country:      ${country}"
    echo -e "  ASN:          AS${asn} — ${as_owner}"
    echo ""

    # Append to output JSON
    echo "$response" | jq \
        --arg ioc "$ip" \
        --arg type "ip" \
        --argjson mal "$malicious" \
        '{ioc: $ioc, type: $type, malicious_detections: $mal, raw: .data.attributes}' \
        >> "${OUTPUT_FILE}.tmp"
}

enrich_hash() {
    local hash="$1"
    log "Enriching hash: ${hash}"

    local response
    response=$(vt_get "files/${hash}")

    if echo "$response" | jq -e '.error' &>/dev/null; then
        err "VT error for hash ${hash}: $(echo "$response" | jq -r '.error.message')"
        return 1
    fi

    local malicious harmless suspicious name size type_desc meaningful_name
    malicious=$(echo "$response"        | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    harmless=$(echo "$response"         | jq -r '.data.attributes.last_analysis_stats.harmless // 0')
    suspicious=$(echo "$response"       | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
    name=$(echo "$response"             | jq -r '.data.attributes.names[0] // "Unknown"')
    size=$(echo "$response"             | jq -r '.data.attributes.size // 0')
    type_desc=$(echo "$response"        | jq -r '.data.attributes.type_description // "Unknown"')
    meaningful_name=$(echo "$response"  | jq -r '.data.attributes.meaningful_name // "Unknown"')

    local verdict
    if [[ "$malicious" -gt 5 ]]; then
        verdict="${RED}MALICIOUS${NC}"
    elif [[ "$malicious" -gt 0 ]] || [[ "$suspicious" -gt 0 ]]; then
        verdict="${YELLOW}SUSPICIOUS${NC}"
    else
        verdict="${GREEN}CLEAN / UNKNOWN${NC}"
    fi

    echo -e "  Hash:         ${hash}"
    echo -e "  Verdict:      ${verdict} (${malicious} malicious, ${suspicious} suspicious)"
    echo -e "  File Name:    ${meaningful_name} (${name})"
    echo -e "  Type:         ${type_desc}"
    echo -e "  Size:         ${size} bytes"
    echo ""

    echo "$response" | jq \
        --arg ioc "$hash" \
        --arg type "hash" \
        --argjson mal "$malicious" \
        '{ioc: $ioc, type: $type, malicious_detections: $mal, raw: .data.attributes}' \
        >> "${OUTPUT_FILE}.tmp"
}

enrich_domain() {
    local domain="$1"
    log "Enriching domain: ${domain}"

    local response
    response=$(vt_get "domains/${domain}")

    if echo "$response" | jq -e '.error' &>/dev/null; then
        err "VT error for domain ${domain}: $(echo "$response" | jq -r '.error.message')"
        return 1
    fi

    local malicious harmless suspicious reputation categories
    malicious=$(echo "$response"    | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
    harmless=$(echo "$response"     | jq -r '.data.attributes.last_analysis_stats.harmless // 0')
    suspicious=$(echo "$response"   | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
    reputation=$(echo "$response"   | jq -r '.data.attributes.reputation // 0')
    categories=$(echo "$response"   | jq -r '.data.attributes.categories | to_entries | map("\(.value)") | join(", ")' 2>/dev/null || echo "Unknown")

    local verdict
    if [[ "$malicious" -gt 5 ]]; then
        verdict="${RED}MALICIOUS${NC}"
    elif [[ "$malicious" -gt 0 ]] || [[ "$suspicious" -gt 0 ]]; then
        verdict="${YELLOW}SUSPICIOUS${NC}"
    else
        verdict="${GREEN}CLEAN${NC}"
    fi

    echo -e "  Domain:       ${domain}"
    echo -e "  Verdict:      ${verdict} (${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless)"
    echo -e "  Reputation:   ${reputation}"
    echo -e "  Categories:   ${categories}"
    echo ""

    echo "$response" | jq \
        --arg ioc "$domain" \
        --arg type "domain" \
        --argjson mal "$malicious" \
        '{ioc: $ioc, type: $type, malicious_detections: $mal, raw: .data.attributes}' \
        >> "${OUTPUT_FILE}.tmp"
}

detect_ioc_type() {
    local ioc="$1"
    # IPv4
    if [[ "$ioc" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ip"
    # MD5 (32 hex chars), SHA-1 (40), SHA-256 (64)
    elif [[ "$ioc" =~ ^[a-fA-F0-9]{32}$ ]] || \
         [[ "$ioc" =~ ^[a-fA-F0-9]{40}$ ]] || \
         [[ "$ioc" =~ ^[a-fA-F0-9]{64}$ ]]; then
        echo "hash"
    # Domain (contains dot, no spaces)
    elif [[ "$ioc" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "domain"
    else
        echo "unknown"
    fi
}

# ── Main ───────────────────────────────────────────────────────────────────────
usage() {
    grep "^#" "$0" | head -20 | sed 's/^# \?//'
    exit 0
}

main() {
    check_deps
    check_api_key

    local ioc_type="" ioc_value="" ioc_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip)       ioc_type="ip";     ioc_value="$2"; shift 2 ;;
            --hash)     ioc_type="hash";   ioc_value="$2"; shift 2 ;;
            --domain)   ioc_type="domain"; ioc_value="$2"; shift 2 ;;
            --file)     ioc_file="$2";     shift 2 ;;
            --help|-h)  usage ;;
            *)
                # Auto-detect type
                ioc_value="$1"
                ioc_type=$(detect_ioc_type "$ioc_value")
                shift
                ;;
        esac
    done

    # Initialize output file
    rm -f "${OUTPUT_FILE}.tmp"

    local iocs=()
    local types=()

    if [[ -n "$ioc_file" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            iocs+=("$line")
            types+=("$(detect_ioc_type "$line")")
        done < "$ioc_file"
        log "Loaded ${#iocs[@]} IOC(s) from ${ioc_file}"
    elif [[ -n "$ioc_value" ]]; then
        iocs=("$ioc_value")
        types=("$ioc_type")
    else
        err "No IOC provided. Use --ip, --hash, --domain, or --file."
        echo "Run: $0 --help"
        exit 1
    fi

    local total=${#iocs[@]}
    local processed=0

    for i in "${!iocs[@]}"; do
        local ioc="${iocs[$i]}"
        local type="${types[$i]}"

        [[ $processed -gt 0 ]] && sleep "$RATE_LIMIT_SLEEP"

        case "$type" in
            ip)     enrich_ip "$ioc" ;;
            hash)   enrich_hash "$ioc" ;;
            domain) enrich_domain "$ioc" ;;
            *)
                warn "Cannot determine IOC type for: ${ioc} — skipping"
                continue
                ;;
        esac

        processed=$((processed + 1))
        log "Processed ${processed}/${total}"
    done

    # Finalize output JSON (wrap array)
    if [[ -f "${OUTPUT_FILE}.tmp" ]]; then
        jq -s '.' "${OUTPUT_FILE}.tmp" > "$OUTPUT_FILE"
        rm "${OUTPUT_FILE}.tmp"
        ok "Enriched results written to ${OUTPUT_FILE}"
    fi

    log "Done. ${processed}/${total} IOC(s) enriched."
}

main "$@"
