#!/usr/bin/env bash

# subenum.sh
#
# Passive subdomain enumeration using:
#   - subfinder
#   - crt.name
#   - urlscan.io
#   - submap.net
#
# Workflow:
#   discovery -> per-source normalization/deduplication
#             -> global deduplication
#             -> puredns resolution
#             -> dnsx retry of unresolved names
#             -> final resolved dataset
#             -> dnsx A/CNAME enumeration

set -uo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_RESOLVERS="$HOME/scripts/resolvers.txt"

domain=""
resolvers="$DEFAULT_RESOLVERS"
show_banner=true

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

green=$'\033[0;32m'
yellow=$'\033[0;33m'
red=$'\033[0;31m'
cyan=$'\033[0;36m'
nc=$'\033[0m'

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage:
  $0 <domain> [options]

Options:
  -r, --resolvers <file>    Resolver file
                            Default: $DEFAULT_RESOLVERS

  -h, --help                Show this help
  
  --no-banner               Disable ASCII banner

Example:
  $0 example.com

  $0 example.com \
    --resolvers ~/scripts/resolvers.txt
EOF
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

domain="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--resolvers)
            [[ $# -lt 2 ]] && {
                echo "${red}[-] Missing value for $1${nc}"
                exit 1
            }
            resolvers="$2"
            shift 2
            ;;

        -h|--help)
            usage
            exit 0
            ;;
            
        --no-banner)
            show_banner=false
            shift
            ;;

        *)
            echo "${red}[-] Unknown option: $1${nc}"
            usage
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

print_banner() {

    [[ "$show_banner" == false ]] && return
    
    printf '%b' "$cyan"

    cat <<'EOF'
   _____       __
  / ___/__  __/ /_  ___  ____  __  ______ ___
  \__ \/ / / / __ \/ _ \/ __ \/ / / / __ `__ \
 ___/ / /_/ / /_/ /  __/ / / / /_/ / / / / / /
/____/\__,_/_.___/\___/_/ /_/\__,_/_/ /_/ /_/
EOF

    printf '%b' "$nc"
    printf '                     %bv1.0%b by cl4yh4x\n\n' \
        "$cyan" "$nc"
}

# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

domain="${domain,,}"

# Remove an accidental trailing dot.
domain="${domain%.}"

if (( ${#domain} > 253 )); then
    echo "${red}[-] Invalid domain: exceeds 253 characters${nc}"
    exit 1
fi

domain_regex='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'

if [[ ! "$domain" =~ $domain_regex ]]; then
    echo "${red}[-] Invalid domain: $domain${nc}"
    echo "    Expected format: example.com"
    exit 1
fi

# ---------------------------------------------------------------------------
# Dependency validation
# ---------------------------------------------------------------------------

missing=0

for cmd in subfinder puredns dnsx curl sort grep sed tr wc comm; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "${red}[-] Missing dependency: $cmd${nc}"
        missing=1
    fi
done

if ! command -v jq >/dev/null 2>&1; then
    echo "${red}[-] Missing dependency: jq${nc}"
    missing=1
fi

if (( missing )); then
    exit 1
fi

if [[ ! -f "$resolvers" ]]; then
    echo "${red}[-] Resolver file not found:${nc} $resolvers"
    exit 1
fi

if [[ ! -s "$resolvers" ]]; then
    echo "${red}[-] Resolver file is empty:${nc} $resolvers"
    exit 1
fi


# ---------------------------------------------------------------------------
# Output paths
# ---------------------------------------------------------------------------

output_dir="${domain}-enum"
sources_dir="$output_dir/sources"

mkdir -p "$sources_dir"

subfinder_file="$sources_dir/subfinder.txt"
crt_file="$sources_dir/crt.txt"
urlscan_file="$sources_dir/urlscan.txt"
submap_file="$sources_dir/submap.txt"

all_file="$output_dir/all-subdomains.txt"
resolved_file="$output_dir/resolved.txt"
dns_file="$output_dir/dns-records.txt"

# Temporary raw files
tmpdir="$(mktemp -d -t subenum.XXXXXX)"

cleanup() {
    rm -rf "$tmpdir"
}

trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

#
# Normalize a source file:
#
#   - lowercase
#   - strip CR characters
#   - strip whitespace
#   - remove trailing DNS dot
#   - only retain requested domain / subdomains
#   - deduplicate
#
normalize_file() {
    local input="$1"
    local output="$2"
    local escaped_domain

    escaped_domain="${domain//./\\.}"

    tr '[:upper:]' '[:lower:]' < "$input" \
        | tr -d '\r' \
        | sed 's/^[[:space:]]*//' \
        | sed 's/[[:space:]]*$//' \
        | sed 's/\.$//' \
        | grep -E "(^|\\.)${escaped_domain}$" \
        | sort -u \
        > "$output" || true
}

count_file() {
    local file="$1"

    if [[ -s "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo 0
    fi
}

spinner() {
    local pid="$1"
    local message="$2"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        printf '\r%b[*]%b %s %b%s%b' \
            "$cyan" \
            "$nc" \
            "$message" \
            "$cyan" \
            "${frames[i]}" \
            "$nc"

        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.08
    done

    printf '\r\033[K'
}

# ---------------------------------------------------------------------------
# Passive discovery
# ---------------------------------------------------------------------------

echo
print_banner
echo "${cyan}[*] Enumerating ${domain}${nc}"
echo

passive_output="$tmpdir/passive-output.txt"

(

# ---------------------------------------------------------------------------
# Subfinder
# ---------------------------------------------------------------------------

subfinder_raw="$tmpdir/subfinder.raw"

if subfinder \
    -d "$domain" \
    -all \
    -recursive \
    -silent \
    > "$subfinder_raw" 2>"$tmpdir/subfinder.err"
then
    normalize_file "$subfinder_raw" "$subfinder_file"

    subfinder_count="$(count_file "$subfinder_file")"

    printf "${green}[+]${nc} %-26s %s\n" \
        "Subfinder" \
        "$subfinder_count"
else
    : > "$subfinder_file"

    printf "${red}[-]${nc} %-26s %s\n" \
        "Subfinder" \
        "failed"
fi

# ---------------------------------------------------------------------------
# crt.name
# ---------------------------------------------------------------------------

crt_raw="$tmpdir/crt.raw"

if curl -fsSG 'https://crt.name/v1/search' \
    --data-urlencode "apex=$domain" \
    -o "$crt_raw" \
    2>"$tmpdir/crt.err"
then
    normalize_file "$crt_raw" "$crt_file"

    crt_count="$(count_file "$crt_file")"

    printf "${green}[+]${nc} %-26s %s\n" \
        "Certificate search" \
        "$crt_count"
else
    : > "$crt_file"

    printf "${red}[-]${nc} %-26s %s\n" \
        "Certificate search" \
        "failed"

    if [[ -s "$tmpdir/crt.err" ]]; then
        sed 's/^/    /' "$tmpdir/crt.err"
    fi
fi

# ---------------------------------------------------------------------------
# URLScan
# ---------------------------------------------------------------------------

urlscan_raw="$tmpdir/urlscan.json"

urlscan_http="$(
    curl \
        -sS \
        -o "$urlscan_raw" \
        -w '%{http_code}' \
        -G 'https://urlscan.io/api/v1/search/' \
        --data-urlencode "q=page.domain:$domain" \
        --data-urlencode 'size=100' \
        --data-urlencode 'datasource=scans' \
        --data-urlencode 'collapse=page.domain.keyword' \
        2>"$tmpdir/urlscan.err"
)" || urlscan_http="000"

if [[ "$urlscan_http" == "200" ]] &&
   jq -e . "$urlscan_raw" >/dev/null 2>&1
then
    jq -r \
        '.results[]?.page?.domain // empty' \
        "$urlscan_raw" \
        > "$tmpdir/urlscan.raw"

    normalize_file \
        "$tmpdir/urlscan.raw" \
        "$urlscan_file"

    urlscan_count="$(count_file "$urlscan_file")"

    printf "${green}[+]${nc} %-26s %s\n" \
        "URLScan" \
        "$urlscan_count"
else
    : > "$urlscan_file"

    printf "${red}[-]${nc} %-26s %s" \
        "URLScan" \
        "failed"

    [[ "$urlscan_http" != "000" ]] &&
        printf " (HTTP %s)" "$urlscan_http"

    printf '\n'
fi

# ---------------------------------------------------------------------------
# Submap
# ---------------------------------------------------------------------------

submap_raw="$tmpdir/submap.raw"
submap_sse="$tmpdir/submap.sse"

if curl -fsSNG 'https://submap.net/api/scan' \
    --data-urlencode "domain=$domain" \
    -H 'Accept: text/event-stream' \
    -o "$submap_sse" \
    2>"$tmpdir/submap.err"
then
    sed -n 's/^data: *//p' "$submap_sse" \
        | jq -r '
            if has("newSubs") then
                .newSubs[]?.sub // empty
            elif has("results") then
                .results[]?.subdomain // empty
            else
                empty
            end
        ' \
        > "$submap_raw"

    normalize_file \
        "$submap_raw" \
        "$submap_file"

    submap_count="$(count_file "$submap_file")"

    printf "${green}[+]${nc} %-26s %s\n" \
        "Submap" \
        "$submap_count"
else
    : > "$submap_file"

    printf "${red}[-]${nc} %-26s %s\n" \
        "Submap" \
        "failed"

    if [[ -s "$tmpdir/submap.err" ]]; then
        sed 's/^/    /' "$tmpdir/submap.err"
    fi
fi

) > "$passive_output" 2>&1 &

passive_pid=$!

spinner \
    "$passive_pid" \
    "Running passive discovery..."

wait "$passive_pid"
passive_status=$?

echo
cat "$passive_output"

if (( passive_status != 0 )); then
    echo "${yellow}[!] Passive discovery completed with errors.${nc}"
fi

# ---------------------------------------------------------------------------
# Global deduplication
# ---------------------------------------------------------------------------

cat \
    "$subfinder_file" \
    "$crt_file" \
    "$urlscan_file" \
    "$submap_file" \
    | sort -u \
    > "$all_file"

all_count="$(count_file "$all_file")"

echo
printf "${green}[+]${nc} %-26s %s\n" \
    "Unique subdomains" \
    "$all_count"

if (( all_count == 0 )); then
    echo
    echo "${yellow}[!] No subdomains were discovered.${nc}"
    echo
    echo "Results:"
    echo "  All subdomains : $all_file"
    exit 0
fi

# ---------------------------------------------------------------------------
# DNS resolution
#
# Workflow:
#
#   1. Resolve the globally deduplicated dataset with PureDNS.
#   2. Identify names PureDNS did not resolve.
#   3. Retry those names with dnsx.
#   4. Merge dnsx-recovered names with the PureDNS results.
#   5. Deduplicate the final resolved dataset.
#
# This provides a secondary validation pass for transient DNS failures,
# resolver inconsistencies, dropped queries, or other resolution misses.
#
# ---------------------------------------------------------------------------

echo
echo "[*] Resolving ${all_count} unique subdomains..."

puredns_resolved="$tmpdir/puredns-resolved.txt"
puredns_missed="$tmpdir/puredns-missed.txt"
dnsx_retry_raw="$tmpdir/dnsx-retry.raw"
dnsx_recovered="$tmpdir/dnsx-recovered.txt"

# ---------------------------------------------------------------------------
# Primary resolution: PureDNS
# ---------------------------------------------------------------------------

if ! puredns resolve \
    "$all_file" \
    --resolvers "$resolvers" \
    --write "$puredns_resolved" \
    --quiet \
    >/dev/null
then
    echo "${red}[-] puredns resolution failed.${nc}"
    exit 1
fi

# PureDNS normally produces unique output, but enforce it anyway.
sort -u \
    "$puredns_resolved" \
    -o "$puredns_resolved"

puredns_count="$(count_file "$puredns_resolved")"

printf "${green}[+]${nc} %-26s %s\n" \
    "Resolved by PureDNS" \
    "$puredns_count"

# ---------------------------------------------------------------------------
# Identify PureDNS misses
# ---------------------------------------------------------------------------

comm -23 \
    "$all_file" \
    "$puredns_resolved" \
    > "$puredns_missed"

missed_count="$(count_file "$puredns_missed")"

# ---------------------------------------------------------------------------
# Secondary resolution: dnsx
# ---------------------------------------------------------------------------

: > "$dnsx_recovered"

if (( missed_count > 0 )); then

    printf "${yellow}[*]${nc} %-26s %s\n" \
        "Retrying with dnsx" \
        "$missed_count"

    if dnsx \
        -l "$puredns_missed" \
        -r "$resolvers" \
        -auto-wildcard \
        -silent \
        > "$dnsx_retry_raw"
    then
        normalize_file \
            "$dnsx_retry_raw" \
            "$dnsx_recovered"
    else
        echo "${yellow}[!] dnsx retry failed; continuing with PureDNS results.${nc}"
        : > "$dnsx_recovered"
    fi
fi

recovered_count="$(count_file "$dnsx_recovered")"

printf "${green}[+]${nc} %-26s %s\n" \
    "Recovered by dnsx" \
    "$recovered_count"

# ---------------------------------------------------------------------------
# Merge final resolved dataset
# ---------------------------------------------------------------------------

cat \
    "$puredns_resolved" \
    "$dnsx_recovered" \
    | sort -u \
    > "$resolved_file"

resolved_count="$(count_file "$resolved_file")"
unresolved_count=$((all_count - resolved_count))

printf "${green}[+]${nc} %-26s %s\n" \
    "Final resolved" \
    "$resolved_count"

if (( unresolved_count > 0 )); then
    printf "${yellow}[-]${nc} %-26s %s\n" \
        "Unresolved" \
        "$unresolved_count"
fi

# ---------------------------------------------------------------------------
# DNS records
# ---------------------------------------------------------------------------

if (( resolved_count > 0 )); then

    echo
    echo "[*] Querying A/CNAME records..."

    if dnsx \
        -l "$resolved_file" \
        -a \
        -cname \
        -resp \
        -silent \
        > "$dns_file"
    then
        echo "${green}[+] Complete${nc}"
    else
        echo "${red}[-] dnsx failed.${nc}"
        exit 1
    fi

else
    : > "$dns_file"

    echo
    echo "${yellow}[!] No discovered subdomains resolved.${nc}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "Results:"
echo "  All subdomains : $all_file"
echo "  Resolved       : $resolved_file"
echo "  DNS records    : $dns_file"

echo
echo "Per-source:"
echo "  Subfinder      : $subfinder_file"
echo "  Certificates   : $crt_file"
echo "  URLScan        : $urlscan_file"
echo "  Submap         : $submap_file"

echo
