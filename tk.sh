#!/usr/bin/env bash
# TikTok 地区与出口 ASN 检测。

set -u -o pipefail

readonly VERSION="2.0.2"
readonly UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

INTERFACE=""

if [[ -t 1 ]]; then
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
    C_RESET=$'\033[0m'
else
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_CYAN=""
    C_RESET=""
fi

usage() {
    cat <<'EOF'
用法：bash tk.sh [-4] [-I 网卡]

选项：
  -4                 使用 IPv4 出口（默认）
  -I, --interface    指定 curl 使用的出口网卡或地址
  -h, --help         显示帮助
  -V, --version      显示版本
EOF
}

die() {
    printf '%s错误：%s%s\n' "$C_RED" "$*" "$C_RESET" >&2
    exit 1
}

is_valid_ip() {
    local value="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$value" \
            >/dev/null 2>&1
    elif [[ "$value" == *:* ]]; then
        [[ "$value" =~ ^[0-9A-Fa-f:]+$ ]]
    else
        [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
    fi
}

json_value() {
    local json="$1"
    local key="$2"

    if command -v jq >/dev/null 2>&1; then
        jq -r --arg key "$key" '.[$key] // empty' <<<"$json" 2>/dev/null
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json, sys
try:
    value = json.load(sys.stdin).get(sys.argv[1], "")
    print("" if value is None else value)
except Exception:
    pass' "$key" <<<"$json"
    else
        if [[ "$key" == "asn" ]]; then
            sed -n 's/.*"asn"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' <<<"$json" | head -n 1
        else
            sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"\\]*\)".*/\1/p' <<<"$json" | head -n 1
        fi
    fi
}

mask_ip() {
    local ip="$1"
    if [[ "$ip" == *:* ]]; then
        awk -F: '{printf "%s:%s:%s:*", $1, $2, $3}' <<<"$ip"
    else
        awk -F. '{printf "%s.%s.*.*", $1, $2}' <<<"$ip"
    fi
}

extract_tiktok_region() {
    grep -oE '"region"[[:space:]]*:[[:space:]]*"[A-Za-z]{2}"' \
        | sed -n 's/.*"\([A-Za-z][A-Za-z]\)"/\U\1/p' \
        | head -n 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -4) ;;
        -6) die "TikTok 地区检测仅支持 IPv4 出口" ;;
        -I|--interface)
            [[ $# -ge 2 ]] || die "$1 需要网卡或地址参数"
            INTERFACE="$2"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        -V|--version) printf 'tk.sh %s\n' "$VERSION"; exit 0 ;;
        *) die "未知选项：$1（使用 --help 查看帮助）" ;;
    esac
    shift
done

command -v curl >/dev/null 2>&1 || die "缺少 curl，请先安装"

CURL_ARGS=(--silent --show-error --location --connect-timeout 5 --max-time 15 --retry 1 -4)
[[ -n "$INTERFACE" ]] && CURL_ARGS+=(--interface "$INTERFACE")
IP_ENDPOINT="https://api4.ipify.org"

public_ip="$(curl "${CURL_ARGS[@]}" --fail "$IP_ENDPOINT" 2>/dev/null || true)"
public_ip="${public_ip//$'\r'/}"
public_ip="${public_ip//$'\n'/}"
is_valid_ip "$public_ip" || die "无法通过 IPv4 获取公网 IP；TikTok 地区检测仅支持有 IPv4 出口的服务器"

if [[ "$public_ip" == *:* ]]; then
    die "当前出口未返回 IPv4 地址"
fi

geo_json="$(curl "${CURL_ARGS[@]}" --fail --user-agent "$UA_BROWSER" \
    "https://api.ip.sb/geoip/${public_ip}" 2>/dev/null || true)"
asn="$(json_value "$geo_json" asn)"
asn_org="$(json_value "$geo_json" asn_organization)"
organization="$(json_value "$geo_json" organization)"
isp="$(json_value "$geo_json" isp)"
country_code="$(json_value "$geo_json" country_code)"
region_name="$(json_value "$geo_json" region)"
city="$(json_value "$geo_json" city)"

[[ -n "$asn_org" ]] || asn_org="$organization"
asn_text="未知"
if [[ -n "$asn" || -n "$asn_org" ]]; then
    asn_text="${asn:+AS${asn}}${asn:+${asn_org:+ }}${asn_org}"
fi
[[ -n "$isp" ]] || isp="${organization:-未知}"
location="$country_code"
[[ -n "$region_name" ]] && location="${location:+${location} / }${region_name}"
[[ -n "$city" ]] && location="${location:+${location} / }${city}"

if [[ -t 1 && -n "${TERM:-}" && "$TERM" != "dumb" ]]; then
    clear
fi

printf '%s【TikTok 地区检测】%s\n\n' "$C_CYAN" "$C_RESET"
printf ' ** 测试时间: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
printf ' %s** 出口 IP: %s%s\n' "$C_CYAN" "$(mask_ip "$public_ip")" "$C_RESET"
printf ' %s** ASN: %s%s\n' "$C_CYAN" "$asn_text" "$C_RESET"
printf ' %s** ISP: %s%s\n' "$C_CYAN" "$isp" "$C_RESET"
[[ -n "$location" ]] && printf ' %s** IP 所在地: %s%s\n' "$C_CYAN" "$location" "$C_RESET"
printf '%s\n\n' '******************************************'

printf ' TikTok Region:\t\t'
tiktok_html="$(curl "${CURL_ARGS[@]}" --compressed --user-agent "$UA_BROWSER" \
    -H 'Accept-Language: en-US,en;q=0.9' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
    'https://www.tiktok.com/' 2>/dev/null || true)"
region="$(extract_tiktok_region <<<"$tiktok_html")"

if [[ -n "$region" ]]; then
    printf '%s【%s】%s\n' "$C_GREEN" "$region" "$C_RESET"
else
    printf '%sFailed%s\n' "$C_RED" "$C_RESET"
    printf ' %s未从 TikTok 页面读取到地区；可能是网络、风控或页面结构变化。%s\n' "$C_YELLOW" "$C_RESET"
fi

printf '\n%s\n' '******************************************'
printf '%s检测完成%s\n\n' "$C_GREEN" "$C_RESET"
