#!/usr/bin/env bash
# IP 信息查询：无需 API Token，不修改系统。

set -u -o pipefail

readonly VERSION="2.0.0"
readonly API_BASE="https://api.ip.sb/geoip"

INTERFACE=""
FAMILY=""
RAW_OUTPUT=0
QUERY_IP=""

if [[ -t 1 ]]; then
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
    C_RESET=$'\033[0m'
else
    C_YELLOW=""
    C_RED=""
    C_CYAN=""
    C_RESET=""
fi

usage() {
    cat <<'EOF'
用法：
  bash ip.sh [IP]
  bash ip.sh [-4|-6] [-I 网卡] [--json] [IP]

选项：
  -4                 查询本机 IPv4（未指定 IP 时）
  -6                 查询本机 IPv6（未指定 IP 时）
  -I, --interface    指定 curl 使用的出口网卡或地址
  --json             原样输出查询服务返回的 JSON
  -h, --help         显示帮助
  -V, --version      显示版本

不指定 IP 时查询本机公网 IP。脚本不保存查询结果。
EOF
}

die() {
    printf '%s错误：%s%s\n' "$C_RED" "$*" "$C_RESET" >&2
    exit 1
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

is_valid_ip() {
    local value="$1"

    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$value" \
            >/dev/null 2>&1
        return
    fi

    if [[ "$value" == *:* ]]; then
        [[ "$value" =~ ^[0-9A-Fa-f:]+$ ]]
    else
        local octet
        local -a octets=()
        IFS='.' read -r -a octets <<<"$value"
        [[ ${#octets[@]} -eq 4 ]] || return 1
        for octet in "${octets[@]}"; do
            [[ "$octet" =~ ^[0-9]+$ ]] || return 1
            ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
        done
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

prepare_curl_args() {
    CURL_ARGS=(
        --silent --show-error --fail --location
        --connect-timeout 5 --max-time 15 --retry 1
        --user-agent "vps-test-ip/${VERSION}"
    )
    [[ -n "$INTERFACE" ]] && CURL_ARGS+=(--interface "$INTERFACE")
}

fetch_public_ip() {
    local endpoint="https://api64.ipify.org"
    local value

    case "$FAMILY" in
        4) endpoint="https://api4.ipify.org" ;;
        6) endpoint="https://api6.ipify.org" ;;
    esac

    value="$(curl "${CURL_ARGS[@]}" "$endpoint" 2>/dev/null || true)"
    value="$(trim "$value")"
    is_valid_ip "$value" || die "无法获取有效的本机公网 IP，请检查网络或使用参数直接指定 IP"

    if [[ "$FAMILY" == "4" && "$value" == *:* ]]; then
        die "当前出口未返回 IPv4 地址"
    fi
    if [[ "$FAMILY" == "6" && "$value" != *:* ]]; then
        die "当前出口未返回 IPv6 地址"
    fi

    QUERY_IP="$value"
}

print_field() {
    local label="$1"
    local value="$2"
    [[ -n "$value" ]] && printf '%-12s %s\n' "${label}:" "$value"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -4) FAMILY="4" ;;
        -6) FAMILY="6" ;;
        -I|--interface)
            [[ $# -ge 2 ]] || die "$1 需要网卡或地址参数"
            INTERFACE="$2"
            shift
            ;;
        --json) RAW_OUTPUT=1 ;;
        -h|--help) usage; exit 0 ;;
        -V|--version) printf 'ip.sh %s\n' "$VERSION"; exit 0 ;;
        --) shift; break ;;
        -*) die "未知选项：$1（使用 --help 查看帮助）" ;;
        *)
            [[ -z "$QUERY_IP" ]] || die "只能指定一个 IP"
            QUERY_IP="$1"
            ;;
    esac
    shift
done

while [[ $# -gt 0 ]]; do
    [[ -z "$QUERY_IP" ]] || die "只能指定一个 IP"
    QUERY_IP="$1"
    shift
done

command -v curl >/dev/null 2>&1 || die "缺少 curl，请先安装"
prepare_curl_args

if [[ -z "$QUERY_IP" && -t 0 ]]; then
    read -r -p "您要查询的 IP（直接回车查询本机公网 IP）：" QUERY_IP
    QUERY_IP="$(trim "$QUERY_IP")"
fi

if [[ -z "$QUERY_IP" ]]; then
    fetch_public_ip
else
    QUERY_IP="$(trim "$QUERY_IP")"
    is_valid_ip "$QUERY_IP" || die "无效的 IP 地址：$QUERY_IP"
fi

response="$(curl "${CURL_ARGS[@]}" "${API_BASE}/${QUERY_IP}" 2>/dev/null || true)"
[[ -n "$response" ]] || die "IP 信息查询失败，请稍后重试"

if ((RAW_OUTPUT)); then
    printf '%s\n' "$response"
    exit 0
fi

result_ip="$(json_value "$response" ip)"
asn="$(json_value "$response" asn)"
asn_org="$(json_value "$response" asn_organization)"
organization="$(json_value "$response" organization)"
isp="$(json_value "$response" isp)"
country="$(json_value "$response" country)"
country_code="$(json_value "$response" country_code)"
region="$(json_value "$response" region)"
city="$(json_value "$response" city)"
timezone="$(json_value "$response" timezone)"

[[ -n "$result_ip" ]] || die "查询服务未返回有效的 IP 信息"

ip_type="IPv4"
[[ "$result_ip" == *:* ]] && ip_type="IPv6"
asn_text=""
[[ -n "$asn" ]] && asn_text="AS${asn}"
[[ -n "$asn_org" ]] && asn_text="${asn_text:+${asn_text} }${asn_org}"
location="${country}${country_code:+ (${country_code})}"
[[ -n "$region" ]] && location="${location:+${location}, }${region}"
[[ -n "$city" ]] && location="${location:+${location}, }${city}"

printf '%sIP 查询结果%s\n' "$C_CYAN" "$C_RESET"
printf '%s\n' '----------------------------------------'
print_field "IP" "$result_ip"
print_field "类型" "$ip_type"
print_field "ASN" "$asn_text"
print_field "组织" "$organization"
print_field "ISP" "$isp"
print_field "位置" "$location"
print_field "时区" "$timezone"
printf '%s\n' '----------------------------------------'
printf '%s数据来源：api.ip.sb，结果仅供参考。%s\n' "$C_YELLOW" "$C_RESET"
