#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
CONFIG_FILE="${HOME}/.ddns-cloudflare.conf"
STATE_DIR="${HOME}/.ddns-cloudflare"
WAN_IP_FILE="${STATE_DIR}/wan_ip.txt"
ID_FILE="${STATE_DIR}/record_id.txt"
LOCK_DIR="${STATE_DIR}/update.lock"

CFKEY=""
CFUSER=""
CF_AUTH_MODE="key"
CFZONE_NAME=""
CFRECORD_NAME=""
CFRECORD_TYPE="A"
CFTTL="120"
FORCE="false"
CRON_SCHEDULE="*/5 * * * *"
CRON_LOG_FILE="${STATE_DIR}/ddns.log"
WANIPSITE="https://ipv4.icanhazip.com"

CRON_BEGIN="# BEGIN ddns.sh managed block"
CRON_END="# END ddns.sh managed block"
CRON_LEGACY_MARK="# ddns.sh managed by script"

log() {
  printf '%s\n' "$*"
}

if [ -t 1 ]; then
  COLOR_RESET=$'\033[0m'
  COLOR_TITLE=$'\033[1;36m'
  COLOR_OK=$'\033[1;32m'
  COLOR_WARN=$'\033[1;33m'
  COLOR_ERROR=$'\033[1;31m'
  COLOR_DIM=$'\033[2m'
else
  COLOR_RESET=""
  COLOR_TITLE=""
  COLOR_OK=""
  COLOR_WARN=""
  COLOR_ERROR=""
  COLOR_DIM=""
fi

title() {
  printf '\n%s== %s ==%s\n' "$COLOR_TITLE" "$1" "$COLOR_RESET"
}

success() {
  printf '%s✓ %s%s\n' "$COLOR_OK" "$1" "$COLOR_RESET"
}

warning() {
  printf '%s! %s%s\n' "$COLOR_WARN" "$1" "$COLOR_RESET"
}

mask_value() {
  local value="${1:-}"
  if [ -z "$value" ]; then
    printf '%s' "未设置"
  else
    printf '%s' '已设置（已隐藏）'
  fi
}

mask_email() {
  if [ -n "${1:-}" ]; then
    printf '%s' '已设置（已隐藏）'
  else
    printf '%s' '未设置'
  fi
}

mask_private() {
  if [ -n "${1:-}" ]; then
    printf '%s' '已设置（已隐藏）'
  else
    printf '%s' '未设置'
  fi
}

die() {
  log "$*"
  exit 1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

prompt() {
  local message="$1"
  local default="${2:-}"
  local reply=""

  if [ -n "$default" ]; then
    read -r -p "${message} [${default}]: " reply
    reply="$(trim "$reply")"
    [ -n "$reply" ] || reply="$default"
  else
    read -r -p "${message}: " reply
    reply="$(trim "$reply")"
  fi

  printf '%s' "$reply"
}

prompt_private() {
  local message="$1"
  local default="${2:-}"
  local reply=""

  if [ -n "$default" ]; then
    read -r -p "${message} [已设置，回车保留]: " reply
  else
    read -r -p "${message} [未设置]: " reply
  fi
  reply="$(trim "$reply")"
  [ -n "$reply" ] || reply="$default"
  printf '%s' "$reply"
}

prompt_secret() {
  local message="$1"
  local default="${2:-}"
  local reply=""

  if [ -n "$default" ]; then
    read -r -s -p "${message} [hidden, Enter 保留默认值]: " reply
  else
    read -r -s -p "${message}: " reply
  fi
  printf '\n' >&2
  reply="$(trim "$reply")"
  [ -n "$reply" ] || reply="$default"
  printf '%s' "$reply"
}

ask_yes_no() {
  local message="$1"
  local default="${2:-Y}"
  local hint="[Y/n]"
  case "$default" in
    N|n) hint="[y/N]" ;;
  esac

  local reply=""
  read -r -p "${message} ${hint}: " reply
  reply="$(trim "$reply")"
  [ -n "$reply" ] || reply="$default"

  case "$reply" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_curl_dependency() {
  command -v curl >/dev/null 2>&1 || die "缺少 curl，请先安装。"
}

ensure_cron_dependency() {
  command -v crontab >/dev/null 2>&1 || die "缺少 crontab，请先安装 cron。"
}

ensure_state_dir() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR" 2>/dev/null || true
}

load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
  fi
}

save_config() {
  ensure_state_dir
  umask 077
  cat > "$CONFIG_FILE" <<EOF2
CFKEY=$(printf '%q' "$CFKEY")
CFUSER=$(printf '%q' "$CFUSER")
CF_AUTH_MODE=$(printf '%q' "$CF_AUTH_MODE")
CFZONE_NAME=$(printf '%q' "$CFZONE_NAME")
CFRECORD_NAME=$(printf '%q' "$CFRECORD_NAME")
CFRECORD_TYPE=$(printf '%q' "$CFRECORD_TYPE")
CFTTL=$(printf '%q' "$CFTTL")
FORCE=$(printf '%q' "$FORCE")
CRON_SCHEDULE=$(printf '%q' "$CRON_SCHEDULE")
CRON_LOG_FILE=$(printf '%q' "$CRON_LOG_FILE")
EOF2
  chmod 600 "$CONFIG_FILE"
}

configure_wan_site() {
  case "$CFRECORD_TYPE" in
    A) WANIPSITE="https://ipv4.icanhazip.com" ;;
    AAAA) WANIPSITE="https://ipv6.icanhazip.com" ;;
    *) die "CFRECORD_TYPE 只能是 A 或 AAAA。" ;;
  esac
}

normalize_record_name() {
  if [ -n "$CFZONE_NAME" ] && [ "$CFRECORD_NAME" != "$CFZONE_NAME" ] && [[ "$CFRECORD_NAME" != *".$CFZONE_NAME" ]]; then
    CFRECORD_NAME="$CFRECORD_NAME.$CFZONE_NAME"
    log "=> 主机名不是完整 FQDN，已自动补全（主机名已隐藏）"
  fi
}

validate_auth_mode() {
  case "$CF_AUTH_MODE" in
    key|token) ;;
    *) die "认证方式只能是 key 或 token。" ;;
  esac
}

validate_config() {
  validate_auth_mode

  case "$CFRECORD_TYPE" in
    A|AAAA) ;;
    *) die "CFRECORD_TYPE 只能是 A 或 AAAA。" ;;
  esac

  case "$CFTTL" in
    ''|*[!0-9]*) die "TTL 必须是 120-86400 之间的整数。" ;;
  esac
  if [ "$CFTTL" -lt 120 ] || [ "$CFTTL" -gt 86400 ]; then
    die "TTL 必须是 120-86400 之间的整数。"
  fi

  case "$FORCE" in
    true|false) ;;
    *) die "FORCE 只能是 true 或 false。" ;;
  esac

  [ -n "$CFZONE_NAME" ] || die "缺少 Zone 域名。"
  [ -n "$CFRECORD_NAME" ] || die "缺少记录主机名。"

  if [[ "$CFZONE_NAME" == *$'\n'* || "$CFZONE_NAME" == *$'\r'* || "$CFZONE_NAME" == *'"'* || "$CFZONE_NAME" == *'\\'* ]]; then
    die "Zone 域名包含不支持的字符。"
  fi
  if [[ "$CFRECORD_NAME" == *$'\n'* || "$CFRECORD_NAME" == *$'\r'* || "$CFRECORD_NAME" == *'"'* || "$CFRECORD_NAME" == *'\\'* ]]; then
    die "DNS 记录名称包含不支持的字符。"
  fi
  if [[ "$CFKEY" == *$'\n'* || "$CFKEY" == *$'\r'* || "$CFKEY" == *'"'* ]]; then
    die "Cloudflare Key/Token 包含不支持的字符。"
  fi
  if [[ "$CFUSER" == *$'\n'* || "$CFUSER" == *$'\r'* || "$CFUSER" == *'"'* ]]; then
    die "Cloudflare 邮箱包含不支持的字符。"
  fi
}

sanitize_cron_schedule() {
  CRON_SCHEDULE="$(trim "$CRON_SCHEDULE")"
  [ -n "$CRON_SCHEDULE" ] || CRON_SCHEDULE="*/5 * * * *"
  [[ "$CRON_SCHEDULE" != *$'\n'* && "$CRON_SCHEDULE" != *$'\r'* ]] || die "Cron 表达式不能包含换行。"

  if [[ "$CRON_SCHEDULE" != @* ]]; then
    local f1 f2 f3 f4 f5 extra
    read -r f1 f2 f3 f4 f5 extra <<< "$CRON_SCHEDULE"
    if [ -z "$f1" ] || [ -z "$f2" ] || [ -z "$f3" ] || [ -z "$f4" ] || [ -z "$f5" ] || [ -n "$extra" ]; then
      die "Cron 表达式必须包含 5 个字段，例如：*/5 * * * *。"
    fi
  fi
}

show_help() {
  cat <<EOF2
Usage:
  bash ddns.sh
  bash ddns.sh --run
  bash ddns.sh --install-cron
  bash ddns.sh --remove-cron
  bash ddns.sh --show-config

Old flags are still supported:
  -k <api-key> -u <email> -h <host> -z <zone> -t <A|AAAA> -f <true|false>
  --auth <key|token>
  --force
  --config <path>

Interactive mode will guide you through configuration and save it to:
  $CONFIG_FILE
EOF2
}

cron_job_line() {
  if [ -n "${CRON_LOG_FILE:-}" ]; then
    printf '%s bash "%s" --run >> "%s" 2>&1' "$CRON_SCHEDULE" "$SCRIPT_PATH" "$CRON_LOG_FILE"
  else
    printf '%s bash "%s" --run' "$CRON_SCHEDULE" "$SCRIPT_PATH"
  fi
}

remove_managed_cron_blocks() {
  awk -v begin="$CRON_BEGIN" -v end="$CRON_END" -v legacy="$CRON_LEGACY_MARK" -v script="$SCRIPT_PATH" '
    BEGIN { in_block=0; skip_legacy_command=0 }
    $0 == begin { in_block=1; next }
    in_block && $0 == end { in_block=0; next }
    in_block { next }
    $0 == legacy { skip_legacy_command=1; next }
    skip_legacy_command {
      if (index($0, script) > 0 && $0 ~ /[[:space:]]+bash[[:space:]]+"/ && $0 ~ /[[:space:]]--run([[:space:]]|$)/) {
        skip_legacy_command=0
        next
      }
      skip_legacy_command=0
    }
    { print }
  '
}

install_cron_job() {
  ensure_cron_dependency
  ensure_state_dir
  [ -f "$CONFIG_FILE" ] || die "未找到配置文件，请先运行交互配置并保存。"

  normalize_record_name
  configure_wan_site
  validate_config
  sanitize_cron_schedule

  local current_cron tmp_file
  current_cron="$(crontab -l 2>/dev/null || true)"
  tmp_file="$(mktemp)"

  if [ -n "$current_cron" ]; then
    printf '%s\n' "$current_cron" | remove_managed_cron_blocks > "$tmp_file"
  else
    : > "$tmp_file"
  fi

  if ! {
    {
      cat "$tmp_file"
      [ ! -s "$tmp_file" ] || printf '\n'
      printf '%s\n' "$CRON_BEGIN"
      cron_job_line
      printf '\n%s\n' "$CRON_END"
    } | crontab -
  }; then
    rm -f "$tmp_file"
    die "写入 crontab 失败，请检查 cron 配置。"
  fi

  rm -f "$tmp_file"
  log "已安装/更新 crontab：$CRON_SCHEDULE"
  [ -z "${CRON_LOG_FILE:-}" ] || log "日志文件：$CRON_LOG_FILE"
}

remove_cron_job() {
  ensure_cron_dependency

  local current_cron tmp_file
  current_cron="$(crontab -l 2>/dev/null || true)"
  tmp_file="$(mktemp)"

  if [ -n "$current_cron" ]; then
    printf '%s\n' "$current_cron" | remove_managed_cron_blocks > "$tmp_file"
    if ! crontab "$tmp_file"; then
      rm -f "$tmp_file"
      die "写入 crontab 失败，请检查 cron 配置。"
    fi
  else
    crontab -r 2>/dev/null || true
  fi

  rm -f "$tmp_file"
  log "已移除与本脚本相关的 crontab 任务。"
}

interactive_configure() {
  ensure_state_dir
  title "Cloudflare DDNS 交互配置"
  log "直接回车可保留已有值；API Key / Token 输入时不会回显。"
  log ""

  title "Cloudflare 认证"
  CF_AUTH_MODE="$(prompt "认证方式 key/token" "${CF_AUTH_MODE:-key}")"
  case "$CF_AUTH_MODE" in
    key)
      CFKEY="$(prompt_secret "Cloudflare Global API Key" "${CFKEY:-}")"
      CFUSER="$(prompt_private "Cloudflare 邮箱" "${CFUSER:-}")"
      ;;
    token)
      CFKEY="$(prompt_secret "Cloudflare API Token" "${CFKEY:-}")"
      CFUSER=""
      ;;
    *)
      die "认证方式只能是 key 或 token。"
      ;;
  esac

  title "DNS 记录"
  CFZONE_NAME="$(prompt_private "根域名 / Zone，例如 example.com" "${CFZONE_NAME:-}")"
  CFRECORD_NAME="$(prompt_private "要更新的主机名，例如 home.example.com 或 home" "${CFRECORD_NAME:-}")"
  CFRECORD_TYPE="$(prompt "记录类型 A/AAAA" "${CFRECORD_TYPE:-A}")"
  CFTTL="$(prompt "TTL（120-86400）" "${CFTTL:-120}")"
  FORCE="$(prompt "是否每次都强制更新 true/false" "${FORCE:-false}")"
  title "定时任务"
  CRON_SCHEDULE="$(prompt "Cron 表达式，默认每 5 分钟执行一次" "${CRON_SCHEDULE:-*/5 * * * *}")"
  CRON_LOG_FILE="$(prompt_private "Cron 日志文件（留空则不记录）" "${CRON_LOG_FILE:-}")"

  normalize_record_name
  configure_wan_site
  validate_config
  sanitize_cron_schedule
  save_config

  success "配置已保存到：$CONFIG_FILE"
}

fetch_wan_ip() {
  curl -fsS --connect-timeout 10 --max-time 30 "$WANIPSITE" | tr -d '[:space:]'
}

validate_wan_ip() {
  local ip="$1"
  if [ "$CFRECORD_TYPE" = "A" ]; then
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "获取到的公网 IPv4 地址格式异常：$ip"
  else
    [[ "$ip" == *:* ]] || die "获取到的公网 IPv6 地址格式异常：$ip"
  fi
}

cf_auth_mode() {
  case "${CF_AUTH_MODE:-key}" in
    token) printf '%s' "token" ;;
    key) printf '%s' "key" ;;
    *) die "认证方式只能是 key 或 token。" ;;
  esac
}

cf_curl() {
  # Store authentication headers in a temporary 600-permission curl config file
  # so API credentials do not appear in the curl process command line.
  ensure_state_dir
  local auth_config rc=0
  umask 077
  auth_config="$(mktemp "$STATE_DIR/curl-auth.XXXXXX")"
  chmod 600 "$auth_config"

  if [ "$(cf_auth_mode)" = "token" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$CFKEY" > "$auth_config"
  else
    {
      printf 'header = "X-Auth-Email: %s"\n' "$CFUSER"
      printf 'header = "X-Auth-Key: %s"\n' "$CFKEY"
    } > "$auth_config"
  fi

  curl -sS --connect-timeout 10 --max-time 30 \
    --config "$auth_config" "$@" || rc=$?
  rm -f "$auth_config"
  return "$rc"
}

api_response_failed() {
  printf '%s' "$1" | grep -Eq '"success"[[:space:]]*:[[:space:]]*false'
}

extract_first_id() {
  local json="$1"
  local id=""

  if command -v jq >/dev/null 2>&1; then
    id="$(printf '%s' "$json" | jq -r '.result[0].id // empty' 2>/dev/null || true)"
  fi

  if [ -z "$id" ]; then
    # Fallback for systems without jq; unlike grep -P this works with
    # standard sed implementations and tolerates spaces around the colon.
    id="$(printf '%s' "$json" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 || true)"
  fi

  printf '%s' "$id"
}

read_cached_ids() {
  CFZONE_ID=""
  CFRECORD_ID=""

  if [ ! -f "$ID_FILE" ]; then
    return 0
  fi

  local lines=()
  mapfile -t lines < "$ID_FILE" || true

  if [ "${#lines[@]}" -ge 4 ] \
    && [ "${lines[2]}" = "$CFZONE_NAME" ] \
    && [ "${lines[3]}" = "$CFRECORD_NAME" ]; then
    CFZONE_ID="${lines[0]}"
    CFRECORD_ID="${lines[1]}"
  fi
}

write_cached_ids() {
  ensure_state_dir
  umask 077
  {
    printf '%s\n' "$CFZONE_ID"
    printf '%s\n' "$CFRECORD_ID"
    printf '%s\n' "$CFZONE_NAME"
    printf '%s\n' "$CFRECORD_NAME"
  } > "$ID_FILE"
  chmod 600 "$ID_FILE"
}

write_wan_ip() {
  ensure_state_dir
  umask 077
  printf '%s\n' "$1" > "$WAN_IP_FILE"
  chmod 600 "$WAN_IP_FILE"
}

acquire_update_lock() {
  ensure_state_dir

  if command -v flock >/dev/null 2>&1; then
    umask 077
    exec 9>"$STATE_DIR/update.lock"
    if ! flock -n 9; then
      warning "已有另一个 DDNS 更新任务正在运行，跳过本次执行。"
      exec 9>&-
      return 1
    fi
    return 0
  fi

  # Fallback for minimal Linux systems without flock.
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$LOCK_DIR/pid"
    chmod 700 "$LOCK_DIR"
    return 0
  fi

  local old_pid=""
  if [ -f "$LOCK_DIR/pid" ]; then
    old_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
  fi

  if [ -n "$old_pid" ] && [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
    warning "已有另一个 DDNS 更新任务正在运行，跳过本次执行。"
    return 1
  fi

  rm -rf "$LOCK_DIR"
  mkdir "$LOCK_DIR" || die "无法创建 DDNS 更新锁。"
  printf '%s\n' "$$" > "$LOCK_DIR/pid"
  chmod 700 "$LOCK_DIR"
}

release_update_lock() {
  if command -v flock >/dev/null 2>&1; then
    flock -u 9 2>/dev/null || true
    exec 9>&- 2>/dev/null || true
  fi
  rm -rf "$LOCK_DIR"
}

update_dns() {
  ensure_curl_dependency
  ensure_state_dir

  normalize_record_name
  configure_wan_site
  validate_config

  [ -n "${CFKEY:-}" ] || die "缺少 Cloudflare 凭据。"
  if [ "$(cf_auth_mode)" = "key" ]; then
    [ -n "${CFUSER:-}" ] || die "Global API Key 模式下还需要 Cloudflare 邮箱。"
  fi

  if ! acquire_update_lock; then
    return 0
  fi

  local wan_ip old_wan_ip response zone_response record_response
  if ! wan_ip="$(fetch_wan_ip)"; then
    die "获取公网 IP 失败，请检查网络连接。"
  fi
  validate_wan_ip "$wan_ip"
  old_wan_ip=""

  if [ -f "$WAN_IP_FILE" ]; then
    old_wan_ip="$(tr -d '[:space:]' < "$WAN_IP_FILE" || true)"
  fi

  if [ "$wan_ip" = "$old_wan_ip" ] && [ "${FORCE:-false}" = "false" ]; then
    log "公网 IP 未变化：$wan_ip，跳过更新。"
    release_update_lock
    return 0
  fi

  read_cached_ids
  if [ -z "${CFZONE_ID:-}" ] || [ -z "${CFRECORD_ID:-}" ]; then
    log "正在查询 Cloudflare zone 与 record ID..."
    if ! zone_response="$(cf_curl -X GET "https://api.cloudflare.com/client/v4/zones" \
      --get --data-urlencode "name=$CFZONE_NAME" \
      -H "Content-Type: application/json")"; then
      die "查询 Cloudflare Zone 失败，请检查网络连接。"
    fi
    if api_response_failed "$zone_response"; then
      die "Cloudflare Zone 查询失败，请检查 API Key、邮箱和 Zone 权限。"
    fi
    CFZONE_ID="$(extract_first_id "$zone_response")"
    [ -n "$CFZONE_ID" ] || die "未找到对应的 Zone ID，请检查认证信息和 Zone 配置。"

    if ! record_response="$(cf_curl -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records" \
      --get --data-urlencode "name=$CFRECORD_NAME" \
      -H "Content-Type: application/json")"; then
      die "查询 Cloudflare DNS 记录失败，请检查网络连接。"
    fi
    if api_response_failed "$record_response"; then
      die "Cloudflare DNS 记录查询失败，请检查 API 权限和记录配置。"
    fi
    CFRECORD_ID="$(extract_first_id "$record_response")"
    [ -n "$CFRECORD_ID" ] || die "未找到对应的 DNS 记录，请检查记录配置。"
    write_cached_ids
  fi

  log "更新 DNS：目标主机名（已隐藏） -> $wan_ip"
  local payload
  payload="$(printf '{\"id\":\"%s\",\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":%s}' \
    "$CFZONE_ID" "$CFRECORD_TYPE" "$CFRECORD_NAME" "$wan_ip" "$CFTTL")"

  if ! response="$(cf_curl -X PUT "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID" \
    -H "Content-Type: application/json" \
    --data "$payload")"; then
    die "更新 Cloudflare DNS 失败，请检查网络连接。"
  fi

  if printf '%s' "$response" | grep -q '"success"[[:space:]]*:[[:space:]]*true'; then
    write_wan_ip "$wan_ip"
    success "更新成功。"
    release_update_lock
    return 0
  fi

  log "更新失败。"
  if printf '%s' "$response" | grep -q '"success"[[:space:]]*:[[:space:]]*false'; then
    log "提示：如果这里是 403，通常表示认证方式不对，或者当前账号/Token 没有该 Zone 的 DNS 编辑权限。"
    log "建议："
    log "  1) 如果你填的是 API Token，请在交互配置里选 token。"
    log "  2) 如果你填的是 Global API Key，请确认邮箱和 key 都正确。"
    log "  3) Token 需要至少有 Zone:Read 和 DNS:Edit 权限，并且作用范围要包含目标 Zone。"
  fi
  release_update_lock
  return 1
}

show_menu() {
  title "Cloudflare DDNS 管理菜单"
  printf '  %s1%s  交互式配置并立即更新\n' "$COLOR_OK" "$COLOR_RESET"
  printf '  %s2%s  手动执行一次更新\n' "$COLOR_OK" "$COLOR_RESET"
  printf '  %s3%s  安装/更新 crontab 任务\n' "$COLOR_OK" "$COLOR_RESET"
  printf '  %s4%s  移除 crontab 任务\n' "$COLOR_OK" "$COLOR_RESET"
  printf '  %s5%s  查看当前配置（敏感信息已隐藏）\n' "$COLOR_OK" "$COLOR_RESET"
  printf '  %s0%s  退出\n' "$COLOR_DIM" "$COLOR_RESET"
}

show_config() {
  validate_auth_mode
  title "当前配置（敏感信息已隐藏）"
  printf '  认证方式     : %s\n' "${CF_AUTH_MODE:-key}"
  if [ "$(cf_auth_mode)" = "key" ]; then
    printf '  API Key      : %s\n' "$(mask_value "${CFKEY:-}")"
    printf '  Cloudflare 邮箱: %s\n' "$(mask_email "${CFUSER:-}")"
  else
    printf '  API Token    : %s\n' "$(mask_value "${CFKEY:-}")"
  fi
  printf '  Zone         : %s\n' "$(mask_private "${CFZONE_NAME:-}")"
  printf '  DNS 记录     : %s\n' "$(mask_private "${CFRECORD_NAME:-}")"
  printf '  记录类型     : %s\n' "${CFRECORD_TYPE:-A}"
  printf '  TTL          : %s\n' "${CFTTL:-120}"
  printf '  强制更新     : %s\n' "${FORCE:-false}"
  printf '  Cron 计划    : %s\n' "${CRON_SCHEDULE:-未设置}"
  printf '  Cron 日志    : %s\n' "${CRON_LOG_FILE:-未记录}"
  printf '  配置文件     : %s\n' "$CONFIG_FILE"
  printf '  状态目录     : %s\n' "$STATE_DIR"
}

parse_legacy_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -k)
        [ "$#" -ge 2 ] || die "-k 需要一个参数。"
        CFKEY="$2"
        shift 2
        ;;
      -u)
        [ "$#" -ge 2 ] || die "-u 需要一个参数。"
        CFUSER="$2"
        shift 2
        ;;
      -h)
        [ "$#" -ge 2 ] || die "-h 需要一个参数。"
        CFRECORD_NAME="$2"
        shift 2
        ;;
      -z)
        [ "$#" -ge 2 ] || die "-z 需要一个参数。"
        CFZONE_NAME="$2"
        shift 2
        ;;
      -t)
        [ "$#" -ge 2 ] || die "-t 需要一个参数。"
        CFRECORD_TYPE="$2"
        shift 2
        ;;
      -f)
        [ "$#" -ge 2 ] || die "-f 需要一个参数。"
        FORCE="$2"
        shift 2
        ;;
      --auth)
        [ "$#" -ge 2 ] || die "--auth 需要 key 或 token。"
        CF_AUTH_MODE="$2"
        shift 2
        ;;
      --auth=*)
        CF_AUTH_MODE="${1#--auth=}"
        shift
        ;;
      --force)
        FORCE="true"
        shift
        ;;
      --config)
        [ "$#" -ge 2 ] || die "--config 需要一个文件路径。"
        CONFIG_FILE="$2"
        shift 2
        ;;
      --config=*)
        CONFIG_FILE="${1#--config=}"
        shift
        ;;
      --install-cron|--remove-cron|--show-config|--run)
        shift
        ;;
      --help)
        show_help
        exit 0
        ;;
      --)
        shift
        break
        ;;
      *)
        die "未知参数：$1。使用 --help 查看帮助。"
        ;;
    esac
  done

  [ "$#" -eq 0 ] || die "未知参数：$1。使用 --help 查看帮助。"
}

capture_config_path() {
  local args=("$@")
  local i=0
  while [ "$i" -lt "$#" ]; do
    case "${args[$i]}" in
      --config)
        if [ $((i + 1)) -lt "$#" ]; then
          CONFIG_FILE="${args[$((i + 1))]}"
        fi
        ;;
      --config=*)
        CONFIG_FILE="${args[$i]#--config=}"
        ;;
    esac
    i=$((i + 1))
  done
}

main() {
  case "${1:-}" in
    --help)
      show_help
      ;;
    --install-cron)
      capture_config_path "$@"
      load_config
      parse_legacy_args "$@"
      install_cron_job
      ;;
    --remove-cron)
      remove_cron_job
      ;;
    --show-config)
      capture_config_path "$@"
      load_config
      parse_legacy_args "$@"
      show_config
      ;;
    --run)
      capture_config_path "$@"
      load_config
      parse_legacy_args "$@"
      update_dns
      ;;
    -*)
      capture_config_path "$@"
      load_config
      parse_legacy_args "$@"
      update_dns
      ;;
    *)
      load_config
      while true; do
        show_menu
        choice="$(prompt "请选择" "1")"
        case "$choice" in
          1)
            interactive_configure
            update_dns
            if ask_yes_no "安装/更新 crontab 任务吗？" "Y"; then
              install_cron_job
            fi
            ;;
          2)
            update_dns
            ;;
          3)
            install_cron_job
            ;;
          4)
            remove_cron_job
            ;;
          5)
            show_config
            ;;
          0)
            exit 0
            ;;
          *)
            log "无效选项，请重新输入。"
            ;;
        esac
      done
      ;;
  esac
}

main "$@"
