#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
CONFIG_FILE="${HOME}/.ddns-cloudflare.conf"
STATE_DIR="${HOME}/.ddns-cloudflare"
WAN_IP_FILE="${STATE_DIR}/wan_ip.txt"
ID_FILE="${STATE_DIR}/record_id.txt"

CFKEY=""
CFUSER=""
CFZONE_NAME=""
CFRECORD_NAME=""
CFRECORD_TYPE="A"
CFTTL="120"
FORCE="false"
CRON_SCHEDULE="*/5 * * * *"
CRON_LOG_FILE="${STATE_DIR}/ddns.log"
WANIPSITE="http://ipv4.icanhazip.com"

log() {
  printf '%s\n' "$*"
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

prompt_secret() {
  local message="$1"
  local default="${2:-}"
  local reply=""

  if [ -n "$default" ]; then
    read -r -s -p "${message} [hidden, Enter 保留默认值]: " reply
  else
    read -r -s -p "${message}: " reply
  fi
  printf '\n'
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

ensure_dependencies() {
  command -v curl >/dev/null 2>&1 || die "缺少 curl，请先安装。"
  command -v crontab >/dev/null 2>&1 || die "缺少 crontab，请先安装 cron。"
}

ensure_state_dir() {
  mkdir -p "$STATE_DIR"
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
  cat > "$CONFIG_FILE" <<EOF
CFKEY=$(printf '%q' "$CFKEY")
CFUSER=$(printf '%q' "$CFUSER")
CFZONE_NAME=$(printf '%q' "$CFZONE_NAME")
CFRECORD_NAME=$(printf '%q' "$CFRECORD_NAME")
CFRECORD_TYPE=$(printf '%q' "$CFRECORD_TYPE")
CFTTL=$(printf '%q' "$CFTTL")
FORCE=$(printf '%q' "$FORCE")
CRON_SCHEDULE=$(printf '%q' "$CRON_SCHEDULE")
CRON_LOG_FILE=$(printf '%q' "$CRON_LOG_FILE")
EOF
}

configure_wan_site() {
  case "$CFRECORD_TYPE" in
    A) WANIPSITE="http://ipv4.icanhazip.com" ;;
    AAAA) WANIPSITE="http://ipv6.icanhazip.com" ;;
    *) die "CFRECORD_TYPE 只能是 A 或 AAAA。" ;;
  esac
}

normalize_record_name() {
  if [ -n "$CFZONE_NAME" ] && [ "$CFRECORD_NAME" != "$CFZONE_NAME" ] && ! [ -z "${CFRECORD_NAME##*$CFZONE_NAME}" ]; then
    CFRECORD_NAME="$CFRECORD_NAME.$CFZONE_NAME"
    log "=> 主机名不是完整 FQDN，已自动补全为：$CFRECORD_NAME"
  fi
}

sanitize_cron_schedule() {
  CRON_SCHEDULE="$(trim "$CRON_SCHEDULE")"
  [ -n "$CRON_SCHEDULE" ] || CRON_SCHEDULE="*/5 * * * *"
}

show_help() {
  cat <<EOF
Usage:
  bash ddns.sh
  bash ddns.sh --run
  bash ddns.sh --install-cron
  bash ddns.sh --remove-cron
  bash ddns.sh --show-config

Old flags are still supported:
  -k <api-key> -u <email> -h <host> -z <zone> -t <A|AAAA> -f <true|false>

Interactive mode will guide you through configuration and save it to:
  $CONFIG_FILE
EOF
}

install_cron_job() {
  ensure_dependencies
  ensure_state_dir

  [ -f "$CONFIG_FILE" ] || die "未找到配置文件，请先运行交互配置并保存。"

  sanitize_cron_schedule

  local tmp_file
  tmp_file="$(mktemp)"
  crontab -l 2>/dev/null | grep -v -F "# ddns.sh managed by script" > "$tmp_file" || :

  {
    cat "$tmp_file"
    printf '# ddns.sh managed by script\n'
    if [ -n "${CRON_LOG_FILE:-}" ]; then
      printf '%s bash "%s" --run >> "%s" 2>&1\n' "$CRON_SCHEDULE" "$SCRIPT_PATH" "$CRON_LOG_FILE"
    else
      printf '%s bash "%s" --run\n' "$CRON_SCHEDULE" "$SCRIPT_PATH"
    fi
  } | crontab -

  rm -f "$tmp_file"
  log "已安装/更新 crontab：$CRON_SCHEDULE"
  [ -z "${CRON_LOG_FILE:-}" ] || log "日志文件：$CRON_LOG_FILE"
}

remove_cron_job() {
  ensure_dependencies
  local tmp_file
  tmp_file="$(mktemp)"
  crontab -l 2>/dev/null | grep -v -F "# ddns.sh managed by script" > "$tmp_file" || :
  crontab "$tmp_file"
  rm -f "$tmp_file"
  log "已移除与本脚本相关的 crontab 任务。"
}

interactive_configure() {
  ensure_state_dir
  log "Cloudflare DDNS 交互配置"
  log "直接回车可保留已有值。"
  log ""

  CFKEY="$(prompt_secret "Cloudflare Global API Key" "${CFKEY:-}")"
  CFUSER="$(prompt "Cloudflare 邮箱" "${CFUSER:-}")"
  CFZONE_NAME="$(prompt "根域名 / Zone，例如 example.com" "${CFZONE_NAME:-}")"
  CFRECORD_NAME="$(prompt "要更新的主机名，例如 home.example.com 或 home" "${CFRECORD_NAME:-}")"
  CFRECORD_TYPE="$(prompt "记录类型 A/AAAA" "${CFRECORD_TYPE:-A}")"
  CFTTL="$(prompt "TTL（120-86400）" "${CFTTL:-120}")"
  FORCE="$(prompt "是否每次都强制更新 true/false" "${FORCE:-false}")"
  CRON_SCHEDULE="$(prompt "Cron 表达式，默认每 5 分钟执行一次" "${CRON_SCHEDULE:-*/5 * * * *}")"
  CRON_LOG_FILE="$(prompt "Cron 日志文件（留空则不记录）" "${CRON_LOG_FILE:-}")"

  normalize_record_name
  configure_wan_site
  save_config

  log ""
  log "配置已保存到：$CONFIG_FILE"
}

fetch_wan_ip() {
  curl -fsS "$WANIPSITE" | tr -d '[:space:]'
}

read_cached_ids() {
  CFZONE_ID=""
  CFRECORD_ID=""

  if [ ! -f "$ID_FILE" ]; then
    return 0
  fi

  local lines=()
  mapfile -t lines < "$ID_FILE" || true

  if [ "${#lines[@]}" -ge 4 ]; then
    CFZONE_ID="${lines[0]}"
    CFRECORD_ID="${lines[1]}"
  elif [ "${#lines[@]}" -ge 2 ]; then
    CFZONE_ID="${lines[0]}"
    CFRECORD_ID="${lines[1]}"
  fi
}

write_cached_ids() {
  {
    printf '%s\n' "$CFZONE_ID"
    printf '%s\n' "$CFRECORD_ID"
    printf '%s\n' "$CFZONE_NAME"
    printf '%s\n' "$CFRECORD_NAME"
  } > "$ID_FILE"
}

update_dns() {
  ensure_dependencies
  ensure_state_dir
  load_config

  normalize_record_name
  configure_wan_site

  [ -n "${CFKEY:-}" ] || die "缺少 Cloudflare API Key。"
  [ -n "${CFUSER:-}" ] || die "缺少 Cloudflare 邮箱。"
  [ -n "${CFZONE_NAME:-}" ] || die "缺少 Zone 域名。"
  [ -n "${CFRECORD_NAME:-}" ] || die "缺少记录主机名。"

  local wan_ip old_wan_ip response
  wan_ip="$(fetch_wan_ip)"
  old_wan_ip=""

  if [ -f "$WAN_IP_FILE" ]; then
    old_wan_ip="$(tr -d '[:space:]' < "$WAN_IP_FILE" || true)"
  fi

  if [ "$wan_ip" = "$old_wan_ip" ] && [ "${FORCE:-false}" = "false" ]; then
    log "公网 IP 未变化：$wan_ip，跳过更新。"
    return 0
  fi

  read_cached_ids
  if [ -z "${CFZONE_ID:-}" ] || [ -z "${CFRECORD_ID:-}" ]; then
    log "正在查询 Cloudflare zone 与 record ID..."
    CFZONE_ID="$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones?name=$CFZONE_NAME" \
      -H "X-Auth-Email: $CFUSER" \
      -H "X-Auth-Key: $CFKEY" \
      -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)"

    CFRECORD_ID="$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records?name=$CFRECORD_NAME" \
      -H "X-Auth-Email: $CFUSER" \
      -H "X-Auth-Key: $CFKEY" \
      -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)"

    [ -n "$CFZONE_ID" ] || die "未找到对应的 zone ID。"
    [ -n "$CFRECORD_ID" ] || die "未找到对应的 record ID。"
    write_cached_ids
  fi

  log "更新 DNS：$CFRECORD_NAME -> $wan_ip"
  response="$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID" \
    -H "X-Auth-Email: $CFUSER" \
    -H "X-Auth-Key: $CFKEY" \
    -H "Content-Type: application/json" \
    --data "{\"id\":\"$CFZONE_ID\",\"type\":\"$CFRECORD_TYPE\",\"name\":\"$CFRECORD_NAME\",\"content\":\"$wan_ip\",\"ttl\":$CFTTL}")"

  if printf '%s' "$response" | grep -q '"success":true'; then
    printf '%s\n' "$wan_ip" > "$WAN_IP_FILE"
    log "更新成功。"
    return 0
  fi

  log "更新失败，返回内容："
  log "$response"
  return 1
}

show_menu() {
  echo
  echo "Cloudflare DDNS 管理菜单"
  echo "1) 交互式配置并立即更新"
  echo "2) 手动执行一次更新"
  echo "3) 安装/更新 crontab 任务"
  echo "4) 移除 crontab 任务"
  echo "5) 查看当前配置"
  echo "0) 退出"
}

show_config() {
  load_config
  echo
  echo "当前配置："
  printf '  CONFIG_FILE: %s\n' "$CONFIG_FILE"
  printf '  CFUSER: %s\n' "${CFUSER:-}"
  printf '  CFZONE_NAME: %s\n' "${CFZONE_NAME:-}"
  printf '  CFRECORD_NAME: %s\n' "${CFRECORD_NAME:-}"
  printf '  CFRECORD_TYPE: %s\n' "${CFRECORD_TYPE:-}"
  printf '  CFTTL: %s\n' "${CFTTL:-}"
  printf '  FORCE: %s\n' "${FORCE:-}"
  printf '  CRON_SCHEDULE: %s\n' "${CRON_SCHEDULE:-}"
  printf '  CRON_LOG_FILE: %s\n' "${CRON_LOG_FILE:-}"
  printf '  STATE_DIR: %s\n' "$STATE_DIR"
}

parse_legacy_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -k)
        CFKEY="${2:-}"
        shift 2
        ;;
      -u)
        CFUSER="${2:-}"
        shift 2
        ;;
      -h)
        CFRECORD_NAME="${2:-}"
        shift 2
        ;;
      -z)
        CFZONE_NAME="${2:-}"
        shift 2
        ;;
      -t)
        CFRECORD_TYPE="${2:-}"
        shift 2
        ;;
      -f)
        FORCE="${2:-true}"
        shift 2
        ;;
      --force)
        FORCE="true"
        shift
        ;;
      --config)
        CONFIG_FILE="${2:-$CONFIG_FILE}"
        shift 2
        ;;
      --config=*)
        CONFIG_FILE="${1#--config=}"
        shift
        ;;
      --run)
        shift
        ;;
      --install-cron|--remove-cron|--show-config)
        break
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
        break
        ;;
    esac
  done
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
