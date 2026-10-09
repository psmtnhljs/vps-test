#!/usr/bin/env bash
# Xray 安装与 socks/vmess/shadowsocks 配置工具。

set -euo pipefail
umask 077

readonly SCRIPT_VERSION="2.0.0"
readonly XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
readonly XRAY_BIN="/usr/local/bin/xrayL"
readonly CONFIG_DIR="/etc/xrayL"
readonly CONFIG_FILE="${CONFIG_DIR}/config.toml"
readonly SERVICE_FILE="/etc/systemd/system/xrayL.service"
readonly SERVICE_NAME="xrayL.service"
readonly BACKUP_ROOT="/var/backups/vps-test"
readonly DEFAULT_START_PORT=20000
readonly DEFAULT_SOCKS_USERNAME="userb"
readonly DEFAULT_WS_PATH="/ws"
readonly DEFAULT_SS_METHOD="aes-256-gcm"

TEMP_DIR=""
GENERATED_SECRET=""
GENERATED_UUID=""
XRAY_ASSET=""
XRAY_SERVICE_USER="xray"
XRAY_SERVICE_GROUP="xray"
LAST_BINARY_BACKUP=""
LAST_SERVICE_BACKUP=""
declare -a IP_ADDRESSES=()

if [[ -t 1 ]]; then
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
    C_RESET=$'\033[0m'
else
    C_GREEN=""
    C_YELLOW=""
    C_RED=""
    C_CYAN=""
    C_RESET=""
fi

info() { printf '%s[i]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok() { printf '%s[✓]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die() { printf '%s[✗] %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

usage() {
    cat <<EOF
用法：
  sudo bash xrayQ.sh socks
  sudo bash xrayQ.sh vmess
  sudo bash xrayQ.sh ss
  sudo bash xrayQ.sh --update
  sudo bash xrayQ.sh --uninstall
  sudo bash xrayQ.sh --check

选项：
  socks              创建 SOCKS 入站，密码留空时随机生成
  vmess              创建 VMess WebSocket 入站
  ss                 创建 Shadowsocks 入站，密码留空时随机生成
  --update           重新下载并校验固定版本 Xray
  --uninstall        备份后卸载 XrayL，需要输入 REMOVE 确认
  --check            只查看安装和服务状态
  -h, --help         显示帮助
  -V, --version      显示脚本和预设 Xray 版本

可在执行时用环境变量固定其他发行版：
  sudo XRAY_VERSION=v26.3.27 bash xrayQ.sh --update
EOF
}

cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请使用 root 权限运行： sudo bash xrayQ.sh ..."
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 || die "当前系统没有 systemctl，脚本暂不支持该启动方式"
}

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        GENERATED_SECRET="$(openssl rand -hex 16)"
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        GENERATED_SECRET="$(tr -d '-' </proc/sys/kernel/random/uuid)"
    elif command -v od >/dev/null 2>&1; then
        GENERATED_SECRET="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    else
        GENERATED_SECRET="$(date +%s%N)-$RANDOM-$RANDOM"
    fi
}

generate_uuid() {
    if [[ -r /proc/sys/kernel/random/uuid ]]; then
        GENERATED_UUID="$(</proc/sys/kernel/random/uuid)"
    elif command -v uuidgen >/dev/null 2>&1; then
        GENERATED_UUID="$(uuidgen)"
    elif command -v python3 >/dev/null 2>&1; then
        GENERATED_UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    else
        die "无法生成 UUID，请安装 uuidgen 或 Python 3"
    fi
}

toml_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

detect_asset() {
    [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"
    case "$(uname -m)" in
        x86_64|amd64) XRAY_ASSET="Xray-linux-64.zip" ;;
        i386|i486|i586|i686) XRAY_ASSET="Xray-linux-32.zip" ;;
        aarch64|arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;;
        armv7l|armv7) XRAY_ASSET="Xray-linux-arm32-v7a.zip" ;;
        s390x) XRAY_ASSET="Xray-linux-s390x.zip" ;;
        *) die "暂不支持的 CPU 架构：$(uname -m)" ;;
    esac
}

install_dependencies() {
    local -a missing=()
    local command_name

    for command_name in curl unzip sha256sum install; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    ((${#missing[@]} == 0)) && return 0

    warn "缺少依赖：${missing[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl unzip coreutils
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl unzip coreutils
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl unzip coreutils
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl unzip coreutils
    else
        die "无法识别包管理器，请手动安装 curl、unzip 和 coreutils"
    fi

    for command_name in curl unzip sha256sum install; do
        command -v "$command_name" >/dev/null 2>&1 || die "依赖安装后仍找不到：$command_name"
    done
}

ensure_service_user() {
    if id "$XRAY_SERVICE_USER" >/dev/null 2>&1; then
        XRAY_SERVICE_GROUP="$(id -gn "$XRAY_SERVICE_USER")"
        return 0
    fi

    if command -v useradd >/dev/null 2>&1; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
            --user-group "$XRAY_SERVICE_USER"
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -s /sbin/nologin "$XRAY_SERVICE_USER"
    else
        die "无法创建 Xray 专用用户"
    fi
    XRAY_SERVICE_GROUP="$(id -gn "$XRAY_SERVICE_USER")"
}

write_service_file() {
    local backup=""
    LAST_SERVICE_BACKUP=""
    if [[ -f "$SERVICE_FILE" ]]; then
        backup="${SERVICE_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        cp -a "$SERVICE_FILE" "$backup"
        LAST_SERVICE_BACKUP="$backup"
        info "原服务文件已备份：$backup"
    fi

    cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=XrayL Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${XRAY_SERVICE_USER}
Group=${XRAY_SERVICE_GROUP}
ExecStart=${XRAY_BIN} run -config ${CONFIG_FILE}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$SERVICE_FILE"
    systemctl daemon-reload
}

install_xray_binary() {
    local base_url zip_file digest_file expected actual backup=""

    detect_asset
    install_dependencies
    ensure_service_user
    TEMP_DIR="$(mktemp -d)"
    base_url="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"
    zip_file="${TEMP_DIR}/${XRAY_ASSET}"
    digest_file="${zip_file}.dgst"

    info "下载 Xray ${XRAY_VERSION} (${XRAY_ASSET})..."
    curl --fail --location --show-error --connect-timeout 10 --max-time 180 --retry 2 \
        --output "$zip_file" "${base_url}/${XRAY_ASSET}"
    curl --fail --location --show-error --connect-timeout 10 --max-time 60 --retry 2 \
        --output "$digest_file" "${base_url}/${XRAY_ASSET}.dgst"

    expected="$(awk -F'= *' '/^SHA2-256=/{print tolower($2); exit}' "$digest_file")"
    actual="$(sha256sum "$zip_file" | awk '{print tolower($1)}')"
    [[ -n "$expected" && "$actual" == "$expected" ]] \
        || die "Xray 压缩包 SHA-256 校验失败，未安装"
    ok "下载校验通过"

    unzip -j -q "$zip_file" xray -d "$TEMP_DIR"
    [[ -x "${TEMP_DIR}/xray" ]] || chmod +x "${TEMP_DIR}/xray"

    LAST_BINARY_BACKUP=""
    if [[ -f "$XRAY_BIN" ]]; then
        mkdir -p "$BACKUP_ROOT"
        backup="${BACKUP_ROOT}/xrayL.binary.$(date +%Y%m%d_%H%M%S)"
        cp -a "$XRAY_BIN" "$backup"
        LAST_BINARY_BACKUP="$backup"
        info "原程序已备份：$backup"
    fi
    install -m 0755 "${TEMP_DIR}/xray" "$XRAY_BIN"
    write_service_file
    ok "Xray ${XRAY_VERSION} 已安装"

    rm -rf -- "$TEMP_DIR"
    TEMP_DIR=""
}

collect_ip_addresses() {
    local address existing
    IP_ADDRESSES=()

    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r address; do
            address="${address%%/*}"
            [[ -n "$address" && "$address" != 127.* && "$address" != "::1" ]] || continue
            existing=" $(printf '%s ' "${IP_ADDRESSES[@]:-}") "
            [[ "$existing" == *" $address "* ]] || IP_ADDRESSES+=("$address")
        done < <(ip -o addr show scope global up 2>/dev/null | awk '{print $4}')
    fi

    if ((${#IP_ADDRESSES[@]} == 0)); then
        while IFS= read -r address; do
            [[ -n "$address" ]] && IP_ADDRESSES+=("$address")
        done < <(hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d')
    fi
    ((${#IP_ADDRESSES[@]} > 0)) || die "未找到可用的本机 IP 地址"
}

validate_start_port() {
    local port="$1"
    local count="$2"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    ((port >= 1024 && port <= 65535 && port + count - 1 <= 65535))
}

validate_xray_config() {
    local candidate="$1"
    if "$XRAY_BIN" run -test -config "$candidate" >/dev/null 2>&1; then
        return 0
    fi
    "$XRAY_BIN" -test -config "$candidate" >/dev/null 2>&1
}

build_config() {
    local config_type="$1"
    local output_file="$2"
    local start_port="$3"
    local username="$4"
    local password="$5"
    local uuid="$6"
    local ws_path="$7"
    local ss_method="$8"
    local i port tag address

    : >"$output_file"
    for ((i = 0; i < ${#IP_ADDRESSES[@]}; i++)); do
        port=$((start_port + i))
        tag="tag_$((i + 1))"
        address="$(toml_escape "${IP_ADDRESSES[i]}")"

        {
            printf '[[inbounds]]\nport = %s\n' "$port"
            case "$config_type" in
                socks)
                    printf 'protocol = "socks"\ntag = "%s"\n' "$tag"
                    printf '[inbounds.settings]\nauth = "password"\nudp = true\nip = "%s"\n' "$address"
                    printf '[[inbounds.settings.accounts]]\nuser = "%s"\npass = "%s"\n' \
                        "$(toml_escape "$username")" "$(toml_escape "$password")"
                    ;;
                vmess)
                    printf 'protocol = "vmess"\ntag = "%s"\n' "$tag"
                    printf '[inbounds.settings]\n[[inbounds.settings.clients]]\nid = "%s"\n' "$(toml_escape "$uuid")"
                    printf '[inbounds.streamSettings]\nnetwork = "ws"\n'
                    printf '[inbounds.streamSettings.wsSettings]\npath = "%s"\n' "$(toml_escape "$ws_path")"
                    ;;
                ss)
                    printf 'protocol = "shadowsocks"\ntag = "%s"\n' "$tag"
                    printf '[inbounds.settings]\nmethod = "%s"\npassword = "%s"\nnetwork = "tcp,udp"\n' \
                        "$ss_method" "$(toml_escape "$password")"
                    ;;
            esac
            printf '\n[[outbounds]]\nsendThrough = "%s"\nprotocol = "freedom"\ntag = "%s"\n\n' "$address" "$tag"
            printf '[[routing.rules]]\ntype = "field"\ninboundTag = "%s"\noutboundTag = "%s"\n\n' "$tag" "$tag"
        } >>"$output_file"
    done
}

configure_xray() {
    local config_type="$1"
    local start_port username="" password="" uuid="" ws_path="" ss_method="$DEFAULT_SS_METHOD"
    local generated_password=0 temp_config backup=""

    collect_ip_addresses
    read -r -p "起始端口 (默认 ${DEFAULT_START_PORT}): " start_port
    start_port="${start_port:-$DEFAULT_START_PORT}"
    validate_start_port "$start_port" "${#IP_ADDRESSES[@]}" \
        || die "端口无效；Xray 使用非 root 用户运行，起始端口需在 1024-65535 之间"

    case "$config_type" in
        socks)
            read -r -p "SOCKS 账号 (默认 ${DEFAULT_SOCKS_USERNAME}): " username
            username="${username:-$DEFAULT_SOCKS_USERNAME}"
            read -r -s -p "SOCKS 密码 (留空随机生成): " password
            printf '\n'
            if [[ -z "$password" ]]; then
                generate_secret
                password="$GENERATED_SECRET"
                generated_password=1
            fi
            ;;
        vmess)
            warn "Xray ${XRAY_VERSION} 已将 VMess 和 WebSocket 标记为过时功能；此选项仅保留现有兼容用途"
            generate_uuid
            read -r -p "UUID (默认随机生成): " uuid
            uuid="${uuid:-$GENERATED_UUID}"
            read -r -p "WebSocket 路径 (默认 ${DEFAULT_WS_PATH}): " ws_path
            ws_path="${ws_path:-$DEFAULT_WS_PATH}"
            [[ "$ws_path" == /* ]] || die "WebSocket 路径必须以 / 开头"
            ;;
        ss)
            warn "Xray ${XRAY_VERSION} 已将内置 Shadowsocks 标记为过时功能；新部署建议后续迁移到 VLESS"
            read -r -s -p "Shadowsocks 密码 (留空随机生成): " password
            printf '\n'
            if [[ -z "$password" ]]; then
                generate_secret
                password="$GENERATED_SECRET"
                generated_password=1
            fi
            read -r -p "加密方式 (默认 ${DEFAULT_SS_METHOD}): " ss_method
            ss_method="${ss_method:-$DEFAULT_SS_METHOD}"
            case "$ss_method" in
                aes256|aes-256) ss_method="aes-256-gcm" ;;
                aes128|aes-128) ss_method="aes-128-gcm" ;;
                chacha20) ss_method="chacha20-poly1305" ;;
                aes-256-gcm|aes-128-gcm|chacha20-poly1305) ;;
                *) die "不支持的加密方式：$ss_method" ;;
            esac
            ;;
        *) die "类型错误，仅支持 socks、vmess 和 ss" ;;
    esac

    ensure_service_user
    install -d -m 0750 -o root -g "$XRAY_SERVICE_GROUP" "$CONFIG_DIR"
    temp_config="$(mktemp "${CONFIG_DIR}/config.toml.tmp.XXXXXX")"
    build_config "$config_type" "$temp_config" "$start_port" "$username" "$password" "$uuid" "$ws_path" "$ss_method"
    chown root:"$XRAY_SERVICE_GROUP" "$temp_config"
    chmod 0640 "$temp_config"

    if ! validate_xray_config "$temp_config"; then
        rm -f -- "$temp_config"
        die "Xray 配置校验失败，原配置未修改"
    fi

    if [[ -f "$CONFIG_FILE" ]]; then
        backup="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        cp -a "$CONFIG_FILE" "$backup"
        info "原配置已备份：$backup"
    fi
    mv -f -- "$temp_config" "$CONFIG_FILE"
    write_service_file
    systemctl enable "$SERVICE_NAME" >/dev/null

    if ! systemctl restart "$SERVICE_NAME"; then
        if [[ -n "$backup" && -f "$backup" ]]; then
            cp -a "$backup" "$CONFIG_FILE"
            systemctl restart "$SERVICE_NAME" || true
            die "Xray 启动失败，已恢复原配置"
        fi
        die "Xray 启动失败，请运行 journalctl -u ${SERVICE_NAME} 查看日志"
    fi

    ok "${config_type} 配置完成，服务已启动"
    printf '端口范围：%s-%s\n' "$start_port" "$((start_port + ${#IP_ADDRESSES[@]} - 1))"
    case "$config_type" in
        socks)
            printf 'SOCKS 账号：%s\nSOCKS 密码：%s\n' "$username" "$password"
            ;;
        vmess)
            printf 'UUID：%s\nWebSocket 路径：%s\n' "$uuid" "$ws_path"
            ;;
        ss)
            printf 'Shadowsocks 密码：%s\n加密方式：%s\n' "$password" "$ss_method"
            ;;
    esac
    ((generated_password)) && warn "上述密码由脚本随机生成，请立即保存到安全位置"
    warn "如果已启用防火墙，请手动放行上述端口范围"
}

show_status() {
    printf 'Xray 程序：%s\n' "$([[ -x "$XRAY_BIN" ]] && echo '已安装' || echo '未安装')"
    printf '配置文件：%s\n' "$([[ -f "$CONFIG_FILE" ]] && echo "$CONFIG_FILE" || echo '未找到')"
    printf '服务文件：%s\n' "$([[ -f "$SERVICE_FILE" ]] && echo "$SERVICE_FILE" || echo '未找到')"
    if command -v systemctl >/dev/null 2>&1 && [[ -f "$SERVICE_FILE" ]]; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            printf '服务状态：运行中\n'
        else
            printf '服务状态：未运行\n'
        fi
    fi
    if [[ -x "$XRAY_BIN" ]]; then
        "$XRAY_BIN" version 2>/dev/null | head -n 1 || true
    fi
}

uninstall_xray() {
    local answer backup
    printf '将停止服务并移除：\n  %s\n  %s\n  %s\n' "$XRAY_BIN" "$CONFIG_DIR" "$SERVICE_FILE"
    printf '\n可恢复边界：上述文件会备份；运行状态、防火墙规则和客户端配置不在自动恢复范围内。\n'
    read -r -p '输入 REMOVE 继续：' answer
    [[ "$answer" == "REMOVE" ]] || { info "已取消"; return 0; }

    mkdir -p "$BACKUP_ROOT"
    backup="${BACKUP_ROOT}/xrayL.$(date +%Y%m%d_%H%M%S).tar.gz"
    local -a items=()
    [[ -e "$XRAY_BIN" ]] && items+=("${XRAY_BIN#/}")
    [[ -e "$CONFIG_DIR" ]] && items+=("${CONFIG_DIR#/}")
    [[ -e "$SERVICE_FILE" ]] && items+=("${SERVICE_FILE#/}")
    if ((${#items[@]})); then
        tar -czf "$backup" -C / "${items[@]}" || die "备份失败，已取消卸载"
        ok "备份已保存：$backup"
    fi

    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f -- "$SERVICE_FILE" "$XRAY_BIN"
    rm -rf -- "$CONFIG_DIR"
    systemctl daemon-reload
    ok "XrayL 已卸载"
    [[ -f "$backup" ]] && printf '恢复文件：sudo tar -xzf %q -C / && sudo systemctl daemon-reload\n' "$backup"
}

main() {
    local action="${1:-}"

    case "$action" in
        -h|--help) usage; return 0 ;;
        -V|--version)
            printf 'xrayQ.sh %s (Xray %s)\n' "$SCRIPT_VERSION" "$XRAY_VERSION"
            return 0
            ;;
        --check) show_status; return 0 ;;
    esac

    require_root
    require_systemd

    case "$action" in
        --update)
            install_xray_binary
            if [[ -f "$CONFIG_FILE" ]]; then
                if ! systemctl restart "$SERVICE_NAME"; then
                    warn "更新后服务启动失败，正在恢复原程序和服务文件"
                    [[ -n "$LAST_BINARY_BACKUP" && -f "$LAST_BINARY_BACKUP" ]] \
                        && cp -a "$LAST_BINARY_BACKUP" "$XRAY_BIN"
                    [[ -n "$LAST_SERVICE_BACKUP" && -f "$LAST_SERVICE_BACKUP" ]] \
                        && cp -a "$LAST_SERVICE_BACKUP" "$SERVICE_FILE"
                    systemctl daemon-reload
                    systemctl restart "$SERVICE_NAME" || true
                    die "Xray 更新失败，已尝试恢复更新前版本"
                fi
            fi
            ;;
        --uninstall) uninstall_xray ;;
        socks|vmess|ss)
            [[ -x "$XRAY_BIN" ]] || install_xray_binary
            configure_xray "$action"
            ;;
        "")
            read -r -p "选择配置类型 (socks/vmess/ss): " action
            case "$action" in
                socks|vmess|ss)
                    [[ -x "$XRAY_BIN" ]] || install_xray_binary
                    configure_xray "$action"
                    ;;
                *) die "未选择有效类型" ;;
            esac
            ;;
        *) die "未知参数：$action（使用 --help 查看帮助）" ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
