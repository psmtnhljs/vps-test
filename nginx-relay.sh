#!/usr/bin/env bash
# nginx-relay.sh
# 交互式 Nginx TCP/UDP 端口转发管理脚本
#
# 功能：
#   - 首次运行检测 IPv4/IPv6、安装 Nginx 与 stream 模块
#   - 支持保留 Web 服务或仅作为端口转发服务
#   - 支持静态 IP 转发、域名/DDNS 转发
#   - 自动按目标地址族匹配本机 proxy_bind 地址与监听地址
#   - 支持多 IP 服务器选择具体的出站 IP

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly NGINX_CONF="/etc/nginx/nginx.conf"
readonly RELAY_DIR="/etc/nginx/stream.d"
readonly RELAY_CONF="${RELAY_DIR}/nginx-relay.conf"
readonly RELAY_DB="${RELAY_DIR}/nginx-relay.db"
readonly STATE_FILE="/etc/nginx/.nginx-relay.state"
readonly BACKUP_DIR="/etc/nginx/nginx-relay-backups"
readonly STREAM_INCLUDE="/etc/nginx/stream.d/*.conf"

MODE=""
STREAM_INCLUDE_MODE=""
HAS_IPV4=0
HAS_IPV6=0
LOCAL_IPV4=()
LOCAL_IPV6=()
SELECTED_BIND_IP=""
SELECTED_FAMILY=""
SELECTED_PROTOCOL=""

C_RESET='\033[0m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_BLUE='\033[34m'

msg() { printf '%b\n' "$*"; }
info() { msg "${C_BLUE}[i]${C_RESET} $*"; }
ok() { msg "${C_GREEN}[✓]${C_RESET} $*"; }
warn() { msg "${C_YELLOW}[!]${C_RESET} $*"; }
err() { msg "${C_RED}[✗]${C_RESET} $*"; }
die() { err "$*"; exit 1; }

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

prompt() {
    local label="$1"
    local default="${2:-}"
    local value
    if [[ -n "$default" ]]; then
        read -r -p "${label} [${default}]: " value
        value="$(trim "$value")"
        [[ -n "$value" ]] || value="$default"
    else
        read -r -p "${label}: " value
        value="$(trim "$value")"
    fi
    printf '%s' "$value"
}

ask_yes_no() {
    local label="$1"
    local default="${2:-Y}"
    local hint="[Y/n]"
    [[ "$default" == "N" ]] && hint="[y/N]"
    local value
    read -r -p "${label} ${hint}: " value
    value="$(trim "$value")"
    [[ -n "$value" ]] || value="$default"
    [[ "$value" =~ ^([yY]|[yY][eE][sS])$ ]]
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "需要 root 权限运行，请使用 sudo bash nginx-relay.sh。"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

backup_file() {
    local file="$1"
    [[ -e "$file" || -L "$file" ]] || return 0
    mkdir -p "$BACKUP_DIR"
    local base stamp backup n=1
    base="$(basename "$file")"
    stamp="$(date +%Y%m%d_%H%M%S)"
    backup="${BACKUP_DIR}/${base}.${stamp}.bak"
    while [[ -e "$backup" || -L "$backup" ]]; do
        backup="${BACKUP_DIR}/${base}.${stamp}.${n}.bak"
        ((n++))
    done
    cp -a "$file" "$backup"
    info "已备份 ${file} -> ${backup}"
}

load_state() {
    MODE=""
    if [[ -f "$STATE_FILE" ]]; then
        # 只读取 MODE，避免 source 状态文件覆盖 readonly 变量或执行外部内容。
        local saved_mode
        saved_mode="$(sed -n 's/^MODE=//p' "$STATE_FILE" | tail -n 1)"
        saved_mode="${saved_mode#\'}"
        saved_mode="${saved_mode%\'}"
        saved_mode="${saved_mode#\"}"
        saved_mode="${saved_mode%\"}"
        if [[ "$saved_mode" == "retain-web" || "$saved_mode" == "relay-only" ]]; then
            MODE="$saved_mode"
        fi
    fi
}

save_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    umask 077
    cat > "$STATE_FILE" <<EOF
# nginx-relay.sh state
MODE=$(printf '%q' "$MODE")
EOF
}

is_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local octet
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
}

is_ipv6() {
    local ip="$1"
    if command_exists python3; then
        python3 - "$ip" <<'PY'
import ipaddress
import sys
try:
    ipaddress.IPv6Address(sys.argv[1])
except Exception:
    raise SystemExit(1)
PY
        return $?
    fi
    [[ "$ip" == *:* ]] || return 1
    [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]]
}

ip_family() {
    local ip="$1"
    if is_ipv4 "$ip"; then
        printf '4'
    elif is_ipv6 "$ip"; then
        printf '6'
    else
        return 1
    fi
}

refresh_ip_status() {
    LOCAL_IPV4=()
    LOCAL_IPV6=()

    if command_exists ip; then
        while IFS= read -r value; do
            [[ -n "$value" ]] && LOCAL_IPV4+=("$value")
        done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | sort -u)

        while IFS= read -r value; do
            [[ -n "$value" ]] && LOCAL_IPV6+=("$value")
        done < <(ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^fe80:' | sort -u)
    fi

    if [[ ${#LOCAL_IPV4[@]} -gt 0 ]]; then HAS_IPV4=1; else HAS_IPV4=0; fi
    if [[ ${#LOCAL_IPV6[@]} -gt 0 ]]; then HAS_IPV6=1; else HAS_IPV6=0; fi
}

show_ip_status() {
    refresh_ip_status
    msg ""
    msg "服务器网络状态"
    if (( HAS_IPV4 == 1 && HAS_IPV6 == 1 )); then
        ok "检测到双栈：IPv4 + IPv6"
    elif (( HAS_IPV4 == 1 )); then
        ok "检测到单栈：纯 IPv4（不显示 IPv6 转发选项）"
    elif (( HAS_IPV6 == 1 )); then
        ok "检测到单栈：纯 IPv6（不支持 IPv4 服务转发）"
    else
        warn "未检测到可用的全局 IPv4/IPv6 地址，请先检查网络配置。"
    fi

    if (( HAS_IPV4 == 1 )); then
        printf '  IPv4 出站地址：%s\n' "${LOCAL_IPV4[*]}"
    fi
    if (( HAS_IPV6 == 1 )); then
        printf '  IPv6 出站地址：%s\n' "${LOCAL_IPV6[*]}"
    fi
}

find_stream_module() {
    local candidate
    for candidate in \
        /usr/lib/nginx/modules/ngx_stream_module.so \
        /usr/lib64/nginx/modules/ngx_stream_module.so \
        /lib/nginx/modules/ngx_stream_module.so \
        /lib64/nginx/modules/ngx_stream_module.so; do
        if [[ -f "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

nginx_has_stream() {
    command_exists nginx || return 1
    nginx -V 2>&1 | grep -q -- '--with-stream'
}

nginx_stream_is_dynamic() {
    command_exists nginx || return 1
    nginx -V 2>&1 | grep -q -- '--with-stream=dynamic'
}

readonly STREAM_MODULE_PATTERN='^[[:space:]]*load_module[[:space:]]+([^;[:space:]]*/)?ngx_stream_module\.so[[:space:]]*;'

stream_module_loaded_in_file() {
    local file="$1"
    grep -Eq "$STREAM_MODULE_PATTERN" "$file" 2>/dev/null
}

stream_module_loaded_in_tree() {
    local file
    while IFS= read -r -d '' file; do
        if stream_module_loaded_in_file "$file"; then
            printf '%s' "$file"
            return 0
        fi
    done < <(find /etc/nginx -path "$BACKUP_DIR" -prune -o \( -type f -o -type l \) -print0 2>/dev/null)
    return 1
}

ensure_stream_module_loaded() {
    local module_path="$1"
    local loaded_file=""
    local file

    # Debian/Ubuntu 通常通过 modules-enabled 的相对路径加载模块，优先保留该包管理配置。
    if [[ -d /etc/nginx/modules-enabled ]]; then
        while IFS= read -r -d '' file; do
            if stream_module_loaded_in_file "$file"; then
                loaded_file="$file"
                break
            fi
        done < <(find /etc/nginx/modules-enabled -maxdepth 1 \( -type f -o -type l \) -print0 2>/dev/null | sort -z)
    fi

    if [[ -z "$loaded_file" ]]; then
        loaded_file="$(stream_module_loaded_in_tree || true)"
    fi

    if [[ -z "$loaded_file" ]]; then
        backup_file "$NGINX_CONF"
        sed -i "1i load_module ${module_path};" "$NGINX_CONF"
        info "已加载动态 stream 模块：${module_path}"
        return 0
    fi

    # 如果模块已由 modules-enabled 或其他配置加载，清除 nginx.conf 中由旧版本脚本添加的重复项。
    if [[ "$loaded_file" != "$NGINX_CONF" ]] && stream_module_loaded_in_file "$NGINX_CONF"; then
        backup_file "$NGINX_CONF"
        sed -Ei "/${STREAM_MODULE_PATTERN}/d" "$NGINX_CONF"
        info "检测到 stream 模块已加载，已移除 nginx.conf 中的重复加载项。"
    fi
}

install_nginx_stream() {
    local pm=""
    if command_exists apt-get; then
        pm="apt"
    elif command_exists dnf; then
        pm="dnf"
    elif command_exists yum; then
        pm="yum"
    elif command_exists apk; then
        pm="apk"
    fi

    if ! command_exists nginx; then
        [[ -n "$pm" ]] || die "未找到 Nginx，也无法识别包管理器。"
        info "首次运行：正在安装 Nginx。"
        case "$pm" in
            apt)
                apt-get update
                DEBIAN_FRONTEND=noninteractive apt-get install -y nginx nginx-full libnginx-mod-stream
                ;;
            dnf)
                dnf install -y nginx nginx-mod-stream
                ;;
            yum)
                yum install -y nginx nginx-mod-stream
                ;;
            apk)
                apk add --no-cache nginx
                ;;
        esac
    fi

    if ! nginx_has_stream && ! find_stream_module >/dev/null 2>&1; then
        [[ -n "$pm" ]] || die "当前 Nginx 不包含 stream 模块，且无法识别包管理器。"
        info "正在安装 Nginx stream 模块。"
        case "$pm" in
            apt)
                DEBIAN_FRONTEND=noninteractive apt-get install -y nginx-full libnginx-mod-stream
                ;;
            dnf)
                dnf install -y nginx-mod-stream
                ;;
            yum)
                yum install -y nginx-mod-stream
                ;;
            apk)
                warn "当前发行版通常将 stream 编译在 nginx 主包中，请确认 nginx 版本支持 stream。"
                ;;
        esac
    fi

    if ! nginx_has_stream && ! find_stream_module >/dev/null 2>&1; then
        die "Nginx stream 模块安装失败，请手动安装后重新运行。"
    fi
    ok "Nginx 与 stream 模块已就绪。"
}

ensure_nginx_ready() {
    if [[ ! -f "$STATE_FILE" ]]; then
        install_nginx_stream
    else
        if ! command_exists nginx; then
            warn "状态文件已存在，但当前系统未找到 Nginx。"
            if ask_yes_no "是否现在安装 Nginx 与 stream 模块？" "Y"; then
                install_nginx_stream
            else
                die "没有 Nginx 无法继续。"
            fi
        elif ! nginx_has_stream && ! find_stream_module >/dev/null 2>&1; then
            warn "当前 Nginx 未检测到 stream 模块。"
            if ask_yes_no "是否安装/补齐 stream 模块？" "N"; then
                install_nginx_stream
            else
                die "缺少 stream 模块，无法继续。"
            fi
        else
            info "检测到已有 Nginx 配置，跳过重复安装。"
        fi
    fi
}

ensure_stream_layout() {
    command_exists nginx || die "找不到 nginx 命令。"
    [[ -f "$NGINX_CONF" ]] || die "找不到 Nginx 主配置：${NGINX_CONF}"
    mkdir -p "$RELAY_DIR"

    local module_path
    # --with-stream=dynamic 仍然需要在配置中加载 .so，不能当作静态编译处理。
    if nginx_stream_is_dynamic || ! nginx_has_stream; then
        module_path="$(find_stream_module || true)"
        if [[ -n "$module_path" ]]; then
            ensure_stream_module_loaded "$module_path"
        elif ! nginx_has_stream; then
            die "未找到 ngx_stream_module.so，请先安装 Nginx stream 模块。"
        fi
    fi

    if grep -Eq '^[[:space:]]*stream[[:space:]]*\{' "$NGINX_CONF"; then
        STREAM_INCLUDE_MODE="inside-stream"
        if ! grep -Eq '^[[:space:]]*include[[:space:]]+/etc/nginx/stream\.d/\*\.conf;' "$NGINX_CONF"; then
            backup_file "$NGINX_CONF"
            sed -i "/^[[:space:]]*stream[[:space:]]*{/a\\    include ${STREAM_INCLUDE};" "$NGINX_CONF"
            info "已将转发配置接入现有 stream 块。"
        fi
    else
        STREAM_INCLUDE_MODE="standalone"
        if ! grep -Eq '^[[:space:]]*include[[:space:]]+/etc/nginx/stream\.d/\*\.conf;' "$NGINX_CONF"; then
            backup_file "$NGINX_CONF"
            printf '\n# nginx-relay.sh managed include\ninclude %s;\n' "$STREAM_INCLUDE" >> "$NGINX_CONF"
            info "已将转发配置接入 Nginx 主配置。"
        fi
    fi
}

select_mode_first_run() {
    msg ""
    msg "首次运行请选择 Nginx 工作模式："
    msg "1) 保留 Web 服务"
    msg "   - 不修改现有 80/443 配置，仅增加 stream 转发"
    msg "2) 不保留 Web 服务（仅转发）"
    msg "   - 备份后注释 Nginx 配置中的 80/443 listen，占用端口将被释放"
    local choice
    while true; do
        choice="$(prompt "请选择 [1-2]" "1")"
        case "$choice" in
            1) MODE="retain-web"; break ;;
            2)
                MODE="relay-only"
                disable_web_ports
                break
                ;;
            *) warn "请输入 1 或 2。" ;;
        esac
    done
    save_state
    ok "已保存工作模式：${MODE}"
}

disable_web_ports() {
    local roots=(/etc/nginx/nginx.conf /etc/nginx/sites-enabled /etc/nginx/conf.d)
    local file changed=0 root
    for root in "${roots[@]}"; do
        [[ -e "$root" ]] || continue
        if [[ -f "$root" || -L "$root" ]]; then
            set -- "$root"
        else
            set --
            while IFS= read -r -d '' file; do
                set -- "$@" "$file"
            done < <(find "$root" -maxdepth 1 \( -type f -o -type l \) -print0 2>/dev/null)
        fi
        for file in "$@"; do
            if grep -Eq '^[[:space:]]*listen[[:space:]]+([^;[:space:]]+:)?(80|443)([[:space:];])' "$file"; then
                backup_file "$file"
                sed -Ei '/^[[:space:]]*listen[[:space:]]+([^;[:space:]]+:)?(80|443)([[:space:];])/ s/^/# nginx-relay disabled web port: /' "$file"
                changed=1
                info "已释放 Web 端口：${file}"
            fi
        done
    done
    if (( changed == 0 )); then
        info "未发现需要注释的 80/443 listen 配置。"
    fi
}

valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

port_in_registry() {
    local port="$1"
    [[ -f "$RELAY_DB" ]] || return 1
    awk -F'|' -v p="$port" '$4 == p { found=1 } END { exit(found ? 0 : 1) }' "$RELAY_DB"
}

port_in_use() {
    local port="$1"
    if command_exists ss; then
        ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$" && return 0
        ss -H -lun 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$" && return 0
    fi
    return 1
}

choose_protocol() {
    local value
    while true; do
        value="$(prompt "传输协议 1) TCP  2) UDP" "1")"
        case "$value" in
            1) SELECTED_PROTOCOL="tcp"; return 0 ;;
            2) SELECTED_PROTOCOL="udp"; return 0 ;;
            *) warn "请输入 1 或 2。" ;;
        esac
    done
}

choose_family_for_domain() {
    local value
    if (( HAS_IPV4 == 1 && HAS_IPV6 == 1 )); then
        while true; do
            value="$(prompt "目标地址族 1) IPv4  2) IPv6" "1")"
            case "$value" in
                1) SELECTED_FAMILY="4"; return 0 ;;
                2) SELECTED_FAMILY="6"; return 0 ;;
                *) warn "请输入 1 或 2。" ;;
            esac
        done
    elif (( HAS_IPV4 == 1 )); then
        SELECTED_FAMILY="4"
        info "当前为纯 IPv4，域名转发默认使用 IPv4。"
    elif (( HAS_IPV6 == 1 )); then
        SELECTED_FAMILY="6"
        info "当前为纯 IPv6，域名转发默认使用 IPv6，不支持 IPv4 服务转发。"
    else
        die "未检测到可用 IP，无法创建转发。"
    fi
}

choose_bind_ip() {
    local family="$1"
    local -n candidates
    if [[ "$family" == "4" ]]; then
        candidates=LOCAL_IPV4
    else
        candidates=LOCAL_IPV6
    fi

    (( ${#candidates[@]} > 0 )) || die "没有可用的 IPv${family} 出站地址。"
    msg ""
    msg "可用的 IPv${family} 出站地址："
    local i=1 ip choice
    for ip in "${candidates[@]}"; do
        printf '  %d) %s\n' "$i" "$ip"
        ((i++))
    done
    choice="$(prompt "请选择出站 IP" "1")"
    [[ "$choice" =~ ^[0-9]+$ ]] || die "出站 IP 选项无效。"
    (( choice >= 1 && choice <= ${#candidates[@]} )) || die "出站 IP 选项超出范围。"
    SELECTED_BIND_IP="${candidates[$((choice - 1))]}"
}

next_relay_id() {
    local n=1 id
    while true; do
        id="relay_$(printf '%03d' "$n")"
        if [[ ! -f "$RELAY_DB" ]] || ! grep -qE "^${id}\|" "$RELAY_DB"; then
            printf '%s' "$id"
            return 0
        fi
        ((n++))
    done
}

append_relay() {
    local id="$1" kind="$2" protocol="$3" listen_port="$4" target="$5" target_port="$6" family="$7" bind_ip="$8"
    mkdir -p "$RELAY_DIR"
    touch "$RELAY_DB"
    chmod 600 "$RELAY_DB"
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$id" "$kind" "$protocol" "$listen_port" "$target" "$target_port" "$family" "$bind_ip" >> "$RELAY_DB"
}

remove_last_relay() {
    local id="$1"
    [[ -f "$RELAY_DB" ]] || return 0
    local tmp="${RELAY_DB}.tmp.$$"
    awk -F'|' -v id="$id" '$1 != id' "$RELAY_DB" > "$tmp"
    mv "$tmp" "$RELAY_DB"
}

render_relay_config() {
    local output="$1"
    local id kind protocol listen_port target target_port family bind_ip
    {
        printf '# This file is generated by nginx-relay.sh. Do not edit manually.\n'
        printf '# Regenerate by running the script and using the relay management menu.\n\n'
        if [[ "$STREAM_INCLUDE_MODE" == "standalone" ]]; then
            printf 'stream {\n'
        fi
        if [[ ! -s "$RELAY_DB" ]]; then
            if [[ "$STREAM_INCLUDE_MODE" == "standalone" ]]; then printf '}\n'; fi
            return 0
        fi

        while IFS='|' read -r id kind protocol listen_port target target_port family bind_ip; do
            [[ -n "$id" ]] || continue
            printf '    # %s: %s %s -> %s:%s (IPv%s, bind %s)\n' "$id" "$kind" "$protocol" "$target" "$target_port" "$family" "$bind_ip"
            if [[ "$kind" == "static-ip" ]]; then
                if [[ "$family" == "6" ]]; then
                    printf '    upstream %s_backend {\n        server [%s]:%s;\n    }\n' "$id" "$target" "$target_port"
                else
                    printf '    upstream %s_backend {\n        server %s:%s;\n    }\n' "$id" "$target" "$target_port"
                fi
                printf '    server {\n'
            else
                printf '    server {\n'
                if [[ "$family" == "6" ]]; then
                    printf '        resolver [2001:4860:4860::8888] [2606:4700:4700::1111] valid=30s ipv4=off ipv6=on;\n'
                else
                    printf '        resolver 8.8.8.8 1.1.1.1 valid=30s ipv4=on ipv6=off;\n'
                fi
            fi

            if [[ "$family" == "6" ]]; then
                if [[ "$protocol" == "udp" ]]; then
                    printf '        listen [%s]:%s udp ipv6only=on;\n' "$bind_ip" "$listen_port"
                else
                    printf '        listen [%s]:%s ipv6only=on;\n' "$bind_ip" "$listen_port"
                fi
            else
                if [[ "$protocol" == "udp" ]]; then
                    printf '        listen %s udp;\n' "$listen_port"
                else
                    printf '        listen %s;\n' "$listen_port"
                fi
            fi
            printf '        proxy_bind %s;\n' "$bind_ip"
            printf '        proxy_connect_timeout 10s;\n        proxy_timeout 1h;\n'
            if [[ "$kind" == "static-ip" ]]; then
                printf '        proxy_pass %s_backend;\n' "$id"
            else
                printf '        set $%s_backend "%s";\n        proxy_pass $%s_backend:%s;\n' "$id" "$target" "$id" "$target_port"
            fi
            printf '    }\n\n'
        done < "$RELAY_DB"

        if [[ "$STREAM_INCLUDE_MODE" == "standalone" ]]; then
            printf '}\n'
        fi
    } > "$output"
}

apply_relay_config() {
    local old_backup=""
    local tmp="${RELAY_CONF}.tmp.$$"
    if [[ -f "$RELAY_CONF" ]]; then
        old_backup="${RELAY_CONF}.bak.$$"
        cp -a "$RELAY_CONF" "$old_backup"
    fi

    render_relay_config "$tmp"
    mv "$tmp" "$RELAY_CONF"
    chmod 644 "$RELAY_CONF"

    if ! nginx -t; then
        err "Nginx 配置测试失败，正在回滚本次转发配置。"
        if [[ -n "$old_backup" && -f "$old_backup" ]]; then
            mv "$old_backup" "$RELAY_CONF"
        else
            rm -f "$RELAY_CONF"
        fi
        return 1
    fi

    [[ -n "$old_backup" ]] && rm -f "$old_backup"
    ok "Nginx 配置测试通过。"
    return 0
}

restart_nginx_prompt() {
    msg ""
    warn "转发已写入配置，Nginx 将会重启以应用更改。"
    if ask_yes_no "是否现在重启 Nginx？" "Y"; then
        if command_exists systemctl; then
            systemctl restart nginx
        elif command_exists service; then
            service nginx restart
        else
            die "找不到 systemctl/service，无法重启 Nginx。"
        fi
        ok "Nginx 已重启。"
    else
        info "已跳过重启；稍后可在菜单中执行配置测试/重启。"
    fi
}

create_static_relay() {
    refresh_ip_status
    local target listen_port target_port family
    target="$(prompt "目标静态 IP")"
    family="$(ip_family "$target" || true)"
    [[ "$family" == "4" || "$family" == "6" ]] || die "目标 IP 无效，请输入合法 IPv4 或 IPv6 地址。"
    if [[ "$family" == "4" && "$HAS_IPV4" -ne 1 ]]; then
        die "当前服务器为纯 IPv6，不能转发 IPv4 服务。"
    fi
    if [[ "$family" == "6" && "$HAS_IPV6" -ne 1 ]]; then
        die "当前服务器没有 IPv6，不能转发 IPv6 服务。"
    fi

    listen_port="$(prompt "本地监听端口")"
    valid_port "$listen_port" || die "本地监听端口必须是 1-65535。"
    port_in_registry "$listen_port" && die "该端口已存在于转发列表。"
    port_in_use "$listen_port" && warn "检测到系统已有服务监听该端口，Nginx 测试可能失败。"

    target_port="$(prompt "目标服务端口" "22")"
    valid_port "$target_port" || die "目标服务端口必须是 1-65535。"
    choose_protocol
    choose_bind_ip "$family"

    local id
    id="$(next_relay_id)"
    append_relay "$id" "static-ip" "$SELECTED_PROTOCOL" "$listen_port" "$target" "$target_port" "$family" "$SELECTED_BIND_IP"
    if apply_relay_config; then
        ok "已创建静态 IP 转发：${id}"
        restart_nginx_prompt
    else
        remove_last_relay "$id"
        die "创建静态 IP 转发失败。"
    fi
}

valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
    [[ "$domain" != *..* ]]
}

create_domain_relay() {
    refresh_ip_status
    local target listen_port target_port
    target="$(prompt "目标域名（DDNS/FQDN，例如 dynamic.example.com）")"
    valid_domain "$target" || die "域名格式无效。"
    choose_family_for_domain

    listen_port="$(prompt "本地监听端口")"
    valid_port "$listen_port" || die "本地监听端口必须是 1-65535。"
    port_in_registry "$listen_port" && die "该端口已存在于转发列表。"
    port_in_use "$listen_port" && warn "检测到系统已有服务监听该端口，Nginx 测试可能失败。"

    target_port="$(prompt "目标服务端口" "22")"
    valid_port "$target_port" || die "目标服务端口必须是 1-65535。"
    choose_protocol
    choose_bind_ip "$SELECTED_FAMILY"

    local id
    id="$(next_relay_id)"
    append_relay "$id" "domain" "$SELECTED_PROTOCOL" "$listen_port" "$target" "$target_port" "$SELECTED_FAMILY" "$SELECTED_BIND_IP"
    if apply_relay_config; then
        ok "已创建域名/DDNS 转发：${id}"
        restart_nginx_prompt
    else
        remove_last_relay "$id"
        die "创建域名/DDNS 转发失败。"
    fi
}

show_relays() {
    msg ""
    msg "当前转发列表"
    if [[ ! -s "$RELAY_DB" ]]; then
        info "暂无转发。"
        return 0
    fi
    printf '%-12s %-10s %-5s %-8s %-32s %-8s %-6s %s\n' "ID" "类型" "协议" "监听端口" "目标" "目标端口" "族" "proxy_bind"
    printf '%s\n' "------------------------------------------------------------------------------------------------------------"
    local id kind protocol listen_port target target_port family bind_ip
    while IFS='|' read -r id kind protocol listen_port target target_port family bind_ip; do
        [[ -n "$id" ]] || continue
        printf '%-12s %-10s %-5s %-8s %-32s %-8s IPv%-5s %s\n' \
            "$id" "$kind" "$protocol" "$listen_port" "$target" "$target_port" "$family" "$bind_ip"
    done < "$RELAY_DB"
}

delete_relay() {
    show_relays
    [[ -s "$RELAY_DB" ]] || return 0
    local id
    id="$(prompt "请输入要删除的转发 ID")"
    awk -F'|' -v wanted="$id" '$1 == wanted { found=1 } END { exit(found ? 0 : 1) }' "$RELAY_DB" \
        || die "未找到该转发 ID。"
    local tmp="${RELAY_DB}.tmp.$$"
    awk -F'|' -v id="$id" '$1 != id' "$RELAY_DB" > "$tmp"
    cp -a "$RELAY_DB" "${RELAY_DB}.bak.$$.delete"
    mv "$tmp" "$RELAY_DB"
    if apply_relay_config; then
        ok "已删除转发：${id}"
        restart_nginx_prompt
        rm -f "${RELAY_DB}.bak.$$.delete"
    else
        mv "${RELAY_DB}.bak.$$.delete" "$RELAY_DB"
        die "删除操作导致 Nginx 配置测试失败，已回滚。"
    fi
}

check_and_restart() {
    if nginx -t; then
        ok "Nginx 配置测试通过。"
        restart_nginx_prompt
    else
        die "Nginx 配置测试失败，请先修复配置。"
    fi
}

show_menu() {
    msg ""
    msg "=============================================="
    msg " nginx-relay.sh v${SCRIPT_VERSION}"
    msg " 工作模式：${MODE:-未设置}"
    msg "=============================================="
    msg "1) 显示转发列表"
    msg "2) 创建静态 IP 转发"
    msg "3) 创建域名（DDNS）转发"
    msg "4) 删除转发"
    msg "5) 测试配置并重启 Nginx"
    msg "6) 重新执行‘是否保留 Web 服务’设置"
    msg "0) 退出"
}

change_web_mode() {
    msg "当前工作模式：${MODE}"
    local choice
    local default_choice="2"
    [[ "$MODE" == "retain-web" ]] && default_choice="1"
    choice="$(prompt "1) 保留 Web 服务  2) 仅转发" "$default_choice")"
    case "$choice" in
        1) MODE="retain-web"; save_state; ok "已切换为保留 Web 服务。" ;;
        2) MODE="relay-only"; disable_web_ports; save_state; ok "已切换为仅转发模式。" ;;
        *) warn "无效选项。" ;;
    esac
}

main() {
    require_root
    load_state
    show_ip_status
    ensure_nginx_ready

    if [[ -z "$MODE" ]]; then
        select_mode_first_run
    fi
    ensure_stream_layout
    if [[ ! -f "$RELAY_DB" ]]; then
        touch "$RELAY_DB"
        chmod 600 "$RELAY_DB"
    fi
    if ! nginx -t >/dev/null 2>&1; then
        warn "当前 Nginx 配置测试未通过，创建转发前请先检查现有配置。"
    fi

    local choice
    while true; do
        show_ip_status
        show_menu
        choice="$(prompt "请选择" "1")"
        case "$choice" in
            1) show_relays ;;
            2) create_static_relay ;;
            3) create_domain_relay ;;
            4) delete_relay ;;
            5) check_and_restart ;;
            6) change_web_mode ;;
            0) info "已退出。"; exit 0 ;;
            *) warn "无效选项，请重新输入。" ;;
        esac
    done
}

main "$@"
