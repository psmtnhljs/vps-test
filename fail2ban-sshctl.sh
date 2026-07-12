#!/usr/bin/env bash
set -Eeuo pipefail

readonly JAIL_NAME="sshd"
readonly JAIL_DIR="/etc/fail2ban/jail.d"
readonly JAIL_FILE="${JAIL_DIR}/sshd.local"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
die()  { printf "${RED}[FAIL]${NC} %s\n" "$*" >&2; exit 1; }

trap 'printf "\n${RED}[FAIL]${NC} 第 %s 行执行失败：%s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

clear_screen() { [[ -t 1 ]] && clear || true; }
pause() { printf "\n"; read -r -p "按 Enter 键返回主菜单..." _; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

header() {
    clear_screen
    printf "${CYAN}${BOLD}"
    cat <<'EOF'
============================================================
          Linux SSH Fail2Ban 管理工具
============================================================
EOF
    printf "${NC}\n"
}

require_root() {
    [[ $EUID -eq 0 ]] || die "请使用 root 权限运行：sudo bash $0"
}

detect_os() {
    [[ -r /etc/os-release ]] || die "找不到 /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release

    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-${NAME:-Unknown Linux}}"
    OS_ID_LIKE="${ID_LIKE:-}"

    case "$OS_ID" in
        debian|ubuntu|linuxmint|raspbian|kali|devuan)
            OS_FAMILY="debian"
            PKG_MANAGER="apt"
            ;;
        rhel|centos|rocky|almalinux|ol|fedora|cloudlinux|virtuozzo)
            OS_FAMILY="rhel"
            ;;
        *)
            case " $OS_ID_LIKE " in
                *" debian "*|*" ubuntu "*)
                    OS_FAMILY="debian"
                    PKG_MANAGER="apt"
                    ;;
                *" rhel "*|*" fedora "*|*" centos "*)
                    OS_FAMILY="rhel"
                    ;;
                *)
                    die "暂不支持：${OS_NAME} (ID=${OS_ID}, ID_LIKE=${OS_ID_LIKE:-无})"
                    ;;
            esac
            ;;
    esac

    if [[ "$OS_FAMILY" == "rhel" ]]; then
        if command_exists dnf; then
            PKG_MANAGER="dnf"
        elif command_exists yum; then
            PKG_MANAGER="yum"
        else
            die "检测到 RHEL 系统，但找不到 dnf/yum"
        fi
    fi
}

is_installed() {
    command_exists fail2ban-client
}

is_jail_active() {
    is_installed &&
    fail2ban-client ping 2>/dev/null | grep -q "pong" &&
    fail2ban-client status "$JAIL_NAME" >/dev/null 2>&1
}

detect_ssh_service() {
    local unit
    for unit in ssh.service sshd.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then
            SSH_UNIT="$unit"
            return 0
        fi
    done
    return 1
}

detect_ssh_ports() {
    local sshd_bin=""
    sshd_bin="$(command -v sshd || true)"

    if [[ -z "$sshd_bin" ]]; then
        [[ -x /usr/sbin/sshd ]] && sshd_bin="/usr/sbin/sshd"
        [[ -z "$sshd_bin" && -x /sbin/sshd ]] && sshd_bin="/sbin/sshd"
    fi

    [[ -x "$sshd_bin" ]] || return 1

    mapfile -t SSH_PORTS < <(
        "$sshd_bin" -T 2>/dev/null |
        awk '$1 == "port" && $2 ~ /^[0-9]+$/ && $2 >= 1 && $2 <= 65535 {print $2}' |
        sort -nu
    )

    if [[ ${#SSH_PORTS[@]} -eq 0 ]] && command_exists ss; then
        mapfile -t SSH_PORTS < <(
            ss -H -lntp 2>/dev/null |
            awk '/sshd/ {
                addr=$4
                sub(/^.*]:/, "", addr)
                sub(/^.*:/, "", addr)
                if (addr ~ /^[0-9]+$/) print addr
            }' | sort -nu
        )
    fi

    [[ ${#SSH_PORTS[@]} -gt 0 ]] || return 1
    SSH_PORT_CSV="$(IFS=,; echo "${SSH_PORTS[*]}")"
}

detect_log_backend() {
    command_exists journalctl || return 1

    if journalctl -u "$SSH_UNIT" -n 1 --no-pager >/dev/null 2>&1; then
        SSH_JOURNAL_MODE="unit"
    elif journalctl _COMM=sshd -n 1 --no-pager >/dev/null 2>&1; then
        SSH_JOURNAL_MODE="comm"
    else
        return 1
    fi

    F2B_BACKEND="systemd"
}

detect_nftables_action() {
    local action
    for action in nftables nftables-multiport; do
        if [[ -f "/etc/fail2ban/action.d/${action}.conf" ]]; then
            BANACTION="$action"
            return 0
        fi
    done
    return 1
}

refresh_environment() {
    detect_ssh_service || die "未检测到 SSH systemd 服务"
    detect_ssh_ports || die "无法识别 SSH 监听端口"
    detect_log_backend || die "无法访问 SSH systemd journal"
    detect_nftables_action || die "未找到 Fail2Ban nftables action"
}

install_packages() {
    header
    info "检测到：$OS_NAME"
    info "正在安装 Fail2Ban 与 nftables..."

    if [[ "$OS_FAMILY" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            fail2ban nftables python3-systemd iproute2
    else
        if [[ "$OS_ID" != "fedora" ]]; then
            "$PKG_MANAGER" install -y epel-release || \
                warn "无法安装 epel-release，将继续尝试安装 Fail2Ban"
        fi

        "$PKG_MANAGER" install -y fail2ban nftables iproute

        "$PKG_MANAGER" install -y python3-systemd || \
        "$PKG_MANAGER" install -y python-systemd || true
    fi

    command_exists fail2ban-client || die "Fail2Ban 安装失败"
    command_exists nft || die "nftables 安装失败"
    ok "依赖安装完成"
}

validate_positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
validate_time_value() { [[ "$1" =~ ^[1-9][0-9]*(s|m|h|d|w)$ ]]; }
validate_ip() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PY
}

prompt_integer() {
    local prompt="$1" default="$2" target="$3" value
    while true; do
        read -r -p "$prompt [$default]: " value
        value="${value:-$default}"
        if validate_positive_integer "$value"; then
            printf -v "$target" '%s' "$value"
            return
        fi
        printf "${RED}请输入大于 0 的整数。${NC}\n"
    done
}

prompt_time() {
    local prompt="$1" default="$2" target="$3" value
    while true; do
        read -r -p "$prompt [$default]: " value
        value="${value:-$default}"
        if validate_time_value "$value"; then
            printf -v "$target" '%s' "$value"
            return
        fi
        printf "${RED}格式错误，支持：30s、10m、2h、7d、4w${NC}\n"
    done
}

prompt_yes_no() {
    local prompt="$1" default="${2:-Y}" answer
    while true; do
        if [[ "$default" == "Y" ]]; then
            read -r -p "$prompt [Y/n]: " answer
            answer="${answer:-Y}"
        else
            read -r -p "$prompt [y/N]: " answer
            answer="${answer:-N}"
        fi
        case "${answer,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) printf "${RED}请输入 y 或 n。${NC}\n" ;;
        esac
    done
}

read_current_config() {
    CURRENT_MAXRETRY="3"
    CURRENT_FINDTIME="10m"
    CURRENT_BANTIME="7d"

    if [[ -f "$JAIL_FILE" ]]; then
        CURRENT_MAXRETRY="$(awk -F= '/^[[:space:]]*maxretry[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$JAIL_FILE")"
        CURRENT_FINDTIME="$(awk -F= '/^[[:space:]]*findtime[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$JAIL_FILE")"
        CURRENT_BANTIME="$(awk -F= '/^[[:space:]]*bantime[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$JAIL_FILE")"
    fi

    CURRENT_MAXRETRY="${CURRENT_MAXRETRY:-3}"
    CURRENT_FINDTIME="${CURRENT_FINDTIME:-10m}"
    CURRENT_BANTIME="${CURRENT_BANTIME:-7d}"
}

configure_policy() {
    local mode="${1:-install}"
    read_current_config

    header
    printf "${BOLD}SSH 防护策略配置${NC}\n\n"
    printf "系统：       %s\n" "$OS_NAME"
    printf "SSH 服务：   %s\n" "$SSH_UNIT"
    printf "SSH 端口：   %s\n" "$SSH_PORT_CSV"
    printf "日志后端：   %s\n" "$F2B_BACKEND"
    printf "封禁方式：   %s\n\n" "$BANACTION"

    prompt_integer "1. 最大失败尝试次数 maxretry" "$CURRENT_MAXRETRY" MAXRETRY

    printf "\n${CYAN}findtime：失败次数统计窗口，例如 10m、1h。${NC}\n"
    prompt_time "2. 失败次数统计时间 findtime" "$CURRENT_FINDTIME" FINDTIME

    printf "\n${CYAN}bantime：触发规则后的封禁时间，例如 1h、7d、4w。${NC}\n"
    prompt_time "3. IP 封禁时间 bantime" "$CURRENT_BANTIME" BANTIME

    header
    printf "${BOLD}配置确认${NC}\n\n"
    printf "SSH 端口：       ${GREEN}%s${NC}\n" "$SSH_PORT_CSV"
    printf "最大尝试次数：   ${GREEN}%s 次${NC}\n" "$MAXRETRY"
    printf "统计时间：       ${GREEN}%s${NC}\n" "$FINDTIME"
    printf "封禁时间：       ${GREEN}%s${NC}\n\n" "$BANTIME"
    printf "${YELLOW}策略：%s 内认证失败 %s 次 -> 封禁 %s${NC}\n\n" \
        "$FINDTIME" "$MAXRETRY" "$BANTIME"

    prompt_yes_no "确认应用？" "Y" || return 1

    if [[ -f "$JAIL_FILE" ]]; then
        cp -a "$JAIL_FILE" "${JAIL_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    fi

    install -d -m 0755 "$JAIL_DIR"
    cat > "$JAIL_FILE" <<EOF
# Generated by Linux SSH Fail2Ban Manager
# OS: ${OS_NAME}
# $(date -Is)

[sshd]
enabled = true
port = ${SSH_PORT_CSV}
backend = ${F2B_BACKEND}
banaction = ${BANACTION}

maxretry = ${MAXRETRY}
findtime = ${FINDTIME}
bantime = ${BANTIME}
EOF
    chmod 0644 "$JAIL_FILE"

    info "正在测试配置..."
    fail2ban-client -t

    systemctl enable fail2ban >/dev/null
    systemctl restart fail2ban

    local i
    for i in {1..15}; do
        fail2ban-client ping 2>/dev/null | grep -q "pong" && break
        sleep 1
    done

    is_jail_active || die "sshd Jail 启动失败，请检查：journalctl -u fail2ban -n 100 --no-pager"

    if [[ "$mode" == "install" ]]; then
        ok "Fail2Ban SSH 防护初始化完成"
    else
        ok "SSH 防护策略修改完成"
    fi
}

menu_install() {
    if ! is_installed; then
        install_packages
    else
        header
        info "检测到 Fail2Ban 已安装，将重新初始化 SSH Jail"
    fi

    refresh_environment
    configure_policy "install"
    pause
}

menu_modify_policy() {
    header
    if ! is_installed; then
        warn "Fail2Ban 尚未安装，请先执行“安装 / 初始化”"
        pause
        return
    fi

    refresh_environment
    configure_policy "modify"
    pause
}

menu_status() {
    header
    printf "${BOLD}Fail2Ban SSH 状态${NC}\n\n"

    if ! is_installed; then
        warn "Fail2Ban 尚未安装"
    elif ! fail2ban-client ping 2>/dev/null | grep -q "pong"; then
        warn "Fail2Ban 当前未运行"
        systemctl status fail2ban --no-pager || true
    elif ! fail2ban-client status "$JAIL_NAME" >/dev/null 2>&1; then
        warn "sshd Jail 当前未启用"
        fail2ban-client status || true
    else
        fail2ban-client status "$JAIL_NAME"
        printf "\n${BOLD}服务状态：${NC}\n"
        systemctl is-active fail2ban || true
        printf "\n${BOLD}nftables Fail2Ban 规则：${NC}\n"
        nft list ruleset 2>/dev/null | grep -i -A 20 -B 2 -E 'f2b|fail2ban' || \
            warn "暂未匹配到规则名称"
    fi
    pause
}

collect_ssh_logs() {
    local hours="$1" output="$2"
    detect_ssh_service || return 1
    detect_log_backend || return 1

    if [[ "$SSH_JOURNAL_MODE" == "unit" ]]; then
        journalctl -u "$SSH_UNIT" --since "${hours} hours ago" \
            --no-pager -o cat 2>/dev/null > "$output" || true
    else
        journalctl _COMM=sshd --since "${hours} hours ago" \
            --no-pager -o cat 2>/dev/null > "$output" || true
    fi
}

menu_ranking() {
    local hours tmp ranking
    header
    prompt_integer "统计最近多少小时" "24" hours

    tmp="$(mktemp)"
    ranking="$(mktemp)"
    collect_ssh_logs "$hours" "$tmp" || {
        rm -f "$tmp" "$ranking"
        warn "无法读取 SSH journal"
        pause
        return
    }

    awk '
    /Failed password|Failed publickey|Invalid user|authentication failure/ {
        ip=""
        if (match($0, / from ([0-9A-Fa-f:.]+)/, m))
            ip=m[1]
        else if (match($0, /rhost=([0-9A-Fa-f:.]+)/, m))
            ip=m[1]
        if (ip != "" && ip != "::1" && ip != "127.0.0.1")
            count[ip]++
    }
    END {
        for (ip in count) printf "%d %s\n", count[ip], ip
    }' "$tmp" | sort -nr | head -20 > "$ranking"

    header
    printf "${BOLD}最近 %s 小时 SSH 爆破 IP TOP 20${NC}\n\n" "$hours"

    if [[ ! -s "$ranking" ]]; then
        warn "未发现匹配的 SSH 认证失败记录"
    else
        printf "%-8s %-12s %s\n" "排名" "尝试次数" "IP"
        printf "%-8s %-12s %s\n" "----" "--------" "--"
        awk '{printf "%-8d %-12d %s\n", NR, $1, $2}' "$ranking"
    fi

    rm -f "$tmp" "$ranking"
    pause
}

get_banned_ips() {
    fail2ban-client get "$JAIL_NAME" banip 2>/dev/null || true
}

menu_banned_ips() {
    local banned count=0 ip
    header
    printf "${BOLD}当前 SSH 封禁 IP${NC}\n\n"

    if ! is_jail_active; then
        warn "sshd Jail 当前不可用"
        pause
        return
    fi

    banned="$(get_banned_ips)"
    if [[ -z "$banned" ]]; then
        printf "当前没有被封禁的 IP。\n"
    else
        printf "%-8s %s\n" "序号" "IP"
        printf "%-8s %s\n" "----" "--"
        for ip in $banned; do
            ((++count))
            printf "%-8d %s\n" "$count" "$ip"
        done
        printf "\n共封禁 %d 个 IP。\n" "$count"
    fi
    pause
}

menu_ban_ip() {
    local ip
    header
    printf "${BOLD}手动封禁 IP${NC}\n\n"

    if ! is_jail_active; then
        warn "sshd Jail 当前不可用"
        pause
        return
    fi

    read -r -p "请输入要封禁的 IPv4/IPv6 地址: " ip
    if ! validate_ip "$ip"; then
        warn "IP 地址格式无效"
        pause
        return
    fi

    printf "\n${YELLOW}即将封禁：%s${NC}\n" "$ip"
    if prompt_yes_no "确认封禁？" "N"; then
        fail2ban-client set "$JAIL_NAME" banip "$ip"
        ok "已封禁：$ip"
    else
        info "操作已取消"
    fi
    pause
}

menu_unban_ip() {
    local ip
    header
    printf "${BOLD}解封 IP${NC}\n\n"

    if ! is_jail_active; then
        warn "sshd Jail 当前不可用"
        pause
        return
    fi

    menu_print_banned_inline
    printf "\n"
    read -r -p "请输入要解封的 IPv4/IPv6 地址: " ip

    if ! validate_ip "$ip"; then
        warn "IP 地址格式无效"
        pause
        return
    fi

    fail2ban-client set "$JAIL_NAME" unbanip "$ip"
    ok "已执行解封：$ip"
    pause
}

menu_print_banned_inline() {
    local banned
    banned="$(get_banned_ips)"
    if [[ -z "$banned" ]]; then
        printf "当前没有被封禁的 IP。\n"
    else
        printf "当前封禁 IP：\n"
        printf '%s\n' "$banned" | tr ' ' '\n' | sed 's/^/  /'
    fi
}

menu_live_log() {
    header
    printf "${BOLD}Fail2Ban 实时日志${NC}\n\n"
    printf "${YELLOW}按 Ctrl+C 返回主菜单。${NC}\n\n"

    if ! is_installed; then
        warn "Fail2Ban 尚未安装"
        pause
        return
    fi

    set +e
    journalctl -u fail2ban -f
    set -e
}

menu_uninstall() {
    header
    printf "${RED}${BOLD}卸载 Fail2Ban${NC}\n\n"
    printf "此操作将：\n"
    printf "  - 停止 Fail2Ban\n"
    printf "  - 删除 %s\n" "$JAIL_FILE"
    printf "  - 卸载 Fail2Ban 软件包\n"
    printf "  - 保留 nftables 软件包及其他防火墙配置\n\n"

    if ! is_installed; then
        warn "Fail2Ban 尚未安装"
        pause
        return
    fi

    prompt_yes_no "确认卸载 Fail2Ban？" "N" || {
        info "操作已取消"
        pause
        return
    }

    read -r -p "请输入 UNINSTALL 进行二次确认: " confirm
    if [[ "$confirm" != "UNINSTALL" ]]; then
        warn "确认文本不匹配，已取消"
        pause
        return
    fi

    systemctl disable --now fail2ban 2>/dev/null || true
    rm -f "$JAIL_FILE"

    if [[ "$OS_FAMILY" == "debian" ]]; then
        apt-get remove -y fail2ban
    else
        "$PKG_MANAGER" remove -y fail2ban
    fi

    ok "Fail2Ban 已卸载"
    pause
}

show_main_menu() {
    local install_state service_state jail_state

    if is_installed; then
        install_state="${GREEN}已安装${NC}"
    else
        install_state="${RED}未安装${NC}"
    fi

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        service_state="${GREEN}运行中${NC}"
    else
        service_state="${YELLOW}未运行${NC}"
    fi

    if is_jail_active; then
        jail_state="${GREEN}已启用${NC}"
    else
        jail_state="${YELLOW}未启用${NC}"
    fi

    header
    printf "系统：%s\n" "$OS_NAME"
    printf "Fail2Ban：%b | 服务：%b | SSH Jail：%b\n\n" \
        "$install_state" "$service_state" "$jail_state"

    printf "${BOLD}1.${NC} 安装 / 初始化 Fail2Ban\n"
    printf "${BOLD}2.${NC} 修改 SSH 防护策略\n"
    printf "${BOLD}3.${NC} 查看 Fail2Ban 状态\n"
    printf "${BOLD}4.${NC} 查看 SSH 爆破 IP 排名\n"
    printf "${BOLD}5.${NC} 查看当前封禁 IP\n"
    printf "${BOLD}6.${NC} 手动封禁 IP\n"
    printf "${BOLD}7.${NC} 解封 IP\n"
    printf "${BOLD}8.${NC} 查看 Fail2Ban 实时日志\n"
    printf "${BOLD}9.${NC} 卸载 Fail2Ban\n"
    printf "${BOLD}0.${NC} 退出\n\n"
}

main() {
    local choice
    require_root
    detect_os

    while true; do
        show_main_menu
        read -r -p "请选择 [0-9]: " choice

        case "$choice" in
            1) menu_install ;;
            2) menu_modify_policy ;;
            3) menu_status ;;
            4) menu_ranking ;;
            5) menu_banned_ips ;;
            6) menu_ban_ip ;;
            7) menu_unban_ip ;;
            8) menu_live_log ;;
            9) menu_uninstall ;;
            0)
                printf "\n已退出。\n"
                exit 0
                ;;
            *)
                warn "无效选项：$choice"
                sleep 1
                ;;
        esac
    done
}

main "$@"
