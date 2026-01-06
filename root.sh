#!/bin/bash
#
# SSH Authentication Configuration Script
# Version: 4.2.1 (BUGFIX)
# Fixed: 颜色代码污染路径变量导致公钥添加失败
#
set -euo pipefail

####################################
# 配置常量
####################################
readonly SCRIPT_VERSION="4.2.1"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly LOG_FILE="/var/log/ssh_auth_setup.log"
readonly KEY_DIR="/root/ssh_keys"
readonly AUTH_KEYS_DIR="/root/.ssh"
readonly AUTH_KEYS_FILE="${AUTH_KEYS_DIR}/authorized_keys"
readonly TEST_TIMEOUT=120

# 颜色定义
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_BLUE='\033[34m'
C_RESET='\033[0m'

####################################
# 日志与消息函数
####################################
log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>&1 || true; }

msg_ok()   { echo -e "${C_GREEN}[✓]${C_RESET} $1"; log_msg "OK: $1"; }
msg_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; log_msg "WARN: $1"; }
msg_err()  { echo -e "${C_RED}[✗]${C_RESET} $1";   log_msg "ERROR: $1"; }
msg_info() { echo -e "${C_BLUE}[i]${C_RESET} $1";  log_msg "INFO: $1"; }

####################################
# 权限检查
####################################
[[ $EUID -ne 0 ]] && { msg_err "请使用 root 权限运行此脚本"; echo "建议: sudo $0"; exit 1; }

####################################
# 依赖检查
####################################
check_dependencies() {
    local deps=(sshd ssh-keygen systemctl)
    local missing=()
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    ((${#missing[@]} > 0)) && {
        msg_warn "缺少命令: ${missing[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y openssh-server putty-tools
        elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
            yum install -y openssh-server putty-tools || dnf install -y openssh-server putty-tools
        else
            msg_err "无法自动安装依赖，请手动安装 openssh-server"
            exit 1
        fi
        msg_ok "依赖安装完成"
    }
}

####################################
# 备份与恢复
####################################
backup_sshd_config() {
    local backup="${SSHD_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -a "$SSHD_CONFIG" "$backup" || { msg_err "备份失败"; exit 1; }
    echo "$backup"
}

restore_sshd_config() {
    local backup="$1"
    [[ -f "$backup" ]] || return
    cp -a "$backup" "$SSHD_CONFIG"
    msg_warn "已恢复配置 → $backup"
    reload_sshd
}

####################################
# 修改 sshd 配置
####################################
set_sshd_option() {
    local key="$1" value="$2"
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -i "s/^[[:space:]]*#[[:space:]]*${key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

####################################
# 重载 SSH 服务
####################################
reload_sshd() {
    local service=$(systemctl list-unit-files | grep -E '^(ssh|sshd)\.service' | awk -F. '{print $1}' | head -1 || echo "sshd")

    msg_info "验证并重载 SSH 服务 ($service)..."
    if ! sshd -t >>"$LOG_FILE" 2>&1; then
        msg_err "sshd 配置语法错误！"
        return 1
    fi

    if systemctl reload "$service" >>"$LOG_FILE" 2>&1; then
        sleep 2
        systemctl is-active --quiet "$service" && msg_ok "SSH 服务重载成功" || msg_warn "服务状态异常"
    else
        msg_warn "reload 失败，继续执行（当前会话不受影响）"
    fi
}

####################################
# 生成 ED25519 密钥（纯函数，不打印颜色信息）
####################################
generate_ed25519_key() {
    local key_base="${KEY_DIR}/id_ed25519"
    local priv="$key_base"
    local pub="${key_base}.pub"
    local ppk="${key_base}.ppk"

    # 覆盖旧密钥
    rm -f "$priv" "$pub" "$ppk" 2>/dev/null

    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"

    # 静默生成
    if ! ssh-keygen -t ed25519 -f "$priv" -N "" -C "root@$(hostname) $(date +%Y-%m-%d)" >/dev/null 2>&1; then
        msg_err "ED25519 密钥生成失败"
        return 1
    fi

    chmod 600 "$priv"
    chmod 644 "$pub"

    # 生成 ppk（可选）
    if command -v puttygen &>/dev/null; then
        puttygen "$priv" -o "$ppk" -O private >/dev/null 2>&1 && chmod 600 "$ppk"
    fi

    echo "$priv"  # 只返回干净路径
}

####################################
# 显示密钥文件信息（接收干净路径）
####################################
show_key_files() {
    local priv_path="$1"
    local base="${priv_path%/*}/id_ed25519"

    echo ""
    msg_ok "新密钥已生成（旧密钥已覆盖）："
    echo "   私钥文件         : $priv_path"
    echo "   公钥文件         : ${priv_path}.pub"
    [[ -f "${base}.ppk" ]] && echo "   PuTTY 私钥 (PPK) : ${base}.ppk"
    echo ""
    msg_warn "请立即将私钥安全拷贝到本地并妥善备份！"
    echo "   示例命令（在新终端执行）："
    local ip=$(curl -s --connect-timeout 4 ifconfig.me || hostname -I | awk '{print $1}')
    echo "   scp root@${ip}:$priv_path ~/.ssh/"
    echo ""
}

####################################
# 添加公钥到 authorized_keys
####################################
setup_authorized_keys() {
    local pub_file="$1"
    [[ -f "$pub_file" ]] || { msg_err "公钥文件不存在: $pub_file"; return 1; }

    mkdir -p "$AUTH_KEYS_DIR" && chmod 700 "$AUTH_KEYS_DIR"

    if [[ -f "$AUTH_KEYS_FILE" ]] && grep -qFx "$(cat "$pub_file")" "$AUTH_KEYS_FILE"; then
        msg_warn "公钥已存在，无需重复添加"
    else
        cat "$pub_file" >> "$AUTH_KEYS_FILE"
        chmod 600 "$AUTH_KEYS_FILE"
        msg_ok "公钥已添加到 $AUTH_KEYS_FILE"
    fi
}

####################################
# 获取服务器 IP
####################################
get_server_ip() {
    curl -s --connect-timeout 4 ifconfig.me 2>/dev/null ||
    curl -s --connect-timeout 4 icanhazip.com 2>/dev/null ||
    hostname -I 2>/dev/null | awk '{print $1}' ||
    echo "unknown"
}

####################################
# 密钥登录测试
####################################
test_key_login() {
    local backup="$1" priv_path="$2" server_ip
    server_ip=$(get_server_ip)

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_warn "密钥登录测试（${TEST_TIMEOUT}秒超时）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "请在新终端执行："
    echo "   scp root@${server_ip}:$priv_path ~/.ssh/"
    echo "   chmod 600 ~/.ssh/id_ed25519"
    echo "   ssh -i ~/.ssh/id_ed25519 root@${server_ip}"
    echo ""
    echo "成功后返回此处输入 yes 确认"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    nohup bash -c "sleep $TEST_TIMEOUT && echo '超时自动回滚' >>'$LOG_FILE' && cp -a '$backup' '$SSHD_CONFIG' && systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null" >/dev/null 2>&1 &
    local timer_pid=$!

    local confirm=""
    read -t "$TEST_TIMEOUT" -p "测试成功？请输入 yes： " confirm || true

    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true

    if [[ "${confirm,,}" == "yes" ]]; then
        msg_ok "确认成功"
        return 0
    else
        msg_err "未确认，执行回滚"
        restore_sshd_config "$backup"
        return 1
    fi
}

####################################
# 模式 3：仅密钥认证
####################################
mode_key_only() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_info "模式 3：仅密钥认证（最安全推荐）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local backup=$(backup_sshd_config)
    msg_ok "已备份配置：$backup"

    msg_info "步骤 1/5：生成 ED25519 密钥对（覆盖旧密钥）"
    local priv_path=$(generate_ed25519_key) || { restore_sshd_config "$backup"; exit 1; }

    show_key_files "$priv_path"

    msg_info "步骤 2/5：添加公钥到 authorized_keys"
    setup_authorized_keys "${priv_path}.pub"

    msg_info "步骤 3/5：临时启用密钥认证（保留密码用于测试）"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"
    reload_sshd || { restore_sshd_config "$backup"; exit 1; }

    msg_info "步骤 4/5：进行密钥登录测试"
    test_key_login "$backup" "$priv_path" || exit 1

    msg_info "步骤 5/5：禁用密码登录，仅允许密钥"
    set_sshd_option "PasswordAuthentication" "no"
    set_sshd_option "PermitRootLogin" "prohibit-password"
    reload_sshd

    echo ""
    msg_ok "仅密钥认证配置完成！密码登录已永久禁用。"
    msg_warn "请务必备份私钥 $priv_path，丢失将无法登录！"
    echo ""
}

####################################
# 其他模式占位（可后续补全）
####################################
mode_hybrid()       { echo "混合认证模式待实现"; }
mode_password_only(){ echo "仅密码模式待实现"; }

####################################
# 主菜单
####################################
show_menu() {
    clear
    cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      SSH 认证配置工具 v${SCRIPT_VERSION}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1) 混合认证（密码 + 密钥）
  2) 仅密码认证
  3) 仅密钥认证（最推荐）
  0) 退出

EOF
}

main() {
    check_dependencies
    [[ -f "$SSHD_CONFIG" ]] || { msg_err "未找到 $SSHD_CONFIG"; exit 1; }

    while true; do
        show_menu
        read -p "请选择操作 [0-3]： " choice
        echo ""
        case "$choice" in
            1) mode_hybrid; break ;;
            2) mode_password_only; break ;;
            3) mode_key_only; break ;;
            0) echo "已退出"; exit 0 ;;
            *) msg_warn "无效选项，请重试" ;;
        esac
    done

    msg_info "日志文件：$LOG_FILE"
    msg_ok "操作完成！"
}

main "$@"
