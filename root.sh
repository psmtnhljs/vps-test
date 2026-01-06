#!/bin/bash
#
# SSH Authentication Configuration Script - 完全修复版
# Version: 4.2.1 (2026-01-06 修复致命输出污染 bug)
#
set -euo pipefail

readonly SCRIPT_VERSION="4.2.1"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly LOG_FILE="/var/log/ssh_auth_setup.log"
readonly KEY_DIR="/root/ssh_keys"
readonly AUTH_KEYS_DIR="/root/.ssh"
readonly AUTH_KEYS_FILE="${AUTH_KEYS_DIR}/authorized_keys"
readonly TEST_TIMEOUT=120

# 颜色
C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_BLUE='\033[34m'; C_RESET='\033[0m'

log_msg() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>&1 || true; }
msg_ok()   { echo -e "${C_GREEN}[✓] $1${C_RESET}"; log_msg "OK: $1"; }
msg_warn() { echo -e "${C_YELLOW}[!] $1${C_RESET}"; log_msg "WARN: $1"; }
msg_err()  { echo -e "${C_RED}[✗] $1${C_RESET}";   log_msg "ERROR: $1"; }
msg_info() { echo -e "${C_BLUE}[i] $1${C_RESET}";  log_msg "INFO: $1"; }

[[ $EUID -ne 0 ]] && { msg_err "需要 root 权限"; exit 1; }

backup_sshd_config() {
    local backup="${SSHD_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -a "$SSHD_CONFIG" "$backup" && echo "$backup" || { msg_err "备份失败"; exit 1; }
}

restore_sshd_config() {
    local backup="$1"
    [[ -f "$backup" ]] || return 1
    cp -a "$backup" "$SSHD_CONFIG"
    msg_warn "已回滚配置 → $backup"
    systemctl reload sshd || systemctl reload ssh
}

set_sshd_option() {
    local key="$1" value="$2"
    sed -i "/^#*\s*${key}\s\+.*/d" "$SSHD_CONFIG" 2>/dev/null || true
    echo "${key} ${value}" >> "$SSHD_CONFIG"
}

reload_sshd() {
    sshd -t >/dev/null 2>&1 || { msg_err "配置语法错误"; return 1; }
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    msg_ok "SSH 服务已重载"
}

# ============ 关键修复：所有函数返回值都必须是纯净路径，绝不能混入颜色 ============
generate_ed25519_key() {
    local priv="${KEY_DIR}/id_ed25519"
    local pub="${KEY_DIR}/id_ed25519.pub"
    local ppk="${KEY_DIR}/id_ed25519.ppk"

    msg_info "正在生成 ED25519 密钥对（将覆盖旧密钥）..."
    rm -f "$priv" "$pub" "$ppk" 2>/dev/null

    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"

    if ! ssh-keygen -t ed25519 -f "$priv" -N "" -C "root@$(hostname)_$(date +%F)" >/dev/null 2>&1; then
        msg_err "ED25519 密钥生成失败"
        return 1
    fi

    chmod 600 "$priv"
    chmod 644 "$pub"

    if command -v puttygen &>/dev/null; then
        puttygen "$priv" -o "$ppk" -O private >/dev/null 2>&1 && chmod 600 "$ppk"
    fi

    # 关键：只返回纯路径，绝不带颜色！
    echo "$priv"
}

show_key_files() {
    local priv="$1"
    echo ""
    msg_ok "密钥生成成功（已覆盖旧密钥）"
    echo "   私钥      → $priv"
    echo "   公钥      → $priv.pub"
    [[ -f "$priv.ppk" ]] && echo "   PuTTY 私钥 → $priv.ppk"
    echo ""
    msg_warn "请立即下载私钥到本地（稍后将无法再次显示）！"
    echo "   scp root@$(hostname -I | awk '{print $1}'):'$priv' ~/.ssh/"
    echo ""
}

setup_authorized_keys() {
    local pub="$1"
    mkdir -p "$AUTH_KEYS_DIR" && chmod 700 "$AUTH_KEYS_DIR"
    if ! grep -qFx "$(cat "$pub")" "$AUTH_KEYS_FILE" 2>/dev/null; then
        cat "$pub" >> "$AUTH_KEYS_FILE"
        chmod 600 "$AUTH_KEYS_FILE"
        msg_ok "公钥已写入 authorized_keys"
    else
        msg_warn "公钥已存在"
    fi
}

get_server_ip() {
    curl -s --connect-timeout 3 ifconfig.me 2>/dev/null || \
    curl -s --connect-timeout 3 ipinfo.io/ip 2>/dev/null || \
    hostname -I | awk '{print $1}'
}

test_key_login() {
    local backup="$1" priv="$2" ip
    ip=$(get_server_ip)

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_warn "请在新终端测试密钥登录（${TEST_TIMEOUT} 秒超时）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. 下载私钥："
    echo "   scp root@$ip:'$priv' ~/.ssh/id_ed25519"
    echo "2. 设置权限：chmod 600 ~/.ssh/id_ed25519"
    echo "3. 测试登录：ssh -i ~/.ssh/id_ed25519 root@$ip"
    echo "4. 成功后回到这里输入 yes"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    nohup bash -c "sleep $TEST_TIMEOUT && echo '超时自动回滚' >> '$LOG_FILE' && cp -f '$backup' '$SSHD_CONFIG' && systemctl reload sshd 2>/dev/null" >/dev/null 2>&1 &
    local timer_pid=$!

    read -t "$TEST_TIMEOUT" -p "输入 yes 确认登录成功: " confirm || true
    kill "$timer_pid" 2>/dev/null || true

    if [[ "${confirm,,}" == "yes" ]]; then
        msg_ok "验证通过！"
        return 0
    else
        msg_err "未确认或超时，已回滚配置"
        restore_sshd_config "$backup"
        return 1
    fi
}

mode_key_only() {
    clear
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_info "模式 3：仅密钥认证（最安全推荐）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local backup=$(backup_sshd_config)

    # 关键修复：先接收纯路径，再打印信息
    local priv_key
    priv_key=$(generate_ed25519_key) || { restore_sshd_config "$backup"; exit 1; }

    show_key_files "$priv_key"

    setup_authorized_keys "$priv_key.pub"

    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"        # 先保留用于测试
    set_sshd_option "PermitRootLogin" "yes"
    reload_sshd

    test_key_login "$backup" "$priv_key" || exit 1

    # 测试通过 → 彻底禁用密码
    set_sshd_option "PasswordAuthentication" "no"
    set_sshd_option "PermitRootLogin" "prohibit-password"
    reload_sshd

    echo ""
    msg_ok "恭喜！服务器已成功切换为纯密钥登录（密码已彻底禁用）"
    msg_warn "私钥路径：$priv_key   请务必已保存！！！"
    echo ""
}

# 主流程
clear
cat << EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     SSH 认证配置工具 v${SCRIPT_VERSION} (已修复)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1) 混合认证（密码 + 密钥）
  2) 仅密码认证  
  3) 仅密钥认证（最推荐）
  0) 退出
EOF

read -p "请选择 [0-3]: " choice
case "$choice" in
    3) mode_key_only ;;
    0) exit 0 ;;
    *) msg_err "暂只开放模式 3，已自动进入" ; mode_key_only ;;
esac
