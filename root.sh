#!/bin/bash
#
# SSH 仅密钥认证配置脚本（安全无交互版）
# Version: 4.3.0 (2025-01-06 修复版)
# 适用于 curl | bash 直接执行
#
set -euo pipefail

####################################
# 配置常量
####################################
readonly SCRIPT_VERSION="4.3.0"
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
msg_ok() { echo -e "${C_GREEN}[✓]${C_RESET} $1"; log_msg "OK: $1"; }
msg_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; log_msg "WARN: $1"; }
msg_err() { echo -e "${C_RED}[✗]${C_RESET} $1"; log_msg "ERROR: $1"; }
msg_info() { echo -e "${C_BLUE}[i]${C_RESET} $1"; log_msg "INFO: $1"; }

####################################
# 权限检查
####################################
[[ $EUID -ne 0 ]] && { msg_err "请使用 root 权限运行此脚本"; exit 1; }

####################################
# 依赖检查
####################################
check_dependencies() {
    local deps=(sshd ssh-keygen systemctl)
    local missing=()
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if ((${#missing[@]} > 0)); then
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
    fi
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
    systemctl reload "$service" >>"$LOG_FILE" 2>&1 || true
    sleep 2
    systemctl is-active --quiet "$service" && msg_ok "SSH 服务重载成功" || msg_warn "服务状态异常"
}

####################################
# 生成 ED25519 密钥
####################################
generate_ed25519_key() {
    local key_base="${KEY_DIR}/id_ed25519"
    local priv="$key_base"
    local pub="${key_base}.pub"
    local ppk="${key_base}.ppk"

    rm -f "$priv" "$pub" "$ppk" 2>/dev/null
    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"

    ssh-keygen -t ed25519 -f "$priv" -N "" -C "root@$(hostname) $(date +%Y-%m-%d)" >/dev/null 2>&1 || {
        msg_err "ED25519 密钥生成失败"
        return 1
    }

    chmod 600 "$priv"
    chmod 644 "$pub"

    if command -v puttygen &>/dev/null; then
        puttygen "$priv" -o "$ppk" -O private >/dev/null 2>&1 && chmod 600 "$ppk"
    fi

    echo "$priv"
}

####################################
# 显示密钥信息
####################################
show_key_files() {
    local priv_path="$1"
    local base="${priv_path%/*}/id_ed25519"

    echo ""
    msg_ok "新密钥已生成（旧密钥已覆盖）："
    echo " 私钥文件 : $priv_path"
    echo " 公钥文件 : ${priv_path}.pub"
    [[ -f "${base}.ppk" ]] && echo " PuTTY 私钥 (PPK) : ${base}.ppk"
    echo ""
    msg_warn "请立即将私钥安全拷贝到本地并妥善备份！"
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
# 获取服务器公网 IP
####################################
get_server_ip() {
    curl -s --connect-timeout 4 https://ifconfig.me 2>/dev/null ||
    curl -s --connect-timeout 4 https://icanhazip.com 2>/dev/null ||
    hostname -I 2>/dev/null | awk '{print $1}' ||
    echo "unknown"
}

####################################
# 密钥登录测试指引（无交互）
####################################
test_key_login() {
    local priv_path="$1"
    local server_ip=$(get_server_ip)

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_warn "重要：请在新终端手动完成密钥登录测试！"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. 将私钥拷贝到本地电脑："
    echo "   scp root@${server_ip}:$priv_path ~/.ssh/id_ed25519"
    echo ""
    echo "2. 设置权限（非常重要！）："
    echo "   chmod 600 ~/.ssh/id_ed25519"
    echo ""
    echo "3. 测试登录："
    echo "   ssh -i ~/.ssh/id_ed25519 root@${server_ip}"
    echo ""
    echo "如果登录成功，说明密钥认证已生效。"
    echo "测试成功后，请继续执行下面命令完成最终配置（禁用密码登录）："
    echo ""
    msg_info "最终命令（复制粘贴即可）："
    cat <<'EOF'
# 禁用密码登录，仅允许密钥
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl reload sshd || service ssh reload
EOF
    echo ""
    msg_warn "务必先测试成功再执行上面命令，否则可能导致自己无法登录！"
    echo ""
}

####################################
# 仅密钥认证模式
####################################
mode_key_only() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_info "模式：仅密钥认证（最安全推荐）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local backup=$(backup_sshd_config)
    msg_ok "已备份配置：$backup"

    msg_info "步骤 1/5：生成 ED25519 密钥对（覆盖旧密钥）"
    local priv_path=$(generate_ed25519_key) || { restore_sshd_config "$backup"; exit 1; }
    show_key_files "$priv_path"

    msg_info "步骤 2/5：添加公钥到 authorized_keys"
    setup_authorized_keys "${priv_path}.pub"

    msg_info "步骤 3/5：启用密钥认证（保留密码用于测试）"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"
    reload_sshd || { restore_sshd_config "$backup"; exit 1; }

    msg_info "步骤 4/5：密钥登录测试（请在新终端手动验证）"
    test_key_login "$priv_path"

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
# 主程序
####################################
main() {
    check_dependencies
    [[ -f "$SSHD_CONFIG" ]] || { msg_err "未找到 $SSHD_CONFIG"; exit 1; }

    echo ""
    msg_info "检测到非交互式执行（curl | bash），已自动跳过等待确认"
    msg_info "请务必在新终端手动完成密钥登录测试！"
    echo ""

    mode_key_only

    msg_info "日志文件：$LOG_FILE"
    msg_ok "操作完成！"
}

main "$@"
