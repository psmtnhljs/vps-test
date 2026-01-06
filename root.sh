#!/bin/bash
#
# SSH Authentication Configuration Script
# Version: 4.0.0
# Purpose: 安全配置 SSH 认证方式
#
# 使用: sudo bash script.sh
#

set -euo pipefail

####################################
# 配置
####################################
readonly SCRIPT_VERSION="4.0.0"
readonly MIN_PASSWORD_LENGTH=8
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly LOG_FILE="/var/log/ssh_auth_setup.log"
readonly KEY_DIR="/root"
readonly TEST_TIMEOUT=60

# 颜色
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_BLUE='\033[34m'
C_RESET='\033[0m'

####################################
# 日志函数
####################################
log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>&1 || true
}

msg_ok() {
    echo -e "${C_GREEN}[✓]${C_RESET} $1"
    log_msg "OK: $1"
}

msg_warn() {
    echo -e "${C_YELLOW}[!]${C_RESET} $1"
    log_msg "WARN: $1"
}

msg_err() {
    echo -e "${C_RED}[✗]${C_RESET} $1"
    log_msg "ERROR: $1"
}

msg_info() {
    echo -e "${C_BLUE}[i]${C_RESET} $1"
}

####################################
# 权限检查
####################################
if [[ $EUID -ne 0 ]]; then
    msg_err "需要 root 权限运行此脚本"
    echo "使用: sudo $0"
    exit 1
fi

####################################
# 依赖检查
####################################
check_dependencies() {
    local deps=(chpasswd sshd systemctl ssh-keygen)
    local missing=()
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        msg_warn "缺少依赖: ${missing[*]}"
        msg_info "正在安装..."
        
        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            apt-get install -y openssh-server passwd systemd putty-tools
        elif command -v yum &>/dev/null; then
            yum install -y openssh-server passwd systemd putty
        else
            msg_err "无法自动安装依赖，请手动安装"
            exit 1
        fi
        msg_ok "依赖安装完成"
    fi
}

####################################
# 备份配置
####################################
backup_sshd_config() {
    local backup="${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    if cp -a "$SSHD_CONFIG" "$backup"; then
        echo "$backup"
    else
        msg_err "配置备份失败"
        exit 1
    fi
}

####################################
# 恢复配置
####################################
restore_sshd_config() {
    local backup="$1"
    if [[ -f "$backup" ]]; then
        cp -a "$backup" "$SSHD_CONFIG"
        msg_warn "已恢复配置: $backup"
        restart_sshd
    fi
}

####################################
# 修改 SSH 配置
####################################
set_sshd_option() {
    local key="$1"
    local value="$2"
    
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -i "s/^[[:space:]]*#[[:space:]]*${key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

####################################
# 检测并重启 SSH 服务
####################################
restart_sshd() {
    local service=""
    
    # 检测服务名
    if systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service'; then
        service="sshd"
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service'; then
        service="ssh"
    elif pgrep -x sshd &>/dev/null; then
        service="sshd"
    else
        service="ssh"
    fi
    
    msg_info "重启 SSH 服务: $service"
    
    # 验证配置
    if ! sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        msg_err "SSH 配置验证失败"
        return 1
    fi
    
    # 重启服务
    if systemctl restart "$service" 2>&1 | tee -a "$LOG_FILE"; then
        sleep 2
        if systemctl is-active --quiet "$service"; then
            msg_ok "SSH 服务已重启"
            return 0
        fi
    fi
    
    msg_err "SSH 服务重启失败"
    return 1
}

####################################
# 读取密码（直接使用 passwd 命令）
####################################
set_root_password_interactive() {
    msg_info "现在将使用 passwd 命令设置 root 密码"
    msg_info "请输入密码两次（输入时不会显示）"
    echo ""
    
    if passwd root; then
        msg_ok "root 密码设置成功"
        return 0
    else
        msg_err "密码设置失败"
        return 1
    fi
}

####################################
# 生成 SSH 密钥
####################################
generate_ssh_key() {
    local key_name="ssh_key_$(date +%Y%m%d_%H%M%S)"
    local key_path="${KEY_DIR}/${key_name}"
    
    msg_info "生成 SSH 密钥: $key_name" >&2
    
    # 尝试 ED25519
    if ssh-keygen -t ed25519 -f "$key_path" -N "" -C "root@$(hostname)" &>/dev/null; then
        msg_ok "密钥生成成功 (ED25519)" >&2
    elif ssh-keygen -t rsa -b 4096 -f "$key_path" -N "" -C "root@$(hostname)" &>/dev/null; then
        msg_ok "密钥生成成功 (RSA 4096)" >&2
    else
        msg_err "密钥生成失败" >&2
        return 1
    fi
    
    chmod 600 "$key_path"
    chmod 644 "${key_path}.pub"
    
    # 只输出路径到 stdout
    echo "$key_path"
}

####################################
# 导出密钥格式
####################################
export_key_formats() {
    local private_key="$1"
    local base="${private_key%.*}"
    
    # PEM 格式
    cp "$private_key" "${base}.pem"
    chmod 600 "${base}.pem"
    
    # PPK 格式
    if command -v puttygen &>/dev/null; then
        if puttygen "$private_key" -o "${base}.ppk" -O private &>/dev/null; then
            chmod 600 "${base}.ppk"
            msg_ok "已生成 PPK 格式 (PuTTY)"
        fi
    fi
    
    echo ""
    msg_ok "密钥文件:"
    echo "  私钥 (PEM): ${base}.pem"
    [[ -f "${base}.ppk" ]] && echo "  私钥 (PPK): ${base}.ppk"
    echo "  公钥 (PUB): ${private_key}.pub"
    echo ""
}

####################################
# 配置 authorized_keys
####################################
setup_authorized_keys() {
    local public_key="$1"
    local auth_keys="${KEY_DIR}/.ssh/authorized_keys"
    
    mkdir -p "${KEY_DIR}/.ssh"
    chmod 700 "${KEY_DIR}/.ssh"
    
    if [[ -f "$auth_keys" ]] && grep -qF "$(cat "$public_key")" "$auth_keys" 2>/dev/null; then
        msg_warn "公钥已存在"
    else
        cat "$public_key" >> "$auth_keys"
        msg_ok "公钥已添加到 authorized_keys"
    fi
    
    chmod 600 "$auth_keys"
}

####################################
# 获取服务器 IP
####################################
get_server_ip() {
    local ip
    ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || \
         curl -s --max-time 3 icanhazip.com 2>/dev/null || \
         hostname -I 2>/dev/null | awk '{print $1}')
    echo "${ip:-unknown}"
}

####################################
# 密钥登录测试
####################################
test_key_login() {
    local backup="$1"
    local key_base="$2"
    local server_ip=$(get_server_ip)
    
    echo ""
    echo "=========================================="
    msg_warn "密钥登录测试 (${TEST_TIMEOUT}秒超时)"
    echo "=========================================="
    echo ""
    echo "请在新终端执行以下步骤："
    echo ""
    echo "1. 下载密钥:"
    echo "   scp root@${server_ip}:${key_base}.pem ~/.ssh/"
    echo ""
    echo "2. 设置权限:"
    echo "   chmod 600 ~/.ssh/$(basename ${key_base}).pem"
    echo ""
    echo "3. 测试登录:"
    echo "   ssh -i ~/.ssh/$(basename ${key_base}).pem root@${server_ip}"
    echo ""
    echo "4. 如果登录成功，返回此窗口输入 'yes'"
    echo ""
    echo "=========================================="
    echo ""
    
    # 后台计时器
    (
        sleep "$TEST_TIMEOUT"
        echo ""
        msg_err "超时！自动回滚配置..."
        restore_sshd_config "$backup"
        exit 1
    ) &
    local timer_pid=$!
    
    # 等待确认
    local confirm
    read -t "$TEST_TIMEOUT" -p "确认密钥登录成功 (输入 yes): " confirm || true
    
    # 停止计时器
    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    
    if [[ "$confirm" == "yes" || "$confirm" == "YES" ]]; then
        msg_ok "用户确认成功"
        return 0
    else
        msg_err "未确认，回滚配置"
        restore_sshd_config "$backup"
        return 1
    fi
}

####################################
# 模式1: 混合认证
####################################
mode_hybrid() {
    echo ""
    echo "=========================================="
    msg_info "模式 1: 混合认证 (密钥+密码)"
    echo "=========================================="
    echo ""
    
    local backup=$(backup_sshd_config)
    msg_ok "配置已备份"
    
    # 设置密码
    echo ""
    msg_info "步骤 1/3: 设置 root 密码"
    if ! set_root_password_interactive; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    # 配置 SSH
    echo ""
    msg_info "步骤 2/3: 配置 SSH"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PasswordAuthentication" "yes"
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "UsePAM" "yes"
    msg_ok "SSH 配置完成"
    
    # 重启服务
    echo ""
    msg_info "步骤 3/3: 重启 SSH 服务"
    if ! restart_sshd; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    echo ""
    msg_ok "混合认证模式配置完成"
    echo ""
    echo "当前状态:"
    echo "  ✓ 密码登录: 已启用"
    echo "  ✓ 密钥登录: 已启用"
    echo ""
}

####################################
# 模式2: 仅密码
####################################
mode_password_only() {
    echo ""
    echo "=========================================="
    msg_info "模式 2: 仅密码认证"
    echo "=========================================="
    echo ""
    
    local backup=$(backup_sshd_config)
    msg_ok "配置已备份"
    
    # 设置密码
    echo ""
    msg_info "步骤 1/3: 设置 root 密码"
    if ! set_root_password_interactive; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    # 配置 SSH
    echo ""
    msg_info "步骤 2/3: 配置 SSH"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PasswordAuthentication" "yes"
    set_sshd_option "PubkeyAuthentication" "no"
    set_sshd_option "UsePAM" "yes"
    msg_ok "SSH 配置完成"
    
    # 重启服务
    echo ""
    msg_info "步骤 3/3: 重启 SSH 服务"
    if ! restart_sshd; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    echo ""
    msg_ok "仅密码认证模式配置完成"
    echo ""
    echo "当前状态:"
    echo "  ✓ 密码登录: 已启用"
    echo "  ✗ 密钥登录: 已禁用"
    echo ""
    msg_warn "安全提示: 密码认证相对不安全"
    echo "建议: 使用强密码 + fail2ban"
    echo ""
}

####################################
# 模式3: 仅密钥
####################################
mode_key_only() {
    echo ""
    echo "=========================================="
    msg_info "模式 3: 仅密钥认证 (推荐)"
    echo "=========================================="
    echo ""
    
    local backup=$(backup_sshd_config)
    msg_ok "配置已备份"
    
    # 生成密钥
    echo ""
    msg_info "步骤 1/5: 生成 SSH 密钥"
    local key_path
    key_path=$(generate_ssh_key)
    local gen_status=$?
    
    if [[ $gen_status -ne 0 || -z "$key_path" || ! -f "$key_path" ]]; then
        msg_err "密钥生成失败"
        restore_sshd_config "$backup"
        exit 1
    fi
    
    # 导出格式
    echo ""
    msg_info "步骤 2/5: 导出密钥格式"
    export_key_formats "$key_path"
    
    # 配置 authorized_keys
    echo ""
    msg_info "步骤 3/5: 配置密钥认证"
    setup_authorized_keys "${key_path}.pub"
    
    # 启用密钥登录（保留密码）
    echo ""
    msg_info "步骤 4/5: 启用密钥登录"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"  # 暂时保留
    
    if ! restart_sshd; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    # 测试密钥登录
    echo ""
    msg_info "步骤 5/5: 测试密钥登录"
    if ! test_key_login "$backup" "${key_path%.*}"; then
        exit 1
    fi
    
    # 禁用密码登录
    echo ""
    msg_info "禁用密码登录"
    set_sshd_option "PasswordAuthentication" "no"
    
    if ! restart_sshd; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    echo ""
    msg_ok "仅密钥认证模式配置完成"
    echo ""
    echo "当前状态:"
    echo "  ✗ 密码登录: 已禁用"
    echo "  ✓ 密钥登录: 已启用"
    echo ""
    msg_warn "重要: 请妥善保管私钥文件"
    echo "密钥位置: ${key_path%.*}.pem"
    echo ""
}

####################################
# 主菜单
####################################
show_menu() {
    clear
    echo ""
    echo "=========================================="
    echo "  SSH 认证配置 v${SCRIPT_VERSION}"
    echo "=========================================="
    echo ""
    echo "1) 混合认证 (密钥+密码)"
    echo "   - 同时支持密钥和密码登录"
    echo "   - 适合过渡使用"
    echo ""
    echo "2) 仅密码认证"
    echo "   - 只允许密码登录"
    echo "   - 快速配置"
    echo ""
    echo "3) 仅密钥认证 (推荐)"
    echo "   - 只允许密钥登录"
    echo "   - 最安全的方式"
    echo "   - 自动生成密钥"
    echo "   - 60秒测试保护"
    echo ""
    echo "0) 退出"
    echo ""
}

####################################
# 主流程
####################################
main() {
    # 检查依赖
    check_dependencies
    
    # 检查配置文件
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        msg_err "找不到 SSH 配置文件"
        exit 1
    fi
    
    # 显示菜单
    show_menu
    
    # 读取选择
    local choice
    read -p "请选择 [0-3]: " choice
    
    case "$choice" in
        1) mode_hybrid ;;
        2) mode_password_only ;;
        3) mode_key_only ;;
        0) echo "退出"; exit 0 ;;
        *) msg_err "无效选项"; exit 1 ;;
    esac
    
    echo ""
    msg_info "日志: $LOG_FILE"
    msg_info "配置: $SSHD_CONFIG"
    echo ""
    msg_ok "完成！"
}

main "$@"
