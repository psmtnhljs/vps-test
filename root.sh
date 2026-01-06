#!/bin/bash
#
# SSH Authentication Configuration Script
# Version: 3.0.0
# Purpose: 灵活配置 SSH 认证方式（密码/密钥/混合）
# 
# 使用方式:
#   sudo bash ssh_auth_setup.sh
#
# 特性:
# - 三种认证模式：混合/仅密码/仅密钥
# - 自动密钥生成（多格式导出）
# - 密钥登录安全回滚机制
# - 完整的错误处理和日志
# - 幂等性操作
#

set -Eeuo pipefail

####################################
# 全局配置
####################################
readonly SCRIPT_VERSION="3.0.0"
readonly MIN_PASSWORD_LENGTH=8
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly LOG_FILE="/var/log/ssh_auth_setup.log"
readonly KEY_DIR="/root"
readonly KEY_NAME="ssh_key_$(date +%Y%m%d_%H%M%S)"
readonly TEST_TIMEOUT=60  # 密钥测试超时时间（秒）

# 颜色输出
readonly COLOR_GREEN='\033[32m'
readonly COLOR_YELLOW='\033[33m'
readonly COLOR_RED='\033[31m'
readonly COLOR_BLUE='\033[34m'
readonly COLOR_RESET='\033[0m'

####################################
# 工具函数
####################################

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE" 2>&1 || true
}

green() {
    echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $1"
    log "INFO" "$1"
}

yellow() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
    log "WARN" "$1"
}

red() {
    echo -e "${COLOR_RED}[ERR]${COLOR_RESET} $1"
    log "ERROR" "$1"
}

blue() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
    log "INFO" "$1"
}

cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        red "脚本执行失败，退出码: $exit_code"
    fi
}

trap cleanup EXIT

####################################
# 权限检查
####################################
check_root() {
    if [[ $EUID -ne 0 ]]; then
        red "此脚本需要 root 权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

####################################
# 依赖检查和安装
####################################
ensure_dependencies() {
    local missing_deps=()
    
    for cmd in chpasswd sshd sed grep systemctl ssh-keygen; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        yellow "检测到缺失依赖: ${missing_deps[*]}"
        yellow "正在尝试安装..."
        
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq || true
            apt-get install -y openssh-server openssh-client passwd systemd putty-tools 2>&1 | tee -a "$LOG_FILE"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y openssh-server openssh-clients passwd systemd putty 2>&1 | tee -a "$LOG_FILE"
        else
            red "无法识别包管理器，请手动安装依赖"
            exit 1
        fi
        
        green "依赖安装完成"
    fi
}

####################################
# SSH 配置检查
####################################
check_sshd_config() {
    if [[ ! -f "$SSHD_CONFIG" ]]; then
        red "SSH 配置文件不存在: $SSHD_CONFIG"
        exit 1
    fi
    
    if [[ ! -r "$SSHD_CONFIG" ]]; then
        red "无法读取 SSH 配置文件: $SSHD_CONFIG"
        exit 1
    fi
    
    green "SSH 配置文件检查通过"
}

####################################
# 备份配置
####################################
backup_config() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${SSHD_CONFIG}.backup.${timestamp}"
    
    if cp -a "$SSHD_CONFIG" "$backup_file"; then
        green "配置已备份: $backup_file"
        echo "$backup_file"
    else
        red "配置备份失败"
        exit 1
    fi
}

####################################
# 恢复配置
####################################
restore_config() {
    local backup_file=$1
    
    if [[ -f "$backup_file" ]]; then
        yellow "正在恢复配置..."
        if cp -a "$backup_file" "$SSHD_CONFIG"; then
            green "配置已恢复: $backup_file"
            restart_ssh_service
        else
            red "配置恢复失败！"
        fi
    fi
}

####################################
# 密码强度验证
####################################
validate_password() {
    local password=$1
    
    if [[ ${#password} -lt $MIN_PASSWORD_LENGTH ]]; then
        return 1
    fi
    
    local has_upper=0 has_lower=0 has_digit=0 has_special=0
    [[ "$password" =~ [A-Z] ]] && has_upper=1
    [[ "$password" =~ [a-z] ]] && has_lower=1
    [[ "$password" =~ [0-9] ]] && has_digit=1
    [[ "$password" =~ [^a-zA-Z0-9] ]] && has_special=1
    
    local complexity=$((has_upper + has_lower + has_digit + has_special))
    
    if [[ $complexity -lt 3 ]]; then
        yellow "密码强度较弱，建议包含大小写字母、数字和特殊字符"
        read -p "是否继续使用此密码？(y/N): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 1
    fi
    
    return 0
}

####################################
# 读取并验证密码
####################################
read_password() {
    local password password_confirm
    
    while true; do
        # 使用 IFS= 防止特殊字符被解释
        IFS= read -r -s -p "请输入新的 root 密码 (最少${MIN_PASSWORD_LENGTH}位): " password
        echo
        
        if [[ -z "$password" ]]; then
            red "密码不能为空"
            continue
        fi
        
        IFS= read -r -s -p "请再次确认 root 密码: " password_confirm
        echo
        
        if [[ "$password" != "$password_confirm" ]]; then
            red "两次输入的密码不一致"
            continue
        fi
        
        if validate_password "$password"; then
            printf '%s' "$password"
            return 0
        fi
    done
}

####################################
# 设置 root 密码
####################################
set_root_password() {
    local password="$1"
    
    # 使用 here-string 是最安全的方法，避免管道和特殊字符问题
    if chpasswd <<EOF
root:${password}
EOF
    then
        green "root 密码设置成功"
        return 0
    else
        red "root 密码设置失败"
        log "ERROR" "chpasswd failed for password length: ${#password}"
        return 1
    fi
}

####################################
# 修改 SSH 配置（幂等）
####################################
set_ssh_option() {
    local key=$1
    local value=$2
    
    local escaped_key=$(echo "$key" | sed 's/[]\/$*.^[]/\\&/g')
    
    if grep -qE "^[[:space:]]*${escaped_key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -i "s/^[[:space:]]*${escaped_key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    elif grep -qE "^[[:space:]]*#[[:space:]]*${escaped_key}[[:space:]]" "$SSHD_CONFIG"; then
        sed -i "s/^[[:space:]]*#[[:space:]]*${escaped_key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

####################################
# 生成 SSH 密钥
####################################
generate_ssh_key() {
    local key_path="${KEY_DIR}/${KEY_NAME}"
    
    yellow "正在生成 SSH 密钥..."
    
    # 生成 ED25519 密钥（更安全、更快）
    if ssh-keygen -t ed25519 -f "${key_path}" -N "" -C "root@$(hostname)" >/dev/null 2>&1; then
        green "SSH 密钥生成成功"
    else
        # 降级到 RSA 4096（兼容性更好）
        yellow "ED25519 失败，尝试 RSA 4096..."
        if ssh-keygen -t rsa -b 4096 -f "${key_path}" -N "" -C "root@$(hostname)" >/dev/null 2>&1; then
            green "SSH 密钥生成成功 (RSA 4096)"
        else
            red "SSH 密钥生成失败"
            return 1
        fi
    fi
    
    # 设置权限
    chmod 600 "${key_path}"
    chmod 644 "${key_path}.pub"
    
    echo "${key_path}"
}

####################################
# 导出密钥为多种格式
####################################
export_key_formats() {
    local private_key=$1
    local key_base="${private_key%.*}"
    
    yellow "正在导出密钥为多种格式..."
    
    # 1. PEM 格式（OpenSSH 原生格式）
    cp "${private_key}" "${key_base}.pem"
    chmod 600 "${key_base}.pem"
    green "PEM 格式: ${key_base}.pem"
    
    # 2. PPK 格式（PuTTY）
    if command -v puttygen >/dev/null 2>&1; then
        if puttygen "${private_key}" -o "${key_base}.ppk" -O private >/dev/null 2>&1; then
            chmod 600 "${key_base}.ppk"
            green "PPK 格式: ${key_base}.ppk"
        else
            yellow "PPK 格式生成失败（puttygen 可能不兼容此密钥类型）"
        fi
    else
        yellow "未安装 puttygen，跳过 PPK 格式"
        blue "安装方法: apt install putty-tools 或 yum install putty"
    fi
    
    # 3. 公钥已存在
    green "公钥格式: ${private_key}.pub"
    
    echo ""
    blue "=========================================="
    blue "密钥文件位置:"
    blue "  私钥(PEM): ${key_base}.pem"
    [[ -f "${key_base}.ppk" ]] && blue "  私钥(PPK): ${key_base}.ppk"
    blue "  公钥(PUB): ${private_key}.pub"
    blue "=========================================="
    echo ""
}

####################################
# 配置密钥到 authorized_keys
####################################
setup_authorized_keys() {
    local public_key=$1
    local auth_keys="${KEY_DIR}/.ssh/authorized_keys"
    
    # 创建 .ssh 目录
    mkdir -p "${KEY_DIR}/.ssh"
    chmod 700 "${KEY_DIR}/.ssh"
    
    # 添加公钥
    if [[ -f "$auth_keys" ]]; then
        # 检查是否已存在
        if grep -qF "$(cat "$public_key")" "$auth_keys" 2>/dev/null; then
            yellow "公钥已存在于 authorized_keys"
        else
            cat "$public_key" >> "$auth_keys"
            green "公钥已添加到 authorized_keys"
        fi
    else
        cat "$public_key" > "$auth_keys"
        green "创建 authorized_keys 并添加公钥"
    fi
    
    chmod 600 "$auth_keys"
}

####################################
# 验证 SSH 配置
####################################
validate_ssh_config() {
    yellow "正在验证 SSH 配置..."
    
    if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        green "SSH 配置验证通过"
        return 0
    else
        red "SSH 配置验证失败"
        return 1
    fi
}

####################################
# 检测 SSH 服务名
####################################
detect_ssh_service() {
    local service_name=""
    
    if systemctl list-units --type=service --all 2>/dev/null | grep -qE '^[[:space:]]*sshd\.service'; then
        service_name="sshd"
    elif systemctl list-units --type=service --all 2>/dev/null | grep -qE '^[[:space:]]*ssh\.service'; then
        service_name="ssh"
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service'; then
        service_name="sshd"
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service'; then
        service_name="ssh"
    elif [[ -f /lib/systemd/system/sshd.service || -f /usr/lib/systemd/system/sshd.service ]]; then
        service_name="sshd"
    elif [[ -f /lib/systemd/system/ssh.service || -f /usr/lib/systemd/system/ssh.service ]]; then
        service_name="ssh"
    elif pgrep -x sshd >/dev/null 2>&1; then
        service_name="sshd"
    elif pgrep -x ssh >/dev/null 2>&1; then
        service_name="ssh"
    fi
    
    echo "$service_name"
}

####################################
# 重启 SSH 服务
####################################
restart_ssh_service() {
    local service_name
    service_name=$(detect_ssh_service)
    
    if [[ -z "$service_name" ]]; then
        red "无法检测 SSH 服务名"
        return 1
    fi
    
    yellow "重启 SSH 服务: ${service_name}"
    
    if systemctl restart "$service_name" 2>&1 | tee -a "$LOG_FILE"; then
        sleep 2  # 等待服务完全启动
        if systemctl is-active --quiet "$service_name"; then
            green "SSH 服务运行正常"
            return 0
        else
            red "SSH 服务未正常运行"
            return 1
        fi
    else
        red "SSH 服务重启失败"
        return 1
    fi
}

####################################
# 获取服务器 IP
####################################
get_server_ip() {
    local ip=""
    
    # 尝试多种方式获取外网 IP
    ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    
    if [[ -z "$ip" ]]; then
        # 获取本地 IP
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    
    echo "$ip"
}

####################################
# 测试密钥登录并等待确认
####################################
test_key_login_with_timeout() {
    local backup_file=$1
    local server_ip=$(get_server_ip)
    
    echo ""
    blue "=========================================="
    blue "重要：密钥登录测试"
    blue "=========================================="
    echo ""
    yellow "⚠️  即将切换到仅密钥登录模式"
    yellow "⚠️  密码登录将被禁用"
    echo ""
    blue "请在 ${TEST_TIMEOUT} 秒内完成以下测试："
    echo ""
    echo "1. 下载密钥文件到本地："
    echo "   scp root@${server_ip}:${KEY_DIR}/${KEY_NAME}.pem ~/.ssh/"
    echo ""
    echo "2. 设置密钥权限（本地执行）："
    echo "   chmod 600 ~/.ssh/${KEY_NAME}.pem"
    echo ""
    echo "3. 新开终端测试登录："
    echo "   ssh -i ~/.ssh/${KEY_NAME}.pem root@${server_ip}"
    echo ""
    echo "4. 如果登录成功，返回此窗口输入 'yes' 确认"
    echo "   如果登录失败，等待超时自动回滚"
    echo ""
    blue "=========================================="
    echo ""
    
    # 后台计时器
    (
        sleep "$TEST_TIMEOUT"
        echo ""
        echo ""
        red "⏰ 超时！未收到确认，自动回滚配置..."
        restore_config "$backup_file"
        red "已回滚到密码登录模式，请检查密钥配置"
        exit 1
    ) &
    local timer_pid=$!
    
    # 等待用户确认
    local confirm=""
    read -t "$TEST_TIMEOUT" -p "密钥登录测试成功后，输入 'yes' 确认: " confirm || true
    
    # 杀死计时器
    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    
    echo ""
    
    if [[ "$confirm" == "yes" || "$confirm" == "YES" ]]; then
        green "✓ 用户确认密钥登录成功"
        return 0
    else
        red "✗ 未确认或输入错误，回滚配置"
        restore_config "$backup_file"
        return 1
    fi
}

####################################
# 模式1: 混合认证（密钥+密码）
####################################
mode_hybrid() {
    echo ""
    blue "=========================================="
    blue "模式 1: 混合认证（密钥+密码共存）"
    blue "=========================================="
    echo ""
    
    # 备份配置
    local backup_file=$(backup_config)
    
    # 设置密码
    yellow "步骤 1/3: 设置 root 密码"
    local password=$(read_password)
    if ! set_root_password "$password"; then
        restore_config "$backup_file"
        exit 1
    fi
    
    # 配置 SSH
    yellow "步骤 2/3: 配置 SSH（允许密钥和密码）"
    set_ssh_option "PermitRootLogin" "yes"
    set_ssh_option "PasswordAuthentication" "yes"
    set_ssh_option "PubkeyAuthentication" "yes"
    set_ssh_option "UsePAM" "yes"
    
    # 验证并重启
    yellow "步骤 3/3: 验证配置并重启服务"
    if ! validate_ssh_config; then
        restore_config "$backup_file"
        exit 1
    fi
    
    if ! restart_ssh_service; then
        restore_config "$backup_file"
        exit 1
    fi
    
    echo ""
    green "✓ 混合认证模式配置完成"
    echo ""
    blue "当前状态："
    echo "  - ✓ root 密码登录：已启用"
    echo "  - ✓ SSH 密钥登录：已启用"
    echo ""
    yellow "安全建议："
    echo "  1. 配置 SSH 密钥后可禁用密码登录"
    echo "  2. 使用防火墙限制 SSH 访问"
    echo "  3. 启用 fail2ban 防暴力破解"
    echo ""
}

####################################
# 模式2: 仅密码认证
####################################
mode_password_only() {
    echo ""
    blue "=========================================="
    blue "模式 2: 仅密码认证"
    blue "=========================================="
    echo ""
    
    # 备份配置
    local backup_file=$(backup_config)
    
    # 设置密码
    yellow "步骤 1/3: 设置 root 密码"
    local password=$(read_password)
    if ! set_root_password "$password"; then
        restore_config "$backup_file"
        exit 1
    fi
    
    # 配置 SSH
    yellow "步骤 2/3: 配置 SSH（仅密码认证）"
    set_ssh_option "PermitRootLogin" "yes"
    set_ssh_option "PasswordAuthentication" "yes"
    set_ssh_option "PubkeyAuthentication" "no"
    set_ssh_option "UsePAM" "yes"
    
    # 验证并重启
    yellow "步骤 3/3: 验证配置并重启服务"
    if ! validate_ssh_config; then
        restore_config "$backup_file"
        exit 1
    fi
    
    if ! restart_ssh_service; then
        restore_config "$backup_file"
        exit 1
    fi
    
    echo ""
    green "✓ 仅密码认证模式配置完成"
    echo ""
    blue "当前状态："
    echo "  - ✓ root 密码登录：已启用"
    echo "  - ✗ SSH 密钥登录：已禁用"
    echo ""
    red "⚠️  安全警告："
    echo "  密码认证相对不安全，建议："
    echo "  1. 使用强密码（包含大小写、数字、特殊字符）"
    echo "  2. 启用 fail2ban 防止暴力破解"
    echo "  3. 考虑切换到密钥认证"
    echo ""
}

####################################
# 模式3: 仅密钥认证
####################################
mode_key_only() {
    echo ""
    blue "=========================================="
    blue "模式 3: 仅密钥认证（最安全）"
    blue "=========================================="
    echo ""
    
    # 备份配置
    local backup_file=$(backup_config)
    
    # 生成密钥
    yellow "步骤 1/5: 生成 SSH 密钥"
    local private_key=$(generate_ssh_key)
    if [[ -z "$private_key" ]]; then
        restore_config "$backup_file"
        exit 1
    fi
    
    # 导出多种格式
    yellow "步骤 2/5: 导出密钥格式"
    export_key_formats "$private_key"
    
    # 配置 authorized_keys
    yellow "步骤 3/5: 配置密钥认证"
    setup_authorized_keys "${private_key}.pub"
    
    # 配置 SSH（先不禁用密码，等测试成功后再禁用）
    yellow "步骤 4/5: 配置 SSH（准备切换到仅密钥模式）"
    set_ssh_option "PermitRootLogin" "yes"
    set_ssh_option "PubkeyAuthentication" "yes"
    
    if ! validate_ssh_config; then
        restore_config "$backup_file"
        exit 1
    fi
    
    if ! restart_ssh_service; then
        restore_config "$backup_file"
        exit 1
    fi
    
    # 测试密钥登录
    yellow "步骤 5/5: 测试密钥登录（60秒超时保护）"
    if ! test_key_login_with_timeout "$backup_file"; then
        red "密钥登录测试失败或超时，已回滚"
        exit 1
    fi
    
    # 确认成功后，禁用密码登录
    yellow "最后一步: 禁用密码登录"
    set_ssh_option "PasswordAuthentication" "no"
    
    if ! validate_ssh_config; then
        restore_config "$backup_file"
        exit 1
    fi
    
    if ! restart_ssh_service; then
        restore_config "$backup_file"
        exit 1
    fi
    
    echo ""
    green "✓✓✓ 仅密钥认证模式配置完成 ✓✓✓"
    echo ""
    blue "当前状态："
    echo "  - ✗ root 密码登录：已禁用"
    echo "  - ✓ SSH 密钥登录：已启用（仅限）"
    echo ""
    green "安全提示："
    echo "  1. 妥善保管私钥文件"
    echo "  2. 建议备份密钥到安全位置"
    echo "  3. 可删除服务器上的私钥文件"
    echo "  4. 定期更换密钥"
    echo ""
    yellow "密钥下载（如果还未下载）："
    local server_ip=$(get_server_ip)
    echo "  scp root@${server_ip}:${KEY_DIR}/${KEY_NAME}.pem ~/.ssh/"
    echo ""
}

####################################
# 显示菜单
####################################
show_menu() {
    clear
    echo ""
    echo "======================================"
    echo "  SSH 认证配置脚本 v${SCRIPT_VERSION}"
    echo "======================================"
    echo ""
    echo "请选择认证模式："
    echo ""
    echo "  1) 混合认证（密钥+密码共存）"
    echo "     - 允许密钥登录"
    echo "     - 允许密码登录"
    echo "     - 适合：过渡期使用"
    echo ""
    echo "  2) 仅密码认证"
    echo "     - 禁用密钥登录"
    echo "     - 仅允许密码登录"
    echo "     - 适合：快速配置、临时使用"
    echo ""
    echo "  3) 仅密钥认证（推荐）"
    echo "     - 禁用密码登录"
    echo "     - 仅允许密钥登录"
    echo "     - 自动生成密钥（PEM/PPK/PUB）"
    echo "     - 60秒超时保护（自动回滚）"
    echo "     - 适合：生产环境"
    echo ""
    echo "  0) 退出"
    echo ""
}

####################################
# 读取菜单选项（防止误输入）
####################################
read_menu_choice() {
    local choice
    while true; do
        read -r -p "请输入选项 [0-3]: " choice
        # 移除前后空白和特殊字符
        choice=$(echo "$choice" | tr -d '[:space:]')
        
        case $choice in
            0|1|2|3)
                echo "$choice"
                return 0
                ;;
            *)
                red "无效选项: $choice (请只输入数字 0-3)"
                sleep 1
                ;;
        esac
    done
}

####################################
# 主流程
####################################
main() {
    # 权限检查
    check_root
    
    # 依赖检查
    ensure_dependencies
    
    # SSH 配置检查
    check_sshd_config
    
    # 显示菜单并读取选择
    show_menu
    choice=$(read_menu_choice)
    
    case $choice in
        1)
            mode_hybrid
            ;;
        2)
            mode_password_only
            ;;
        3)
            mode_key_only
            ;;
        0)
            echo "退出脚本"
            exit 0
            ;;
    esac
    
    echo ""
    blue "配置日志: $LOG_FILE"
    blue "配置文件: $SSHD_CONFIG"
    echo ""
    green "感谢使用！"
}

# 执行主流程
main "$@"
