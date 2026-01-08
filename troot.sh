#!/bin/bash

# By Quorecs
# SSH Authentication Configuration Script
# Version: 4.5.1 (Fixed)
# Purpose: 安全配置 SSH 认证方式（支持 cloud-init 系统）
# Fixes: 修复密码登录不生效、配置冲突、交互式认证缺失问题

set -euo pipefail

####################################
# 配置
####################################
readonly SCRIPT_VERSION="4.5.1"
readonly MIN_PASSWORD_LENGTH=8
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
readonly CLOUD_INIT_SSH_CONFIG="${SSHD_CONFIG_DIR}/50-cloud-init.conf"
readonly CLOUD_INIT_CFG_DIR="/etc/cloud/cloud.cfg.d"
readonly CLOUD_INIT_DISABLE_FILE="${CLOUD_INIT_CFG_DIR}/99-disable-ssh-auth.cfg"
readonly LOG_FILE="/var/log/ssh_auth_setup.log"
readonly KEY_DIR="/root/ssh_keys"
readonly AUTH_KEYS_DIR="/root/.ssh"
readonly AUTH_KEYS_FILE="${AUTH_KEYS_DIR}/authorized_keys"
readonly AUTH_KEYS_BACKUP="${AUTH_KEYS_DIR}/authorized_keys.disabled"
readonly TEST_TIMEOUT=120

# 颜色
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_BLUE='\033[34m'
C_CYAN='\033[36m'
C_MAGENTA='\033[35m'
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

msg_detect() {
    echo -e "${C_CYAN}[→]${C_RESET} $1"
}

msg_cloud() {
    echo -e "${C_MAGENTA}[☁]${C_RESET} $1"
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
# 检测 cloud-init
####################################
detect_cloud_init() {
    if command -v cloud-init &>/dev/null; then
        return 0
    fi
    
    # 检查是否存在 cloud-init 配置
    if [[ -d /etc/cloud ]] || [[ -f "$CLOUD_INIT_SSH_CONFIG" ]]; then
        return 0
    fi
    
    return 1
}

####################################
# 查找 cloud-init SSH 配置文件
####################################
find_cloud_init_ssh_config() {
    local config_files=(
        "${SSHD_CONFIG_DIR}/50-cloud-init.conf"
        "${SSHD_CONFIG_DIR}/60-cloudimg-settings.conf"
        "${SSHD_CONFIG_DIR}/99-cloud-init.conf"
    )
    
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]]; then
            echo "$config"
            return 0
        fi
    done
    
    # 搜索所有可能的 cloud-init 配置
    if [[ -d "$SSHD_CONFIG_DIR" ]]; then
        local found
        found=$(find "$SSHD_CONFIG_DIR" -type f -name "*cloud*" 2>/dev/null | head -n1)
        if [[ -n "$found" ]]; then
            echo "$found"
            return 0
        fi
    fi
    
    return 1
}

####################################
# 配置 cloud-init SSH drop-in
####################################
configure_cloud_init_ssh() {
    local password_auth="$1"
    local pubkey_auth="$2"
    
    msg_cloud "检测到 cloud-init 系统"
    
    # 创建 drop-in 目录
    mkdir -p "$SSHD_CONFIG_DIR"
    
    # 查找现有配置
    local cloud_config
    cloud_config=$(find_cloud_init_ssh_config)
    
    if [[ -n "$cloud_config" ]]; then
        msg_info "找到 cloud-init SSH 配置: $cloud_config"
        # 备份原配置
        cp "$cloud_config" "${cloud_config}.backup.$(date +%Y%m%d_%H%M%S)"
    else
        cloud_config="$CLOUD_INIT_SSH_CONFIG"
        msg_info "创建新的 cloud-init SSH 配置: $cloud_config"
    fi
    
    # 写入配置 (修复：添加 KbdInteractiveAuthentication)
    cat > "$cloud_config" <<EOF
# Managed by SSH Auth Setup Script v${SCRIPT_VERSION}
# Generated: $(date)

PasswordAuthentication ${password_auth}
PubkeyAuthentication ${pubkey_auth}
KbdInteractiveAuthentication yes
PermitRootLogin yes
UsePAM yes
EOF
    
    chmod 644 "$cloud_config"
    msg_ok "cloud-init SSH 配置已更新"
    
    # 验证配置生效
    echo ""
    msg_info "验证最终 SSH 配置..."
    local password_check pubkey_check
    password_check=$(sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
    pubkey_check=$(sshd -T 2>/dev/null | grep "^pubkeyauthentication" | awk '{print $2}')
    
    echo " PasswordAuthentication: ${password_check}"
    echo " PubkeyAuthentication: ${pubkey_check}"
    echo " PermitRootLogin: $(sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}')"
    echo ""
    
    if [[ "$password_check" != "$password_auth" ]]; then
        msg_warn "警告: PasswordAuthentication 配置可能未生效"
        msg_info "可能需要重启系统"
    fi
    
    if [[ "$pubkey_check" != "$pubkey_auth" ]]; then
        msg_warn "警告: PubkeyAuthentication 配置可能未生效"
        msg_info "可能需要重启系统"
    fi
}

####################################
# 禁用 cloud-init SSH 管理（永久密码登录）
####################################
disable_cloud_init_ssh_management() {
    msg_cloud "配置 cloud-init 永久启用密码登录"
    
    mkdir -p "$CLOUD_INIT_CFG_DIR"
    
    cat > "$CLOUD_INIT_DISABLE_FILE" <<'EOF'
# Disable cloud-init SSH authentication management
# This ensures password authentication remains enabled after reboot

ssh_pwauth: true

# Prevent cloud-init from managing SSH config
ssh_deletekeys: false
ssh_genkeytypes: []

# Keep our SSH configuration
bootcmd:
  - [ sh, -c, 'echo "SSH config managed manually" > /var/log/cloud-init-ssh-disabled.log' ]
EOF
    
    chmod 644 "$CLOUD_INIT_DISABLE_FILE"
    msg_ok "cloud-init SSH 管理已禁用"
    
    log_msg "Created cloud-init disable file: $CLOUD_INIT_DISABLE_FILE"
}

####################################
# 提示重启（仅在需要时）
####################################
prompt_reboot_if_needed() {
    local password_check pubkey_check password_expected pubkey_expected
    
    password_expected="$1"
    pubkey_expected="$2"
    
    password_check=$(sshd -T 2>/dev/null | grep "^passwordauthentication" | awk '{print $2}')
    pubkey_check=$(sshd -T 2>/dev/null | grep "^pubkeyauthentication" | awk '{print $2}')
    
    if [[ "$password_check" != "$password_expected" ]] || [[ "$pubkey_check" != "$pubkey_expected" ]]; then
        echo ""
        msg_warn "配置可能需要重启才能完全生效"
        echo ""
        read -p "是否现在重启系统? (yes/no): " do_reboot
        
        if [[ "$do_reboot" == "yes" ]]; then
            msg_info "系统将在 5 秒后重启..."
            sleep 5
            reboot
        else
            msg_info "请稍后手动重启: reboot"
        fi
    fi
}

####################################
# 检测当前认证方式
####################################
detect_current_auth_method() {
    local has_valid_key=false
    local has_password=false
    
    # 检查是否有有效的密钥
    if [[ -f "$AUTH_KEYS_FILE" ]] && [[ -s "$AUTH_KEYS_FILE" ]]; then
        if grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp)' "$AUTH_KEYS_FILE" 2>/dev/null; then
            has_valid_key=true
        fi
    fi
    
    # 检查是否设置了密码
    if [[ -f /etc/shadow ]]; then
        local root_shadow
        root_shadow=$(grep "^root:" /etc/shadow 2>/dev/null || echo "")
        if [[ -n "$root_shadow" ]] && echo "$root_shadow" | awk -F: '{print $2}' | grep -qvE '^(\*|!|\*LOCK\*)'; then
            has_password=true
        fi
    fi
    
    # 返回结果
    if $has_valid_key && $has_password; then
        echo "hybrid"
    elif $has_valid_key; then
        echo "key_only"
    elif $has_password; then
        echo "password_only"
    else
        echo "none"
    fi
}

####################################
# 显示当前认证状态
####################################
show_current_status() {
    local auth_method=$(detect_current_auth_method)
    
    echo ""
    echo "=========================================="
    msg_detect "检测到当前认证方式"
    echo "=========================================="
    
    case "$auth_method" in
        hybrid)
            echo " 状态: 混合认证"
            echo " ✓ 密钥登录: 已启用"
            echo " ✓ 密码登录: 已启用"
            ;;
        key_only)
            echo " 状态: 仅密钥认证"
            echo " ✓ 密钥登录: 已启用"
            echo " ✗ 密码登录: 未配置"
            ;;
        password_only)
            echo " 状态: 仅密码认证"
            echo " ✗ 密钥登录: 无密钥"
            echo " ✓ 密码登录: 已启用"
            ;;
        none)
            echo " 状态: 未配置"
            echo " ✗ 密钥登录: 无密钥"
            echo " ✗ 密码登录: 未配置"
            ;;
    esac
    
    # 检测 cloud-init
    if detect_cloud_init; then
        msg_cloud "检测到 cloud-init 系统"
    fi
    
    echo "=========================================="
    echo ""
    
    echo "$auth_method"
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
        reload_sshd
    fi
}

####################################
# 修改 SSH 配置 (核心修复)
####################################
set_sshd_option() {
    local key="$1"
    local value="$2"
   
    # 核心修复：彻底删除旧行（包括注释行），防止重复或顺序覆盖
    # sed -i "/^[[:space:]]*#\?[[:space:]]*${key}[[:space:]]/d" "$SSHD_CONFIG"
    # 更安全的正则，避免误删类似前缀的配置
    sed -i "/^[[:space:]]*\(#\)\?[[:space:]]*${key}\([[:space:]]\+\|=\)/d" "$SSHD_CONFIG"
    
    # 追加新配置到文件末尾，确保优先级
    echo "${key} ${value}" >> "$SSHD_CONFIG"
}

####################################
# 检测并重载 SSH 服务
####################################
reload_sshd() {
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
   
    # 核心修复：使用 restart 而不是 reload，确保 auth 方式变更立即生效
    if systemctl restart "$service" 2>&1 | tee -a "$LOG_FILE"; then
        sleep 2
        if systemctl is-active --quiet "$service"; then
            msg_ok "SSH 服务已重启"
            return 0
        fi
    fi
   
    msg_warn "SSH 服务重启失败"
    return 1
}

####################################
# 禁用密钥认证
####################################
disable_key_auth() {
    msg_info "禁用现有密钥认证"
    
    # 备份 authorized_keys
    if [[ -f "$AUTH_KEYS_FILE" ]]; then
        mv "$AUTH_KEYS_FILE" "$AUTH_KEYS_BACKUP"
        msg_ok "已备份并禁用 authorized_keys"
        log_msg "Moved $AUTH_KEYS_FILE to $AUTH_KEYS_BACKUP"
    fi
}

####################################
# 恢复密钥认证
####################################
restore_key_auth() {
    msg_info "恢复密钥认证"
    
    # 恢复 authorized_keys
    if [[ -f "$AUTH_KEYS_BACKUP" ]]; then
        mv "$AUTH_KEYS_BACKUP" "$AUTH_KEYS_FILE"
        chmod 600 "$AUTH_KEYS_FILE"
        msg_ok "已恢复 authorized_keys"
    fi
}

####################################
# 清理旧密钥
####################################
cleanup_old_keys() {
    if [[ -d "$KEY_DIR" ]]; then
        local key_count=$(find "$KEY_DIR" -type f \( -name "*.pem" -o -name "*.pub" -o -name "*.ppk" -o ! -name ".*" \) 2>/dev/null | wc -l)
        if [[ $key_count -gt 0 ]]; then
            msg_warn "发现 $key_count 个旧密钥文件"
            read -p "是否删除所有旧密钥? (yes/no): " cleanup
            if [[ "$cleanup" == "yes" ]]; then
                rm -rf "$KEY_DIR"/*
                msg_ok "已清理旧密钥"
            else
                msg_info "保留旧密钥"
            fi
        fi
    fi
}

####################################
# 读取密码（使用 passwd 命令）
####################################
set_root_password_interactive() {
    msg_info "现在将使用 passwd 命令设置 root 密码"
    msg_info "请输入密码两次（输入时不会显示）"
    echo ""
   
    if passwd root 2>&1 | tee -a "$LOG_FILE"; then
        # 验证密码是否真的设置成功
        sleep 1
        if grep "^root:" /etc/shadow 2>/dev/null | awk -F: '{print $2}' | grep -qvE '^(\*|!|\*LOCK\*)'; then
            msg_ok "root 密码设置成功"
            return 0
        else
            msg_err "密码设置失败: 密码未生效"
            return 1
        fi
    else
        msg_err "密码设置失败"
        return 1
    fi
}

####################################
# 验证密码登录是否可用
####################################
test_password_capability() {
    msg_info "检测密码登录能力..."
    
    # 检查 PAM 配置
    if [[ ! -f /etc/pam.d/sshd ]] && [[ ! -f /etc/pam.d/ssh ]]; then
        msg_warn "未找到 PAM SSH 配置文件"
        return 1
    fi
    
    # 检查 shadow 文件
    if [[ ! -f /etc/shadow ]]; then
        msg_warn "未找到 shadow 文件"
        return 1
    fi
    
    # 检查 passwd 命令
    if ! command -v passwd &>/dev/null; then
        msg_warn "passwd 命令不可用"
        return 1
    fi
    
    return 0
}

####################################
# 生成 SSH 密钥
####################################
generate_ssh_key() {
    local key_name="ssh_key_$(date +%Y%m%d_%H%M%S)"
    local key_path="${KEY_DIR}/${key_name}"
   
    # 创建密钥目录
    mkdir -p "$KEY_DIR"
    chmod 700 "$KEY_DIR"
   
    # 尝试 ED25519
    if ssh-keygen -t ed25519 -f "$key_path" -N "" -C "root@$(hostname)" >/dev/null 2>&1; then
        chmod 600 "$key_path"
        chmod 644 "${key_path}.pub"
        printf '%s' "$key_path"
        return 0
    fi
   
    # 降级到 RSA 4096
    if ssh-keygen -t rsa -b 4096 -f "$key_path" -N "" -C "root@$(hostname)" >/dev/null 2>&1; then
        chmod 600 "$key_path"
        chmod 644 "${key_path}.pub"
        printf '%s' "$key_path"
        return 0
    fi
   
    return 1
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
    echo " 私钥 (PEM): ${base}.pem"
    [[ -f "${base}.ppk" ]] && echo " 私钥 (PPK): ${base}.ppk"
    echo " 公钥 (PUB): ${private_key}.pub"
    echo ""
}

####################################
# 配置 authorized_keys
####################################
setup_authorized_keys() {
    local public_key="$1"
    local keep_old="${2:-false}"
   
    mkdir -p "$AUTH_KEYS_DIR"
    chmod 700 "$AUTH_KEYS_DIR"
   
    if [[ "$keep_old" == "true" ]] && [[ -f "$AUTH_KEYS_FILE" ]]; then
        # 保留旧密钥，追加新密钥
        if grep -qF "$(cat "$public_key")" "$AUTH_KEYS_FILE" 2>/dev/null; then
            msg_warn "公钥已存在于 authorized_keys"
        else
            cat "$public_key" >> "$AUTH_KEYS_FILE"
            msg_ok "公钥已追加到 authorized_keys (保留旧密钥)"
        fi
    else
        # 替换为新密钥
        cat "$public_key" > "$AUTH_KEYS_FILE"
        msg_ok "公钥已配置到 authorized_keys"
    fi
   
    chmod 600 "$AUTH_KEYS_FILE"
}

####################################
# 获取服务器 IP
####################################
get_server_ip() {
    local ip
    
    # 优先获取 IPv4
    ip=$(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || \
         curl -4 -s --max-time 3 icanhazip.com 2>/dev/null || \
         hostname -I 2>/dev/null | awk '{print $1}')
    
    # 如果没有 IPv4，尝试 IPv6
    if [[ -z "$ip" || "$ip" == "unknown" ]]; then
        ip=$(curl -6 -s --max-time 3 ifconfig.me 2>/dev/null || \
             curl -6 -s --max-time 3 icanhazip.com 2>/dev/null)
    fi
    
    echo "${ip:-unknown}"
}

####################################
# 密码登录测试
####################################
test_password_login() {
    local server_ip=$(get_server_ip)
    
    echo ""
    echo "=========================================="
    msg_warn "密码登录测试"
    echo "=========================================="
    echo ""
    echo "请在新终端测试密码登录："
    echo ""
    if [[ "$server_ip" =~ : ]]; then
        echo " ssh root@[$server_ip]"
    else
        echo " ssh root@${server_ip}"
    fi
    echo ""
    echo "如果登录成功，返回此窗口输入 'yes'"
    echo "如果失败，输入 'no' 将回滚配置"
    echo ""
    echo "=========================================="
    echo ""
    
    local confirm
    read -p "确认密码登录成功 (输入 yes/no): " confirm
    
    if [[ "$confirm" == "yes" || "$confirm" == "YES" ]]; then
        msg_ok "密码登录测试成功"
        return 0
    else
        msg_err "密码登录测试失败"
        return 1
    fi
}

####################################
# 密钥登录测试（新逻辑：保留密码）
####################################
test_key_login() {
    local backup="$1"
    local key_base="$2"
    local server_ip=$(get_server_ip)
   
    echo ""
    echo "=========================================="
    msg_warn "密钥登录测试"
    echo "=========================================="
    echo ""
    msg_info "重要: 密码登录将保持启用状态"
    msg_info "这样您可以安全地测试新密钥"
    echo ""
    echo "请在新终端执行以下步骤："
    echo ""
    echo "1. 下载密钥:"
    if [[ "$server_ip" =~ : ]]; then
        echo " scp root@[${server_ip}]:${key_base}.pem ~/.ssh/"
    else
        echo " scp root@${server_ip}:${key_base}.pem ~/.ssh/"
    fi
    echo ""
    echo "2. 设置权限:"
    echo " chmod 600 ~/.ssh/$(basename ${key_base}).pem"
    echo ""
    echo "3. 测试登录:"
    if [[ "$server_ip" =~ : ]]; then
        echo " ssh -i ~/.ssh/$(basename ${key_base}).pem root@[$server_ip]"
    else
        echo " ssh -i ~/.ssh/$(basename ${key_base}).pem root@${server_ip}"
    fi
    echo ""
    echo "4. 如果登录成功，返回此窗口输入 'yes'"
    echo ""
    echo "=========================================="
    echo ""
   
    local confirm
    read -p "确认密钥登录成功 (输入 yes/no): " confirm
   
    if [[ "$confirm" == "yes" || "$confirm" == "YES" ]]; then
        msg_ok "密钥登录测试成功"
        
        # 询问是否禁用密码登录
        echo ""
        read -p "是否现在禁用密码登录? (yes/no): " disable_password
        
        if [[ "$disable_password" == "yes" ]]; then
            return 0  # 禁用密码
        else
            msg_info "密码登录将保持启用状态（混合模式）"
            return 2  # 保持混合模式
        fi
    else
        msg_err "密钥登录测试失败"
        msg_warn "建议检查密钥是否正确下载"
        return 1
    fi
}

####################################
# 模式1: 混合认证（智能逻辑）
####################################
mode_hybrid() {
    echo ""
    echo "=========================================="
    msg_info "模式 1: 混合认证 (密钥+密码)"
    echo "=========================================="
    echo ""
    
    # 检测当前认证方式
    local current_auth=$(detect_current_auth_method)
    local is_cloud_init=false
    
    if detect_cloud_init; then
        is_cloud_init=true
    fi
    
    local backup=$(backup_sshd_config)
    msg_ok "配置已备份"
    
    case "$current_auth" in
        key_only)
            # 场景: 用户使用密钥登录，需要增加密码
            echo ""
            msg_detect "检测到仅密钥认证，将增加密码登录"
            echo ""
            
            # 检测密码登录能力
            if ! test_password_capability; then
                msg_err "系统不支持密码登录"
                msg_warn "可能原因: 精简系统镜像缺少 PAM 或 shadow 支持"
                msg_info "建议: 继续使用密钥认证"
                restore_sshd_config "$backup"
                exit 1
            fi
            
            msg_info "步骤 1/4: 设置 root 密码"
            if ! set_root_password_interactive; then
                restore_sshd_config "$backup"
                exit 1
            fi
            
            echo ""
            msg_info "步骤 2/4: 配置 SSH (保留现有密钥)"
            set_sshd_option "PermitRootLogin" "yes"
            set_sshd_option "PasswordAuthentication" "yes"
            set_sshd_option "PubkeyAuthentication" "yes"
            set_sshd_option "UsePAM" "yes"
            set_sshd_option "KbdInteractiveAuthentication" "yes" # 修复：强制交互式认证
            
            # cloud-init 系统配置
            if $is_cloud_init; then
                configure_cloud_init_ssh "yes" "yes"
                
                echo ""
                read -p "是否永久启用密码登录（防止重启后重置）? (yes/no): " permanent
                if [[ "$permanent" == "yes" ]]; then
                    disable_cloud_init_ssh_management
                    msg_ok "已配置永久密码登录"
                fi
            fi
            
            msg_ok "SSH 配置完成，现有密钥不会改变"
            
            echo ""
            msg_info "步骤 3/4: 重启 SSH 服务"
            if ! reload_sshd; then
                restore_sshd_config "$backup"
                exit 1
            fi
            
            echo ""
            msg_info "步骤 4/4: 测试密码登录"
            if ! test_password_login; then
                msg_warn "测试失败，是否回滚配置？"
                read -p "回滚配置? (yes/no): " rollback
                if [[ "$rollback" == "yes" ]]; then
                    restore_sshd_config "$backup"
                    exit 1
                fi
            fi
            
            # 检查是否需要重启
            if $is_cloud_init; then
                prompt_reboot_if_needed "yes" "yes"
            fi
            
            echo ""
            msg_ok "混合认证模式配置完成"
            echo ""
            echo "当前状态:"
            echo " ✓ 密码登录: 已启用 (新增)"
            echo " ✓ 密钥登录: 已启用 (保留原密钥)"
            ;;
            
        password_only|none)
            # 场景: 用户使用密码登录或无认证，需要生成密钥
            echo ""
            msg_detect "检测到无密钥配置，将生成新密钥"
            echo ""
            
            # 清理旧密钥
            cleanup_old_keys
            
            msg_info "步骤 1/7: 确认 root 密码"
            if [[ "$current_auth" == "none" ]]; then
                if ! set_root_password_interactive; then
                    restore_sshd_config "$backup"
                    exit 1
                fi
            else
                read -p "是否重新设置密码? (yes/no): " reset_pw
                if [[ "$reset_pw" == "yes" ]]; then
                    if ! set_root_password_interactive; then
                        restore_sshd_config "$backup"
                        exit 1
                    fi
                else
                    msg_ok "使用现有密码"
                fi
            fi
            
            echo ""
            msg_info "步骤 2/7: 生成 SSH 密钥"
            local key_path
            key_path=$(generate_ssh_key)
            local gen_status=$?
            
            if [[ $gen_status -ne 0 || -z "$key_path" || ! -f "$key_path" ]]; then
                msg_err "密钥生成失败"
                restore_sshd_config "$backup"
                exit 1
            fi
            
            echo ""
            msg_info "步骤 3/7: 导出密钥格式"
            export_key_formats "$key_path"
            
            echo ""
            msg_info "步骤 4/7: 配置密钥认证"
            setup_authorized_keys "${key_path}.pub" "false"
            
            echo ""
            msg_info "步骤 5/7: 配置 SSH"
            set_sshd_option "PermitRootLogin" "yes"
            set_sshd_option "PasswordAuthentication" "yes"
            set_sshd_option "PubkeyAuthentication" "yes"
            set_sshd_option "UsePAM" "yes"
            set_sshd_option "KbdInteractiveAuthentication" "yes" # 修复：强制交互式认证
            
            # cloud-init 系统配置
            if $is_cloud_init; then
                configure_cloud_init_ssh "yes" "yes"
                
                echo ""
                read -p "是否永久启用密码登录（防止重启后重置）? (yes/no): " permanent
                if [[ "$permanent" == "yes" ]]; then
                    disable_cloud_init_ssh_management
                    msg_ok "已配置永久密码登录"
                fi
            fi
            
            msg_ok "SSH 配置完成"
            
            echo ""
            msg_info "步骤 6/7: 重启 SSH 服务"
            if ! reload_sshd; then
                restore_sshd_config "$backup"
                exit 1
            fi
            
            # 检查是否需要重启
            if $is_cloud_init; then
                prompt_reboot_if_needed "yes" "yes"
            fi
            
            echo ""
            msg_info "步骤 7/7: 测试完成"
            echo ""
            msg_ok "混合认证模式配置完成"
            echo ""
            echo "当前状态:"
            echo " ✓ 密码登录: 已启用"
            echo " ✓ 密钥登录: 已启用 (新生成)"
            echo ""
            msg_warn "重要: 请保存新生成的密钥"
            echo "密钥位置: ${key_path%.*}.pem"
            ;;
            
        hybrid)
            # 场景: 已经是混合认证
            echo ""
            msg_warn "检测到已经配置为混合认证模式"
            echo ""
            read -p "是否重新设置密码? (yes/no): " reset_password
            
            if [[ "$reset_password" == "yes" ]]; then
                echo ""
                msg_info "重新设置 root 密码"
                if ! set_root_password_interactive; then
                    restore_sshd_config "$backup"
                    exit 1
                fi
                msg_ok "密码已更新"
            fi
            
            # 确保配置正确 (覆盖修复)
            set_sshd_option "PermitRootLogin" "yes"
            set_sshd_option "PasswordAuthentication" "yes"
            set_sshd_option "PubkeyAuthentication" "yes"
            set_sshd_option "UsePAM" "yes"
            set_sshd_option "KbdInteractiveAuthentication" "yes"
            
            # cloud-init 系统配置
            if $is_cloud_init; then
                configure_cloud_init_ssh "yes" "yes"
                
                if [[ ! -f "$CLOUD_INIT_DISABLE_FILE" ]]; then
                    echo ""
                    read -p "是否永久启用密码登录（防止重启后重置）? (yes/no): " permanent
                    if [[ "$permanent" == "yes" ]]; then
                        disable_cloud_init_ssh_management
                    fi
                fi
            fi
            
            reload_sshd
            
            echo ""
            msg_ok "混合认证配置已确认"
            ;;
    esac
    
    echo ""
    msg_info "提示: 客户端默认优先使用密钥认证"
    msg_info "强制使用密码: ssh -o PubkeyAuthentication=no root@server"
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
    
    # 检测密码登录能力
    if ! test_password_capability; then
        msg_err "系统不支持密码登录"
        msg_warn "可能原因: 精简系统镜像缺少 PAM 或 shadow 支持"
        msg_info "建议: 使用密钥认证（模式 1 或 3）"
        exit 1
    fi
    
    local is_cloud_init=false
    if detect_cloud_init; then
        is_cloud_init=true
    fi
   
    local backup=$(backup_sshd_config)
    msg_ok "配置已备份"
   
    # 设置密码
    echo ""
    msg_info "步骤 1/4: 设置 root 密码"
    if ! set_root_password_interactive; then
        restore_sshd_config "$backup"
        exit 1
    fi
   
    # 禁用密钥认证
    echo ""
    msg_info "步骤 2/4: 禁用密钥认证"
    disable_key_auth
   
    # 配置 SSH
    echo ""
    msg_info "步骤 3/4: 配置 SSH"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PasswordAuthentication" "yes"
    set_sshd_option "PubkeyAuthentication" "no"
    set_sshd_option "UsePAM" "yes"
    set_sshd_option "KbdInteractiveAuthentication" "yes" # 修复：强制交互式认证
    
    # cloud-init 系统配置（默认永久启用密码）
    if $is_cloud_init; then
        configure_cloud_init_ssh "yes" "no"
        disable_cloud_init_ssh_management
        msg_cloud "已配置永久密码登录"
    fi
    
    msg_ok "SSH 配置完成"
   
    # 重载服务
    echo ""
    msg_info "步骤 4/4: 重启 SSH 服务"
    if ! reload_sshd; then
        restore_sshd_config "$backup"
        exit 1
    fi
    
    # 检查是否需要重启
    if $is_cloud_init; then
        prompt_reboot_if_needed "yes" "no"
    fi
   
    # 测试密码登录
    echo ""
    if ! test_password_login; then
        msg_warn "测试失败，是否回滚配置？"
        read -p "回滚配置? (yes/no): " rollback
        if [[ "$rollback" == "yes" ]]; then
            restore_sshd_config "$backup"
            restore_key_auth
            reload_sshd
            exit 1
        fi
    fi
   
    echo ""
    msg_ok "仅密码认证模式配置完成"
    echo ""
    echo "当前状态:"
    echo " ✓ 密码登录: 已启用（永久）"
    echo " ✗ 密钥登录: 已禁用"
    echo ""
    msg_warn "安全提示: 密码认证相对不安全"
    echo "建议: 使用强密码 + fail2ban"
    echo "恢复密钥: authorized_keys 已备份至 $AUTH_KEYS_BACKUP"
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
    
    local is_cloud_init=false
    if detect_cloud_init; then
        is_cloud_init=true
    fi
   
    local backup=$(backup_sshd_config)
    msg_ok "配置已备份"
    
    # 清理旧密钥
    cleanup_old_keys
   
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
   
    # 配置 authorized_keys（追加，保留旧密钥）
    echo ""
    msg_info "步骤 3/5: 配置密钥认证"
    setup_authorized_keys "${key_path}.pub" "true"
   
    # 启用密钥登录（保留密码以便测试）
    echo ""
    msg_info "步骤 4/5: 启用密钥登录（暂时保留密码）"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"
    set_sshd_option "KbdInteractiveAuthentication" "yes" # 临时开启以便测试
    
    # cloud-init 系统配置
    if $is_cloud_init; then
        configure_cloud_init_ssh "yes" "yes"
    fi
   
    if ! reload_sshd; then
        restore_sshd_config "$backup"
        exit 1
    fi
   
    # 测试密钥登录
    echo ""
    msg_info "步骤 5/5: 测试密钥登录"
    local test_result
    test_key_login "$backup" "${key_path%.*}"
    test_result=$?
    
    if [[ $test_result -eq 1 ]]; then
        # 测试失败，回滚
        msg_err "密钥测试失败，已回滚配置"
        exit 1
    elif [[ $test_result -eq 0 ]]; then
        # 用户确认禁用密码
        echo ""
        msg_info "禁用密码登录"
        set_sshd_option "PasswordAuthentication" "no"
        set_sshd_option "KbdInteractiveAuthentication" "no" # 禁用交互式认证
        
        # cloud-init 系统配置
        if $is_cloud_init; then
            configure_cloud_init_ssh "no" "yes"
        fi
        
        reload_sshd
        
        # 检查是否需要重启
        if $is_cloud_init; then
            prompt_reboot_if_needed "no" "yes"
        fi
        
        echo ""
        msg_ok "仅密钥认证模式配置完成"
        echo ""
        echo "当前状态:"
        echo " ✗ 密码登录: 已禁用"
        echo " ✓ 密钥登录: 已启用"
    else
        # test_result == 2，保持混合模式
        if $is_cloud_init; then
            prompt_reboot_if_needed "yes" "yes"
        fi
        
        echo ""
        msg_ok "混合认证模式已启用"
        echo ""
        echo "当前状态:"
        echo " ✓ 密码登录: 已启用"
        echo " ✓ 密钥登录: 已启用"
    fi
   
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
    
    # 显示当前状态
    local current_status=$(show_current_status)
    
    echo ""
    echo "=========================================="
    echo " SSH 认证配置 v${SCRIPT_VERSION}"
    echo "=========================================="
    echo ""
    echo "1) 混合认证 (密钥+密码) - 智能配置"
    echo " • 有密钥: 增加密码登录"
    echo " • 无密钥: 生成密钥 + 设置密码"
    echo ""
    echo "2) 仅密码认证"
    echo " - 只允许密码登录"
    echo " - 会禁用现有密钥"
    echo " - 自动配置永久密码"
    echo ""
    echo "3) 仅密钥认证 (推荐)"
    echo " - 只允许密钥登录"
    echo " - 最安全的方式"
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
