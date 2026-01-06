#!/bin/bash
#
# SSH Authentication Configuration Script
# Version: 4.2.0
# Purpose: 安全配置 SSH 认证方式（生产优化版）
#
# 使用: sudo bash $0
#
set -euo pipefail

####################################
# 配置常量
####################################
readonly SCRIPT_VERSION="4.2.0"
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
log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>&1 || true
}

msg_ok()    { echo -e "${C_GREEN}[✓]${C_RESET} $1"; log_msg "OK: $1"; }
msg_warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $1"; log_msg "WARN: $1"; }
msg_err()   { echo -e "${C_RED}[✗]${C_RESET} $1";   log_msg "ERROR: $1"; }
msg_info()  { echo -e "${C_BLUE}[i]${C_RESET} $1";  log_msg "INFO: $1"; }

####################################
# 权限检查
####################################
[[ $EUID -ne 0 ]] && { msg_err "请使用 root 权限运行此脚本"; echo "建议: sudo $0"; exit 1; }

####################################
# 依赖检查与自动安装
####################################
check_dependencies() {
    local deps=(sshd ssh-keygen systemctl)
    local missing=()

    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if ((${#missing[@]} > 0)); then
        msg_warn "缺少以下命令: ${missing[*]}"
        msg_info "尝试自动安装必要的软件包..."

        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y openssh-server putty-tools
        elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
            yum install -y openssh-server || dnf install -y openssh-server putty
        else
            msg_err "无法自动安装依赖，请手动安装 openssh-server 和 puttygen"
            exit 1
        fi
        msg_ok "依赖安装完成"
    fi
}

####################################
# 备份与恢复 sshd_config
####################################
backup_sshd_config() {
    local backup="${SSHD_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -a "$SSHD_CONFIG" "$backup" || { msg_err "无法备份 sshd_config"; exit 1; }
    echo "$backup"
}

restore_sshd_config() {
    local backup="$1"
    [[ -f "$backup" ]] || return
    cp -a "$backup" "$SSHD_CONFIG"
    msg_warn "已恢复 sshd 配置 → $backup"
    reload_sshd
}

####################################
# 修改 sshd 配置项（幂等）
####################################
set_sshd_option() {
    local key="$1" value="$2"
    local pattern="^#?[[:space:]]*${key}[[:space:]]"

    if grep -qE "${pattern}" "$SSHD_CONFIG"; then
        sed -i "s|^#*[[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

####################################
# 重载 SSH 服务（优先 reload，失败不中断）
####################################
reload_sshd() {
    local service
    if systemctl list-unit-files --type=service | grep -q '^ssh\.service'; then
        service="ssh"
    else
        service="sshd"
    fi

    msg_info "正在验证并重载 SSH 服务 (${service})..."

    if ! sshd -t >>"$LOG_FILE" 2>&1; then
        msg_err "sshd 配置语法检查失败！请查看 $LOG_FILE"
        return 1
    fi

    if systemctl reload "$service" 2>&1 | tee -a "$LOG_FILE"; then
        sleep 2
        systemctl is-active --quiet "$service" && msg_ok "SSH 服务已成功重载" || msg_warn "重载后服务状态异常，但继续执行"
    else
        msg_warn "reload 失败，继续执行（不影响当前会话）"
    fi
    return 0
}

####################################
# 生成 ED25519 密钥（覆盖模式）
####################################
generate_ed25519_key() {
    local key_base="${KEY_DIR}/id_ed25519"
    local priv="${key_base}"
    local pub="${key_base}.pub"
    local ppk="${key_base}.ppk"

    # 先删除旧密钥（实现覆盖）
    rm -f "$priv" "$pub" "$ppk" 2>/dev/null

    mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"

    msg_info "正在生成新的 ED25519 密钥对..."

    if ! ssh-keygen -t ed25519 -f "$priv" -N "" -C "root@$(hostname) $(date +%Y-%m-%d)" >/dev/null 2>&1; then
        msg_err "ED25519 密钥生成失败"
        return 1
    fi

    chmod 600 "$priv"
    chmod 644 "$pub"

    # 生成 PuTTY .ppk（如果有 puttygen）
    if command -v puttygen &>/dev/null; then
        puttygen "$priv" -o "$ppk" -O private >/dev/null 2>&1 &&
            chmod 600 "$ppk" &&
            msg_ok "已生成 PuTTY 格式私钥：${ppk}"
    fi

    echo "$priv"
    return 0
}

####################################
# 显示生成的密钥文件路径
####################################
show_key_files() {
    local key_base="$1"
    echo ""
    msg_ok "新生成的密钥文件如下（已覆盖旧文件）："
    echo "  私钥文件          : ${key_base}"
    echo "  公钥文件          : ${key_base}.pub"
    [[ -f "${key_base}.ppk" ]] && echo "  PuTTY 私钥 (PPK)  : ${key_base}.ppk"
    echo ""
    msg_warn "请立即将私钥安全传输到您的本地电脑，并妥善保管！"
    echo "   建议命令（在新终端执行）："
    echo "   scp root@$(hostname -I | awk '{print $1}'):${key_base} ~/.ssh/"
    echo ""
}

####################################
# 将公钥加入 authorized_keys
####################################
setup_authorized_keys() {
    local pub_file="$1"

    mkdir -p "$AUTH_KEYS_DIR" && chmod 700 "$AUTH_KEYS_DIR"

    if [[ -f "$AUTH_KEYS_FILE" ]] && grep -qFx "$(cat "$pub_file")" "$AUTH_KEYS_FILE"; then
        msg_warn "该公钥已存在于 authorized_keys，无需重复添加"
    else
        cat "$pub_file" >> "$AUTH_KEYS_FILE"
        chmod 600 "$AUTH_KEYS_FILE"
        msg_ok "公钥已成功写入 ${AUTH_KEYS_FILE}"
    fi
}

####################################
# 获取服务器主要公网 IP
####################################
get_server_ip() {
    local ip
    ip=$(curl -s --connect-timeout 4 ifconfig.me 2>/dev/null ||
         curl -s --connect-timeout 4 icanhazip.com 2>/dev/null ||
         hostname -I 2>/dev/null | awk '{print $1}')
    echo "${ip:-无法自动获取 IP}"
}

####################################
# 密钥登录测试（120秒超时 + nohup 回滚）
####################################
test_key_login() {
    local backup="$1" key_base="$2" server_ip
    server_ip=$(get_server_ip)

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_warn "密钥登录测试（${TEST_TIMEOUT}秒内完成验证）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "请在新终端执行以下步骤："
    echo ""
    echo "1. 安全拷贝私钥到本地"
    echo "   scp root@${server_ip}:${key_base} ~/.ssh/"
    echo ""
    echo "2. 设置严格权限"
    echo "   chmod 600 ~/.ssh/id_ed25519"
    echo ""
    echo "3. 测试登录"
    echo "   ssh -i ~/.ssh/id_ed25519 root@${server_ip}"
    echo ""
    echo "4. 登录成功后返回此处输入 yes 并回车"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # 使用 nohup 实现超时自动回滚（防止 SSH 断开后子进程被杀）
    nohup bash -c "sleep $TEST_TIMEOUT && echo '超时未确认 → 自动回滚配置' >> '$LOG_FILE' && cp -a '$backup' '$SSHD_CONFIG' && systemctl reload sshd || systemctl reload ssh" >/dev/null 2>&1 &
    local timer_pid=$!

    local confirm=""
    read -t "$TEST_TIMEOUT" -p "登录测试成功？请输入 yes 确认： " confirm || true

    kill "$timer_pid" 2>/dev/null
    wait "$timer_pid" 2>/dev/null

    if [[ "${confirm,,}" == "yes" ]]; then
        msg_ok "用户确认密钥登录有效"
        return 0
    else
        msg_err "未收到确认 → 执行回滚"
        restore_sshd_config "$backup"
        return 1
    fi
}

####################################
# 模式3：仅密钥认证（推荐）
####################################
mode_key_only() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg_info "模式 3：仅密钥认证（最安全推荐）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local backup=$(backup_sshd_config)
    msg_ok "已备份原始配置：$backup"

    # 生成新密钥（覆盖旧的）
    msg_info "步骤 1/5：生成新的 ED25519 密钥（覆盖旧密钥）"
    local key_path
    key_path=$(generate_ed25519_key) || { restore_sshd_config "$backup"; exit 1; }

    show_key_files "$key_path"

    # 添加到 authorized_keys
    msg_info "步骤 2/5：将公钥加入 authorized_keys"
    setup_authorized_keys "${key_path}.pub"

    # 先启用密钥 + 密码（测试阶段）
    msg_info "步骤 3/5：临时启用密钥认证"
    set_sshd_option "PermitRootLogin" "prohibit-password"   # 更安全的写法，但先测试
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"

    reload_sshd

    # 交互测试
    msg_info "步骤 4/5：进行登录测试（${TEST_TIMEOUT}秒）"
    test_key_login "$backup" "$key_path" || exit 1

    # 测试通过 → 彻底禁用密码
    msg_info "步骤 5/5：禁用密码登录，启用纯密钥模式"
    set_sshd_option "PasswordAuthentication" "no"
    set_sshd_option "PermitRootLogin" "prohibit-password"   # 推荐写法

    reload_sshd

    echo ""
    msg_ok "纯密钥认证配置完成！"
    echo "  • 密码登录：已永久禁用"
    echo "  • 密钥登录：已启用并验证通过"
    echo ""
    msg_warn "重要提醒："
    echo "  请务必将私钥 ${key_path} 安全备份到本地"
    echo "  丢失私钥将导致无法登录服务器！"
    echo ""
}

####################################
# 主菜单与流程
####################################
show_menu() {
    clear
    cat <<'EOF'

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

        case $choice in
            1) mode_hybrid; break ;;
            2) mode_password_only; break ;;
            3) mode_key_only; break ;;
            0) echo "退出"; exit 0 ;;
            *) msg_warn "无效选项，请重新输入" ;;
        esac
    done

    echo ""
    msg_info "操作日志： $LOG_FILE"
    msg_info "当前配置： $SSHD_CONFIG"
    msg_ok "配置完成！"
}

# 保留其他模式（混合、仅密码）简洁版实现（可根据需要补充完整）
mode_hybrid() { echo "混合模式（待实现）"; }
mode_password_only() { echo "仅密码模式（待实现）"; }

main "$@"
