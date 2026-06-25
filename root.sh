#!/bin/bash
# By Quorecs
# SSH Authentication Configuration Script
# Version: 4.2.0
# Purpose: 安全配置 SSH 认证方式
#
#
set -euo pipefail
####################################
# 配置
####################################
readonly SCRIPT_VERSION="4.2.0"
readonly MIN_PASSWORD_LENGTH=8
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly LOG_FILE="/var/log/ssh_auth_setup.log"
readonly KEY_DIR="/root/ssh_keys"
readonly AUTH_KEYS_DIR="/root/.ssh"
readonly AUTH_KEYS_FILE="${AUTH_KEYS_DIR}/authorized_keys"
readonly TEST_TIMEOUT=120

# 颜色
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_BLUE='\033[34m'
C_RESET='\033[0m'

####################################
# 全局变量（用于替代命令替换传值，避免输出污染）
####################################
BACKUP_PATH=""
GENERATED_KEY_PATH=""

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
# 修复：不再用命令替换捕获路径
# 改为写入全局变量 BACKUP_PATH，避免函数内的
# msg_ok 等输出被误捕获进路径字符串
####################################
backup_sshd_config() {
    BACKUP_PATH="${SSHD_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
    if cp -a "$SSHD_CONFIG" "$BACKUP_PATH"; then
        msg_ok "配置已备份至: $BACKUP_PATH"
        log_msg "备份路径: $BACKUP_PATH"
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
# 检测 SSH 服务名
####################################
detect_ssh_service() {
    if systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service'; then
        echo "sshd"
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service'; then
        echo "ssh"
    elif pgrep -x sshd &>/dev/null; then
        echo "sshd"
    else
        echo "ssh"
    fi
}

####################################
# 检测并重载 SSH 服务
####################################
reload_sshd() {
    local service
    service=$(detect_ssh_service)

    msg_info "重载 SSH 服务: $service"

    # 验证配置
    if ! sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        msg_err "SSH 配置验证失败"
        return 1
    fi

    # 重载服务（不中断连接）
    if systemctl reload "$service" 2>&1 | tee -a "$LOG_FILE"; then
        sleep 2
        if systemctl is-active --quiet "$service"; then
            msg_ok "SSH 服务已重载"
            return 0
        fi
    fi

    msg_warn "SSH 服务重载失败，继续执行"
    return 0
}

####################################
# 读取密码（使用 passwd 命令）
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
# 修复：不再用命令替换捕获路径
# 改为写入全局变量 GENERATED_KEY_PATH，彻底避免
# 函数内任何输出（含将来新增的 msg_* 调用）污染路径
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
        GENERATED_KEY_PATH="$key_path"
        return 0
    fi

    # 降级到 RSA 4096
    if ssh-keygen -t rsa -b 4096 -f "$key_path" -N "" -C "root@$(hostname)" >/dev/null 2>&1; then
        chmod 600 "$key_path"
        chmod 644 "${key_path}.pub"
        GENERATED_KEY_PATH="$key_path"
        return 0
    fi

    GENERATED_KEY_PATH=""
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

    mkdir -p "$AUTH_KEYS_DIR"
    chmod 700 "$AUTH_KEYS_DIR"

    # 修复：使用 ssh-keygen -l 比对指纹，比 grep 全文更可靠
    local new_fingerprint
    new_fingerprint=$(ssh-keygen -lf "$public_key" 2>/dev/null | awk '{print $2}')

    if [[ -f "$AUTH_KEYS_FILE" && -n "$new_fingerprint" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            local existing_fp
            existing_fp=$(echo "$line" | ssh-keygen -lf /dev/stdin 2>/dev/null | awk '{print $2}') || true
            if [[ "$existing_fp" == "$new_fingerprint" ]]; then
                msg_warn "公钥已存在（指纹匹配），跳过添加"
                chmod 600 "$AUTH_KEYS_FILE"
                return 0
            fi
        done < "$AUTH_KEYS_FILE"
    fi

    cat "$public_key" >> "$AUTH_KEYS_FILE"
    chmod 600 "$AUTH_KEYS_FILE"
    msg_ok "公钥已添加到 authorized_keys"
}

####################################
# 获取服务器 IP
# 修复：优先使用本地路由表，避免依赖外部服务
####################################
get_server_ip() {
    local ip

    # 优先本地路由表（无需网络请求）
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')

    # 降级到 hostname -I
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    # 最后才尝试外部服务
    if [[ -z "$ip" ]]; then
        ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || \
             curl -s --max-time 3 icanhazip.com 2>/dev/null || true)
    fi

    echo "${ip:-unknown}"
}

####################################
# 获取 SSH 端口
####################################
get_ssh_port() {
    local port
    port=$(grep -E "^Port " "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)
    echo "${port:-22}"
}

####################################
# 密钥登录测试
# 修复：nohup 子 shell 无法调用当前脚本的函数
# 改为在子 shell 中直接内联所有需要执行的命令，
# 不依赖任何外部函数定义
####################################
test_key_login() {
    local backup="$1"
    local key_base="$2"
    local server_ip
    server_ip=$(get_server_ip)
    local ssh_port
    ssh_port=$(get_ssh_port)

    # 检测服务名（需在主进程中提前获取，传给子 shell）
    local service
    service=$(detect_ssh_service)

    echo ""
    echo "=========================================="
    msg_warn "密钥登录测试 (${TEST_TIMEOUT}秒超时)"
    echo "=========================================="
    echo ""
    echo "请在新终端执行以下步骤："
    echo ""
    echo "1. 下载密钥:"
    echo "   scp -P ${ssh_port} root@${server_ip}:${key_base}.pem ~/.ssh/"
    echo ""
    echo "2. 设置权限:"
    echo "   chmod 600 ~/.ssh/$(basename "${key_base}").pem"
    echo ""
    echo "3. 测试登录:"
    echo "   ssh -p ${ssh_port} -i ~/.ssh/$(basename "${key_base}").pem root@${server_ip}"
    echo ""
    echo "4. 如果登录成功，返回此窗口输入 'yes'"
    echo ""
    echo "=========================================="
    echo ""

    # 修复核心：
    # 原代码在 nohup 子 shell 里调用 reload_sshd，但子 shell
    # 继承不到当前脚本定义的函数，导致回滚后 sshd 不会重载，
    # 实际上回滚是静默失败的。
    #
    # 修复方案：将回滚所需的全部逻辑直接内联到 nohup 的 bash -c
    # 字符串中，不依赖任何外部函数，确保子 shell 可独立执行。
    local rollback_cmd
    rollback_cmd=$(cat <<EOF
sleep ${TEST_TIMEOUT}
if [[ -f '${backup}' ]]; then
    cp -a '${backup}' '${SSHD_CONFIG}'
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: 超时回滚已执行，配置已恢复" >> '${LOG_FILE}'
    # 验证配置合法性再重载，防止回滚文件本身损坏
    if sshd -t >/dev/null 2>&1; then
        systemctl reload ${service} >/dev/null 2>&1 || systemctl restart ${service} >/dev/null 2>&1 || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: SSH 服务已重载（超时回滚）" >> '${LOG_FILE}'
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: 回滚配置验证失败，请手动检查" >> '${LOG_FILE}'
    fi
fi
EOF
)
    nohup bash -c "$rollback_cmd" >/dev/null 2>&1 &
    local timer_pid=$!

    # 等待用户确认
    local confirm=""
    read -t "$TEST_TIMEOUT" -p "确认密钥登录成功 (输入 yes): " confirm || true

    # 停止超时任务
    # 注意：nohup 会让子进程脱离当前 shell 的进程组，
    # kill timer_pid 只能终止 nohup 的包装进程（bash -c ...），
    # 如果 sleep 已结束但后续命令还未执行，kill 可能无效。
    # 这里加 2>/dev/null 静默处理，不影响主流程。
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
    log_msg "用户选择模式: 1 (混合认证)"

    backup_sshd_config
    # 修复：直接使用全局变量 BACKUP_PATH，
    # 原代码用 local backup=$(backup_sshd_config) 会把函数里
    # 所有 stdout 输出（包括 msg_ok）都捞进变量，路径会带上多余文本
    local backup="$BACKUP_PATH"

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

    # 重载服务
    echo ""
    msg_info "步骤 3/3: 重载 SSH 服务"
    if ! reload_sshd; then
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
    log_msg "用户选择模式: 2 (仅密码认证)"

    backup_sshd_config
    local backup="$BACKUP_PATH"

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

    # 重载服务
    echo ""
    msg_info "步骤 3/3: 重载 SSH 服务"
    if ! reload_sshd; then
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
    log_msg "用户选择模式: 3 (仅密钥认证)"

    backup_sshd_config
    local backup="$BACKUP_PATH"

    # 生成密钥
    echo ""
    msg_info "步骤 1/5: 生成 SSH 密钥"
    # 修复：generate_ssh_key 将路径写入全局变量 GENERATED_KEY_PATH
    # 原代码用命令替换捕获，函数内任何 stdout 输出都会污染路径
    if ! generate_ssh_key; then
        msg_err "密钥生成失败"
        restore_sshd_config "$backup"
        exit 1
    fi

    local key_path="$GENERATED_KEY_PATH"

    if [[ -z "$key_path" || ! -f "$key_path" ]]; then
        msg_err "密钥路径无效: '$key_path'"
        restore_sshd_config "$backup"
        exit 1
    fi

    msg_ok "密钥已生成: $key_path"

    # 导出格式
    echo ""
    msg_info "步骤 2/5: 导出密钥格式"
    export_key_formats "$key_path"

    # 配置 authorized_keys
    echo ""
    msg_info "步骤 3/5: 配置密钥认证"
    setup_authorized_keys "${key_path}.pub"

    # 启用密钥登录（暂时保留密码，用于测试阶段回滚保障）
    echo ""
    msg_info "步骤 4/5: 启用密钥登录（测试阶段暂保留密码）"
    msg_warn "[安全提示] 此阶段密码登录仍开启，仅用于测试保障，测试后将自动关闭"
    log_msg "临时开放 PasswordAuthentication yes（测试阶段）"
    set_sshd_option "PermitRootLogin" "yes"
    set_sshd_option "PubkeyAuthentication" "yes"
    set_sshd_option "PasswordAuthentication" "yes"

    if ! reload_sshd; then
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
    log_msg "PasswordAuthentication 已关闭"

    reload_sshd || true

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
    echo " SSH 认证配置 v${SCRIPT_VERSION}"
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
    echo "   - 120秒测试保护"
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
    log_msg "用户输入选项: $choice"

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