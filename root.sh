#!/bin/bash
set -Eeuo pipefail

####################################
# 基础环境修复
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 输出工具
green(){ echo -e "\033[32m\033[01m[OK]\033[0m $1"; }
yellow(){ echo -e "\033[33m\033[01m[WARN]\033[0m $1"; }
red(){ echo -e "\033[31m\033[01m[ERR]\033[0m $1"; }

# root / sudo 处理
[[ $EUID -ne 0 ]] && SUDO=sudo || SUDO=""

# 命令检测安装
need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        yellow "缺少命令 $1，正在尝试安装依赖..."
        $SUDO apt update -y
        $SUDO apt install -y passwd openssh-server
    }
}
need_cmd chpasswd
need_cmd sshd || need_cmd ssh

# SSH 配置文件定位（兼容）

SSHD_CONFIG="/etc/ssh/sshd_config"
[[ ! -f $SSHD_CONFIG ]] && { red "未找到 sshd_config"; exit 1; }

# 备份 SSH 配置（万一出事。。。）
BACKUP="${SSHD_CONFIG}.bak.$(date +%F_%H-%M-%S)"
$SUDO cp -a "$SSHD_CONFIG" "$BACKUP"
green "SSH 配置已备份：$BACKUP"

# 读取 root 密码
while true; do
    read -s -p "请输入新的 root 密码: " mima
    echo
    read -s -p "请再次确认 root 密码: " mima2
    echo

    [[ -z $mima ]] && red "密码不能为空" && continue
    [[ ${#mima} -lt 8 ]] && red "密码长度至少 8 位" && continue
    [[ "$mima" != "$mima2" ]] && red "两次输入不一致" && continue
    break
done

# 设置 root 密码
echo "root:$mima" | $SUDO chpasswd
green "root 密码设置成功"

# SSH 配置函数（幂等）
set_ssh_conf() {
    local key=$1 value=$2
    if grep -qE "^[#[:space:]]*$key\b" "$SSHD_CONFIG"; then
        $SUDO sed -i "s|^[#[:space:]]*$key.*|$key $value|" "$SSHD_CONFIG"
    else
        echo "$key $value" | $SUDO tee -a "$SSHD_CONFIG" >/dev/null
    fi
}

# SSH 安全配置（先开后测）
set_ssh_conf PermitRootLogin yes
set_ssh_conf PasswordAuthentication yes
set_ssh_conf PubkeyAuthentication yes
set_ssh_conf UsePAM yes

# 配置校验（防止 sshd 起不来）
if ! $SUDO sshd -t; then
    red "sshd 配置校验失败，正在回滚！"
    $SUDO cp -a "$BACKUP" "$SSHD_CONFIG"
    exit 1
fi

# 重启 SSH 服务（自适应）
if systemctl list-unit-files | grep -q '^sshd'; then
    $SUDO systemctl restart sshd
elif systemctl list-unit-files | grep -q '^ssh'; then
    $SUDO systemctl restart ssh
else
    red "无法识别 SSH 服务名"
    exit 1
fi

# 提示
green "root 密码登录已启用"
green "SSH 服务已重启并通过校验"
green "请确认 22 端口未被防火墙阻断"
green "强烈建议下一步：配置密钥 + 禁用密码登录"
