#!/bin/bash
set -e

green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
red(){ echo -e "\033[31m\033[01m$1\033[0m"; }

[[ $EUID -ne 0 ]] && SUDO=sudo || SUDO=""

# 解除属性（忽略失败）
$SUDO chattr -i -a /etc/passwd /etc/shadow 2>/dev/null || true

# 检查 SSH 配置文件
SSHD_CONFIG="/etc/ssh/sshd_config"
[[ ! -f $SSHD_CONFIG ]] && red "未找到 sshd_config" && exit 1

# 读取密码（隐藏）
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
echo "root:$mima" | $SUDO chpasswd || { red "设置密码失败"; exit 1; }

# SSH 配置（不存在则追加，存在则替换）
set_ssh_conf() {
    local key=$1 value=$2
    if grep -qE "^#?\s*$key" "$SSHD_CONFIG"; then
        $SUDO sed -i "s|^#\?\s*$key.*|$key $value|" "$SSHD_CONFIG"
    else
        echo "$key $value" | $SUDO tee -a "$SSHD_CONFIG" >/dev/null
    fi
}

set_ssh_conf PermitRootLogin yes
set_ssh_conf PasswordAuthentication yes

# 重启 SSH 服务
if systemctl list-unit-files | grep -q '^sshd'; then
    $SUDO systemctl restart sshd
elif systemctl list-unit-files | grep -q '^ssh'; then
    $SUDO systemctl restart ssh
else
    red "无法识别 SSH 服务名，请手动重启"
    exit 1
fi

green "root 密码已设置"
green "已开启 SSH root 登录与密码认证"
green "请确保 22 端口未被防火墙阻断"
