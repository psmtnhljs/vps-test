#!/bin/bash

# 检查是否以 root 权限运行
if [[ $EUID -ne 0 ]]; then
   echo "此脚本需要以 root 权限运行，请使用 sudo"
   exit 1
fi

# 定义伊朗 IP 地址列表的 URL 和本地文件路径
IRAN_IP_URL="https://www.ipdeny.com/ipblocks/data/countries/ir.zone"
IRAN_IP_FILE="/tmp/ir.zone"

# 下载伊朗 IP 地址列表
echo "正在下载伊朗 IP 地址列表..."
if ! wget -q -O "$IRAN_IP_FILE" "$IRAN_IP_URL"; then
    echo "下载失败，请检查网络连接或 URL"
    exit 1
fi

# 检查文件是否下载成功
if [[ ! -s "$IRAN_IP_FILE" ]]; then
    echo "IP 地址列表文件为空或不存在"
    exit 1
fi

# 确保 ufw 已安装
if ! command -v ufw &> /dev/null; then
    echo "ufw 未安装，正在安装..."
    apt-get update && apt-get install -y ufw
fi

# 启用 ufw（如果未启用）
ufw status | grep -q "Status: active" || ufw enable

# 添加阻止规则
echo "正在为伊朗 IP 地址添加 ufw 阻止规则..."
while IFS= read -r ip; do
    if [[ -n "$ip" ]]; then
        ufw deny from "$ip" && echo "已将此伊朗IP添加列表: $ip"
    fi
done < "$IRAN_IP_FILE"

# 重载 ufw 以应用规则
ufw reload
echo "ufw 规则已重载"

# 显示 ufw 状态
echo "当前 ufw 状态："
ufw status

# 清理临时文件
rm -f "$IRAN_IP_FILE"
echo "临时文件已清理，操作完成"
