#!/bin/bash

# 设置黄色字体颜色
YELLOW='\e[33m'
RESET='\e[0m'

# 第一步：更新包列表
echo -e "${YELLOW}Updating package list...${RESET}"
sudo apt update

# 第二步：安装 sudo, wget, curl, git, cpulimit
echo -e "${YELLOW}安装相关组件...${RESET}"
sudo apt install -y sudo wget curl git cpulimit

# 提示用户安装完成
echo -e "${YELLOW}已完成${RESET}"

# 第三步：修改 /etc/resolv.conf 文件
echo -e "${YELLOW}修改DNS服务器...${RESET}"
echo "nameserver 1.1.1.1" > /etc/resolv.conf && echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# 第四步：禁用系统的 IPv6
echo -e "${YELLOW}IPV6已关闭(临时)${RESET}"
# 在 sysctl.conf 中添加禁用 IPv6 的配置
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 && sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# 第五步：启用 BBR 加速
echo -e "${YELLOW}正在启动BBR加速...${RESET}"
sudo bash -c 'echo -e "\n# Enable TCP BBR\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf'
sudo sysctl -p

# 验证是否成功启用 BBR
tcp_congestion_control=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
if [ "$tcp_congestion_control" = "bbr" ]; then
    echo -e "${YELLOW}BBR成功启动${RESET}"
else
    echo -e "${YELLOW}BBR启动失败,请尝试使用其他脚本${RESET}"
fi
