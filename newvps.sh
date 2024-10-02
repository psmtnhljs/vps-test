#!/bin/bash

# 设置黄色字体颜色
YELLOW='\e[33m'
RESET='\e[0m'

# 第一步：更新包列表
if sudo apt update > /dev/null 2>&1; then
    echo -e "${YELLOW}包列表更新成功${RESET}"
else
    echo -e "${YELLOW}包列表更新失败${RESET}"
    exit 1
fi

# 第二步：安装 sudo, wget, curl, git, cpulimit
if sudo apt install -y sudo wget curl git cpulimit > /dev/null 2>&1; then
    echo -e "${YELLOW}相关组件安装成功${RESET}"
else
    echo -e "${YELLOW}相关组件安装失败${RESET}"
    exit 1
fi

# 第三步：修改 /etc/resolv.conf 文件
if sudo bash -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf && echo "nameserver 8.8.8.8" >> /etc/resolv.conf' > /dev/null 2>&1; then
    echo -e "${YELLOW}DNS服务器修改成功${RESET}"
else
    echo -e "${YELLOW}DNS服务器修改失败${RESET}"
    exit 1
fi

# 第四步：禁用系统的 IPv6
if sudo bash -c 'echo -e "\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf' > /dev/null 2>&1 && sudo sysctl -p > /dev/null 2>&1; then
    echo -e "${YELLOW}IPv6禁用成功${RESET}"
else
    echo -e "${YELLOW}IPv6禁用失败${RESET}"
    exit 1
fi

# 第五步：启用 BBR 加速
if sudo bash -c 'echo -e "\n# Enable TCP BBR\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf' > /dev/null 2>&1 && sudo sysctl -p > /dev/null 2>&1; then
    echo -e "${YELLOW}BBR加速启用成功${RESET}"
else
    echo -e "${YELLOW}BBR加速启用失败${RESET}"
    exit 1
fi

# 验证是否成功启用 BBR
tcp_congestion_control=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
if [ "$tcp_congestion_control" = "bbr" ]; then
    echo -e "${YELLOW}BBR成功启动${RESET}"
else
    echo -e "${YELLOW}BBR启动失败，请尝试使用其他脚本${RESET}"
    exit 1
fi

# 第六步：添加 1GB SWAP 空间
if sudo fallocate -l 1G /swapfile > /dev/null 2>&1 && sudo chmod 600 /swapfile > /dev/null 2>&1 && sudo mkswap /swapfile > /dev/null 2>&1 && sudo swapon /swapfile > /dev/null 2>&1; then
    sudo bash -c 'echo "/swapfile none swap sw 0 0" >> /etc/fstab' > /dev/null 2>&1
    echo -e "${YELLOW}1GB SWAP空间添加成功${RESET}"
else
    echo -e "${YELLOW}SWAP空间添加失败${RESET}"
    exit 1
fi

# 第七步：阻止系统杀进程
if sudo bash -c 'echo 1 > /proc/sys/vm/overcommit_memory' > /dev/null 2>&1; then
    echo -e "${YELLOW}内存过量管理配置成功${RESET}"
else
    echo -e "${YELLOW}内存过量管理配置失败${RESET}"
    exit 1
fi

# 输出最终完成信息
echo -e "${YELLOW}所有配置已完成，请继续后续操作${RESET}"
