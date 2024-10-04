#!/bin/bash

# 设置字体颜色
YELLOW='\e[33m'
RED='\e[31m'
GREEN='\e[32m' 
RESET='\e[0m'

#输出等待提示
echo -e "${YELLOW}正在进行相关操作，请耐心等待完成...${RESET}"

# 第一步：更新包列表
if sudo apt update > /dev/null 2>&1; then
    echo -e "${YELLOW}包列表更新成功${RESET}"
else
    echo -e "${RED}包列表更新失败，请检测网络状况${RESET}"
fi

# 第二步：安装 sudo, wget, curl, git, cpulimit
if sudo apt install -y sudo wget curl git cpulimit > /dev/null 2>&1; then
    echo -e "${YELLOW}相关组件安装成功${RESET}"
else
    echo -e "${RED}相关组件安装失败，请检测网络状况${RESET}"
fi

# 第三步：修改 /etc/resolv.conf 文件
if sudo bash -c 'echo "nameserver 1.1.1.1" > /etc/resolv.conf && echo "nameserver 8.8.8.8" >> /etc/resolv.conf' > /dev/null 2>&1; then
    echo -e "${YELLOW}DNS服务器修改成功${RESET}"
else
    echo -e "${RED}DNS服务器修改失败，请检测/etc/resolv.conf文件是否存在${RESET}"
fi

# 第四步：禁用系统的 IPv6
# 检查系统是否只有IPv6地址
if ip -6 addr | grep -q "inet6" && ! ip -4 addr | grep -q "inet"; then
    echo -e "${YELLOW}系统仅有IPv6地址，跳过IPv6禁用步骤${RESET}"
else
    if ip -6 addr | grep -q "inet6"; then
        if sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1 && \
           sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1 && \
           sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null 2>&1; then
            echo -e "${YELLOW}临时禁用IPv6成功${RESET}"
        fi
    else
        echo -e "${YELLOW}没有检测到IPv6，执行下一步${RESET}"
    fi
fi

# 第五步：启用 BBR 加速
tcp_congestion_control=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
if [ "$tcp_congestion_control" = "bbr" ]; then
    echo -e "${YELLOW}BBR已开启${RESET}"
else
    echo -e "${YELLOW}正在开启BBR...${RESET}"
    if sudo bash -c 'echo -e "\n# Enable TCP BBR\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf' > /dev/null 2>&1 && sudo sysctl -p > /dev/null 2>&1; then
        echo -e "${YELLOW}BBR加速启用成功${RESET}"
    else
        echo -e "${RED}BBR加速已启动，跳过${RESET}"
    fi
fi

# 第六步：添加 1GB SWAP 空间
if sudo fallocate -l 1G /swapfile > /dev/null 2>&1 && sudo chmod 600 /swapfile > /dev/null 2>&1 && sudo mkswap /swapfile > /dev/null 2>&1 && sudo swapon /swapfile > /dev/null 2>&1; then
    sudo bash -c 'echo "/swapfile none swap sw 0 0" >> /etc/fstab' > /dev/null 2>&1
    echo -e "${YELLOW}1GB SWAP空间添加成功${RESET}"
else
    echo -e "${YELLOW}SWAP空间添加失败，可能已存在swapfile${RESET}"
fi

# 第七步：阻止系统杀进程
if sudo bash -c 'echo 1 > /proc/sys/vm/overcommit_memory' > /dev/null 2>&1; then
    echo -e "${YELLOW}内存过量管理配置成功${RESET}"
else
    echo -e "${YELLOW}内存过量管理已经配置，跳过${RESET}"
fi

# 第八步：优化系统配置
echo -e "${YELLOW}正在优化系统网络配置...${RESET}"
sudo bash -c 'cat << EOF >> /etc/sysctl.conf
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.eth0.autoconf = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
EOF' > /dev/null 2>&1

if sudo sysctl -p > /dev/null 2>&1; then
    echo -e "${YELLOW}优化系统网络配置成功${RESET}"
else
    echo -e "${YELLOW}已进行相关操作，跳过${RESET}"
fi

# 输出最终完成信息
echo -e "${GREEN}所有步骤已完成，请您继续后续操作${RESET}"
