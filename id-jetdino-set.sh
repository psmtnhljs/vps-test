#! /bin/bash
fallocate -l 1G swapfile && chmod 600 swapfile && mkswap swapfile && swapon swapfile && swapon --show && echo '/root/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
read -p"虚拟内存成功添加"
echo 1 > /proc/sys/vm/overcommit_memory
read -p "完成"
