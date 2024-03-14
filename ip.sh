#! /bin/bash
read -p "您要查询的IP为(直接回车显示本机IP)：$ip" 
curl "ipinfo.io/${ip}?token=7c0448e02e558f"
bash ip.sh
