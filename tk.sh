#!/bin/bash 
shopt -s expand_aliases 
Font_Black="\033[30m" 
Font_Red="\033[31m" 
Font_Green="\033[32m" 
Font_Yellow="\033[33m" 
Font_Blue="\033[34m" 
Font_Purple="\033[35m" 
Font_SkyBlue="\033[36m" 
Font_White="\033[37m" 
Font_Suffix="\033[0m" 
 
while getopts ":I:" optname; do 
    case "$optname" in 
    "I") 
        iface="$OPTARG" 
        useNIC="--interface $iface" 
        ;; 
    ":") 
        echo "Unknown error while processing options" 
        exit 1 
        ;; 
    esac 
done 
 
checkOS(){ 
    ifCentOS=$(cat /etc/os-release 2>/dev/null | grep CentOS) 
    if [ -n "$ifCentOS" ];then 
        OS_Version=$(cat /etc/os-release | grep REDHAT_SUPPORT_PRODUCT_VERSION | cut -f2 -d'"') 
        if [[ "$OS_Version" -lt "8" ]];then 
            echo -e "${Font_Red}此脚本不支持CentOS${OS_Version},请升级至CentOS8或更换其他操作系统${Font_Suffix}" 
            echo -e "${Font_Red}3秒后退出脚本...${Font_Suffix}" 
            sleep 3 
            exit 1 
        fi 
    fi         
} 
checkOS 
 
if [ -z "$iface" ]; then 
    useNIC="" 
fi 
 
if ! mktemp -u --suffix=RRC &>/dev/null; then 
    is_busybox=1 
fi 
 
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36" 
 
local_ipv4=$(curl $useNIC -4 -s --max-time 10 api64.ipify.org) 
local_ipv4_asterisk=$(awk -F"." '{print $1"."$2".*.*"}' <<<"${local_ipv4}") 

# 修复：获取完整的ISP信息，包括AS号和组织名称
local_isp_info=$(curl $useNIC -s -4 --max-time 10 "https://ipinfo.io/${local_ipv4}/org")
if [ -z "$local_isp_info" ] || [ "$local_isp_info" == "undefined" ]; then
    # 备用方案：使用ip-api.com
    local_isp_info=$(curl $useNIC -s -4 --max-time 10 "http://ip-api.com/json/${local_ipv4}?fields=as,isp" | grep -oP '"as":"\K[^"]+')
    if [ -z "$local_isp_info" ]; then
        local_isp_info="Unknown ISP"
    fi
fi
local_isp4="${local_isp_info}"
 
function MediaUnlockTest_Tiktok_Region() { 
    echo -n -e " Tiktok Region:\t\t\c" 
    local Ftmpresult=$(curl $useNIC --user-agent "${UA_Browser}" -s --max-time 10 "https://www.tiktok.com/") 
 
    if [[ "$Ftmpresult" = "curl"* ]]; then 
        echo -n -e "\r Tiktok Region:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n" 
        return 
    fi 
 
    local FRegion=$(echo $Ftmpresult | grep '"region":' | sed 's/.*"region"//' | cut -f2 -'"') 
    if [ -n "$FRegion" ]; then 
        echo -n -e "\r Tiktok Region:\t\t${Font_Green}【${FRegion}】${Font_Suffix}\n" 
        return 
    fi 
 
    local STmpresult=$(curl $useNIC --user-agent "${UA_Browser}" -sL --max-time 10 -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" -H "Accept-Encoding: gzip" -H "Accept-Language: en" "https://www.tiktok.com" | gunzip 2>/dev/null) 
    local SRegion=$(echo $STmpresult | grep '"region":' | sed 's/.*"region"//' | cut -f2 -d'"') 
    if [ -n "$SRegion" ]; then 
        echo -n -e "\r Tiktok Region:\t\t${Font_Yellow}【${SRegion}】(可能为IDC IP)${Font_Suffix}\n" 
        return 
    else 
        echo -n -e "\r Tiktok Region:\t\t${Font_Red}Failed${Font_Suffix}\n" 
        return 
    fi 
} 
 
function Heading() { 
    echo -e " ${Font_SkyBlue}** 您的网络为: ${local_isp4} (${local_ipv4_asterisk})${Font_Suffix} " 
    echo "******************************************" 
    echo "" 
} 
 
function Goodbye() { 
    echo "" 
    echo "******************************************" 
    echo -e "${Font_Green}检测完成${Font_Suffix}" 
    echo "" 
} 
 
clear 
 
function ScriptTitle() { 
    echo -e "${Font_SkyBlue}【Tiktok区域检测】${Font_Suffix}" 
    echo "" 
    echo -e " ** 测试时间: $(date)" 
    echo "" 
} 
ScriptTitle 
 
function RunScript() { 
    Heading 
    MediaUnlockTest_Tiktok_Region 
    Goodbye 
} 
 
RunScript
