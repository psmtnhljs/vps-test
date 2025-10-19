#!/bin/bash
shopt -s expand_aliases

# ====== 字体颜色定义 ======
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_SkyBlue="\033[36m"
Font_White="\033[37m"
Font_Suffix="\033[0m"

# ====== 参数处理 ======
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

# ====== 系统检查 ======
checkOS(){
    ifCentOS=$(cat /etc/os-release | grep CentOS)
    if [ -n "$ifCentOS" ]; then
        OS_Version=$(cat /etc/os-release | grep REDHAT_SUPPORT_PRODUCT_VERSION | cut -f2 -d'"')
        if [[ "$OS_Version" -lt "8" ]]; then
            echo -e "${Font_Red}此脚本不支持 CentOS${OS_Version}，请升级至 CentOS8 或更换其他系统${Font_Suffix}"
            echo -e "${Font_Red}3 秒后退出脚本...${Font_Suffix}"
            sleep 3
            exit 1
        fi
    fi
}
checkOS

if [ -z "$iface" ]; then
    useNIC=""
fi

# ====== 临时命令兼容检测 ======
if ! mktemp -u --suffix=RRC &>/dev/null; then
    is_busybox=1
fi

UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"

# ====== 获取 IPv4 & ISP 信息 ======
local_ipv4=$(curl $useNIC -4 -s --max-time 10 https://api64.ipify.org)
local_ipv4_asterisk=$(awk -F"." '{print $1"."$2".*.*"}' <<<"${local_ipv4}")

# 调用 ipinfo.io API 获取详细 ASN 信息
isp_json=$(curl $useNIC -s --max-time 10 "https://ipinfo.io/${local_ipv4}/json")

local_org=$(echo "$isp_json" | grep '"org":' | cut -d'"' -f4)
local_country=$(echo "$isp_json" | grep '"country":' | cut -d'"' -f4)

if [ -z "$local_org" ]; then
    local_org="未知运营商"
fi
if [ -z "$local_country" ]; then
    local_country="未知国家"
fi

local_isp4="${local_org}, ${local_country}"

# ====== Tiktok 区域检测函数 ======
function MediaUnlockTest_Tiktok_Region() {
    echo -n -e " Tiktok Region:\t\t\c"
    local Ftmpresult=$(curl $useNIC --user-agent "${UA_Browser}" -s --max-time 10 "https://www.tiktok.com/")

    if [[ "$Ftmpresult" = "curl"* ]]; then
        echo -n -e "\r Tiktok Region:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local FRegion=$(echo $Ftmpresult | grep '"region":' | sed 's/.*"region"//' | cut -f2 -d'"')
    if [ -n "$FRegion" ]; then
        echo -n -e "\r Tiktok Region:\t\t${Font_Green}【${FRegion}】${Font_Suffix}\n"
        return
    fi

    local STmpresult=$(curl $useNIC --user-agent "${UA_Browser}" -sL --max-time 10 \
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" \
        -H "Accept-Encoding: gzip" -H "Accept-Language: en" "https://www.tiktok.com" | gunzip 2>/dev/null)
    local SRegion=$(echo $STmpresult | grep '"region":' | sed 's/.*"region"//' | cut -f2 -d'"')
    if [ -n "$SRegion" ]; then
        echo -n -e "\r Tiktok Region:\t\t${Font_Yellow}【${SRegion}】(可能为IDC IP)${Font_Suffix}\n"
    else
        echo -n -e "\r Tiktok Region:\t\t${Font_Red}Failed${Font_Suffix}\n"
    fi
}

# ====== 输出标题 ======
function ScriptTitle() {
    echo -e "${Font_SkyBlue}【Tiktok 区域检测】${Font_Suffix}"
    echo ""
    echo -e " ** 测试时间: $(date)"
    echo ""
}

# ====== 输出头部信息 ======
function Heading() {
    echo -e " ${Font_SkyBlue}** 您的网络为: ${local_isp4} (${local_ipv4_asterisk})${Font_Suffix}"
    echo "******************************************"
    echo ""
}

# ====== 结束提示 ======
function Goodbye() {
    echo ""
    echo "******************************************"
    echo -e "${Font_Green}检测完成${Font_Suffix}"
    echo ""
}

# clear
ScriptTitle
Heading
MediaUnlockTest_Tiktok_Region
Goodbye

