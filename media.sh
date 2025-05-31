#!/bin/bash

# 提取的主要检测函数
# 保持原有的输出格式和颜色显示

# 颜色设置
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_SkyBlue="\033[36m"
Font_White="\033[37m"
Font_Suffix="\033[0m"

# 用户代理设置
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
UA_SEC_CH_UA='"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"'

# Curl 默认选项（需要根据实际情况设置）
CURL_DEFAULT_OPTS="--max-time 10 --retry 3 --retry-max-time 20"

# === 1. Dazn 地区检测 ===
function MediaUnlockTest_Dazn() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi

    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://startup.core.indazn.com/misl/v5/Startup' -X POST -H "Content-Type: application/json" -d '{"LandingPageKey":"generic","languages":"en-US,en","Platform":"web","PlatformAttributes":{},"Manufacturer":"","PromoCode":"","Version":"2"}' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo "$tmpresult" | grep -woP '"isAllowed"\s{0,}:\s{0,}\K(false|true)')
    local region=$(echo "$tmpresult" | grep -woP '"GeolocatedCountry"\s{0,}:\s{0,}"\K[^"]+' | tr a-z A-Z)
    case "$result" in
        'false') echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}No${Font_Suffix}\n" ;;
        'true') echo -n -e "\r Dazn:\t\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n" ;;
        *) echo -n -e "\r Dazn:\t\t\t\t\t${Font_Red}Failed (Error: ${result})${Font_Suffix}\n" ;;
    esac
}

# === 2. Disney+ 流媒体解锁检测 ===
function MediaUnlockTest_DisneyPlus() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi

    local tempresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://disney.api.edge.bamgrid.com/devices' -X POST -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' --user-agent "${UA_BROWSER}")
    if [ -z "$tempresult" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local is403=$(echo "$tempresult" | grep -i '403 ERROR')
    if [ -n "$is403" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No (IP Banned By Disney+)${Font_Suffix}\n"
        return
    fi

    local assertion=$(echo "$tempresult" | grep -woP '"assertion"\s{0,}:\s{0,}"\K[^"]+')
    if [ -z "$assertion" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi

    # 这里需要MEDIA_COOKIE变量，包含预设的cookie模板
    local preDisneyCookie="assertion=${assertion}&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&latitude=0&longitude=0&platform=browser&subject_token=${assertion}&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice"
    local tokenContent=$(curl ${CURL_DEFAULT_OPTS} -s 'https://disney.api.edge.bamgrid.com/token' -X POST -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "${preDisneyCookie}" --user-agent "${UA_BROWSER}")

    local isBlocked=$(echo "$tokenContent" | grep -i 'forbidden-location')
    local is403=$(echo "$tokenContent" | grep -i '403 ERROR')

    if [ -n "$isBlocked" ] || [ -n "$is403" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No (IP Banned By Disney+ 1)${Font_Suffix}\n"
        return
    fi

    local refreshToken=$(echo "$tokenContent" | grep -woP '"refresh_token"\s{0,}:\s{0,}"\K[^"]+')
    local disneyContent="{\"query\":\"mutation refreshToken(\$input: RefreshTokenInput!) { refreshToken(refreshToken: \$input) { activeSession { sessionId } } }\",\"variables\":{\"input\":{\"refreshToken\":\"${refreshToken}\"}}}"
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://disney.api.edge.bamgrid.com/graph/v1/device/graphql' -X POST -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "${disneyContent}" --user-agent "${UA_BROWSER}")

    local previewcheck=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://disneyplus.com' -w '%{url_effective}\n' -o /dev/null --user-agent "${UA_BROWSER}")
    local isUnavailable=$(echo "$previewcheck" | grep -E 'preview|unavailable')
    local region=$(echo "$tmpresult" | grep -woP '"countryCode"\s{0,}:\s{0,}"\K[^"]+')
    local inSupportedLocation=$(echo "$tmpresult" | grep -woP '"inSupportedLocation"\s{0,}:\s{0,}\K(false|true)')

    if [ -z "$region" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ "$region" == 'JP' ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: JP)${Font_Suffix}\n"
        return
    fi
    if [ -n "$isUnavailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ "$inSupportedLocation" == 'false' ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Yellow}Available For [Disney+ ${region}] Soon${Font_Suffix}\n"
        return
    fi
    if [ "$inSupportedLocation" == 'true' ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Error: ${inSupportedLocation}_${region})${Font_Suffix}\n"
}

# === 3. Netflix 流媒体解锁检测 ===
function MediaUnlockTest_Netflix() {
    # LEGO Ninjago
    local tmpresult1=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/81280792' -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' --user-agent "${UA_BROWSER}")
    # Breaking bad
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/70143836' -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' --user-agent "${UA_BROWSER}")

    if [ -z "${tmpresult1}" ] || [ -z "${tmpresult2}" ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result1=$(echo ${tmpresult1} | grep 'Oh no!')
    local result2=$(echo ${tmpresult2} | grep 'Oh no!')

    if [ -n "${result1}" ] && [ -n "${result2}" ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Yellow}Originals Only${Font_Suffix}\n"
        return
    fi
    
    if [ -z "${result1}" ] || [ -z "${result2}" ]; then
        local region=$(echo "$tmpresult1" | grep -o 'data-country="[A-Z]*"' | sed 's/.*="\([A-Z]*\)"/\1/' | head -n1)
        echo -n -e "\r Netflix:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Netflix:\t\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
}

# === 4. YouTube Premium 检测 ===
function MediaUnlockTest_YouTube_Premium() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.youtube.com/premium' -H 'accept-language: en-US,en;q=0.9' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isCN=$(echo "$tmpresult" | grep 'www.google.cn')

    if [ -n "$isCN" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} ${Font_Green} (Region: CN)${Font_Suffix} \n"
        return
    fi

    local isNotAvailable=$(echo "$tmpresult" | grep -i 'Premium is not available in your country')
    local region=$(echo "$tmpresult" | grep -woP '"INNERTUBE_CONTEXT_GL"\s{0,}:\s{0,}"\K[^"]+')
    local isAvailable=$(echo "$tmpresult" | grep -i 'ad-free')

    if [ -n "$isNotAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ -z "$region" ]; then
        local region='UNKNOWN'
    fi
    if [ -n "$isAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
}

# === 5. Amazon Prime Video 检测 ===
function MediaUnlockTest_PrimeVideo() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi

    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.primevideo.com' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isBlocked=$(echo "$tmpresult" | grep -i 'isServiceRestricted')
    local region=$(echo "$tmpresult" | grep -woP '"currentTerritory":"\K[^"]+' | head -n 1)

    if [ -z "$isBlocked" ] && [ -z "$region" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi
    if [ -n "$isBlocked" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}No (Service Not Available)${Font_Suffix}\n"
        return
    fi
    if [ -n "$region" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Error: Unknown Region)${Font_Suffix}\n"
}

# === 6. TVBAnywhere+ 检测 ===
function MediaUnlockTest_TVBAnywhere() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi

    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://uapisfm.tvbanywhere.com.sg/geoip/check/platform/android' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo "$tmpresult" | grep -woP '"allow_in_this_country"\s{0,}:\s{0,}\K(false|true)')
    if [ -z "$result" ]; then
        echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi

    case "$result" in
        'true') echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n" ;;
        'false') echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}No${Font_Suffix}\n" ;;
        *) echo -n -e "\r TVBAnywhere+:\t\t\t\t${Font_Red}Failed (Error: Unknown)${Font_Suffix}\n" ;;
    esac
}

# === 7. Spotify Registration 检测 ===
function MediaUnlockTest_Spotify() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://spclient.wg.spotify.com/signup/public/v1/account' -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=TestUser&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -X POST -H "Accept-Language: en" --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local statusCode=$(echo "$tmpresult" | grep -woP '"status"\s{0,}:\s{0,}\K\d+')
    local region=$(echo "$tmpresult" | grep -woP '"country"\s{0,}:\s{0,}"\K[^"]+')
    local isLaunched=$(echo "$tmpresult" | grep -woP '"is_country_launched"\s{0,}:\s{0,}\K(false|true)')

    if [ -z "$statusCode" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi
    if [ "$statusCode" == '320' ] || [ "$statusCode" == '120' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ -z "$isLaunched" ] || [ -z "$region" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi
    if [ "$isLaunched" == 'false' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ "$statusCode" == '311' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Error: $statusCode)${Font_Suffix}\n"
}

# === 8. OneTrust Region 检测 ===
function RegionTest_oneTrust() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://geolocation.onetrust.com/cookieconsentpub/v1/geo/location' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r OneTrust Region:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local region=$(echo "$tmpresult" | grep -woP '"country"\s{0,}:\s{0,}"\K[^"]+')
    local stateName=$(echo "$tmpresult" | grep -woP '"stateName"\s{0,}:\s{0,}"\K[^"]+')
    if [ -z "$region" ]; then
        echo -n -e "\r OneTrust Region:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi
    if [ -z "$stateName" ]; then
        local stateName='Unknown'
    fi

    echo -n -e "\r OneTrust Region:\t\t\t${Font_Green}${region} [${stateName}]${Font_Suffix}\n"
}

# === 9. iQyi Oversea Region 检测 ===
function RegionTest_iQYI() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi

    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.iq.com/' -w "_TAG_%{http_code}_TAG_" -o /dev/null --user-agent "${UA_BROWSER}" -D -)

    local httpCode=$(echo "$tmpresult" | grep '_TAG_' | awk -F'_TAG_' '{print $2}')
    if [ "$httpCode" == '000' ]; then
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local region=$(echo "$tmpresult" | grep -woP 'mod=\K[a-z]+' | tr a-z A-Z)
    if [ -z "$region" ]; then
        echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Red}Failed (Error: Country Code Not Found)${Font_Suffix}\n"
        return
    fi

    if [ "$region" == 'NTW' ]; then
        region='TW'
    fi

    echo -n -e "\r iQyi Oversea Region:\t\t\t${Font_Green}${region}${Font_Suffix}\n"
}

# === 10. Bing Region 检测 ===
function RegionTest_Bing() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://www.bing.com/search?q=curl' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Bing Region:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isCN=$(echo "$tmpresult" | grep 'cn.bing.com')
    local region=$(echo "$tmpresult" | grep -woP 'Region\s{0,}:\s{0,}"\K[^"]+')

    if [ -n "$isCN" ]; then
        local region='CN'
        echo -n -e "\r Bing Region:\t\t\t\t${Font_Yellow}${region}${Font_Suffix}\n"
        return
    fi

    local isRisky=$(echo "$tmpresult" | grep 'sj_cook.set("SRCHHPGUSR","HV"')

    if [ -n "$isRisky" ]; then
        echo -n -e "\r Bing Region:\t\t\t\t${Font_Yellow}${region} (Risky)${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Bing Region:\t\t\t\t${Font_Green}${region}${Font_Suffix}\n"
}

# === 11. Apple Region 检测 ===
function RegionTest_Apple() {
    local result=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://gspe1-ssl.ls.apple.com/pep/gcc')
    if [ -z "$result" ]; then
        echo -n -e "\r Apple Region:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Apple Region:\t\t\t\t${Font_Green}${result}${Font_Suffix}\n"
        return
    fi
}

# === 12. YouTube CDN 检测 ===
function RegionTest_YouTubeCDN() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://redirector.googlevideo.com/report_mapping' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local iata=$(echo "$tmpresult" | grep '=>' | awk "NR==1" | awk '{print $3}' | cut -f2 -d'-' | cut -c 1-3 | tr a-z A-Z)
    local isIDC=$(echo "$tmpresult" | grep 'router')
    
    # 这里需要IATACODE数据库文件，简化处理
    local location="Unknown"
    if [ -n "$iata" ]; then
        location="Location for ${iata}"
    fi

    if [ -z "$iata" ]; then
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Failed (Error: Location Unknown)${Font_Suffix}\n"
        return
    fi

    if [ -z "$isIDC" ]; then
        local cdnISP=$(echo "$tmpresult" | awk 'NR==1' | awk '{print $3}' | cut -f1 -d'-' | tr a-z A-Z)
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}[${cdnISP}] in [${location}]${Font_Suffix}\n"
        return
    fi
    if [ -n "$isIDC" ]; then
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}${location}${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Failed (Error: Unknown)${Font_Suffix}\n"
}

# === 13. Netflix Preferred CDN 检测 ===
function RegionTest_NetflixCDN() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1' -w '_TAG_%{http_code}' --user-agent "${UA_BROWSER}")
    local httpCode=$(echo "$tmpresult" | grep '_TAG_' | awk -F'_TAG_' '{print $2}')
    local respContent=$(echo "$tmpresult" | awk -F'_TAG_' '{print $1}')
    
    if [ "$httpCode" == '000' ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    if [ "$httpCode" == '403' ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed (IP Banned By Netflix)${Font_Suffix}\n"
        return
    fi

    local cdnDomain=$(echo "$respContent" | grep -woP '"url":"\K[^"]+' | awk -F'[/:]' '{print $4}')
    if [ -z "$cdnDomain" ]; then
        echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi

    # 简化处理CDN信息
    local location="Unknown Location"
    local cdnISP="Unknown ISP"
    
    echo -n -e "\r Netflix Preferred CDN:\t\t\t${Font_Green}${location} [${cdnISP}]${Font_Suffix}\n"
}

# === 14. ChatGPT 检测 ===
function WebTest_OpenAI() {
    local tmpresult1=$(curl ${CURL_DEFAULT_OPTS} -s 'https://api.openai.com/compliance/cookie_requirements' -H 'authorization: Bearer null' --user-agent "${UA_BROWSER}")
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -s 'https://ios.chat.openai.com/' --user-agent "${UA_BROWSER}")
    
    if [ -z "$tmpresult1" ] || [ -z "$tmpresult2" ]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result1=$(echo "$tmpresult1" | grep -i 'unsupported_country')
    local result2=$(echo "$tmpresult2" | grep -i 'VPN')
    
    if [ -z "$result2" ] && [ -z "$result1" ]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi
    if [ -n "$result2" ] && [ -n "$result1" ]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ -z "$result1" ] && [ -n "$result2" ]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Yellow}No (Only Available with Web Browser)${Font_Suffix}\n"
        return
    fi
    if [ -n "$result1" ] && [ -z "$result2" ]; then
        echo -n -e "\r ChatGPT:\t\t\t\t${Font_Yellow}No (Only Available with Mobile APP)${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r ChatGPT:\t\t\t\t${Font_Red}Failed (Error: Unknown)${Font_Suffix}\n"
}

# === 15. Google Gemini 检测 ===
function WebTest_Gemini() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL "https://gemini.google.com" --user-agent "${UA_BROWSER}")
    if [[ "$tmpresult" = "curl"* ]]; then
        echo -n -e "\r Google Gemini:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    
    local result=$(echo "$tmpresult" | grep -q '45631641,null,true' && echo "Yes" || echo "")
    local countrycode=$(echo "$tmpresult" | grep -o ',2,1,200,"[A-Z]\{3\}"' | sed 's/,2,1,200,"//;s/"//' || echo "")
    
    if [ -n "$result" ] && [ -n "$countrycode" ]; then
        echo -n -e "\r Google Gemini:\t\t\t\t${Font_Green}Yes (Region: $countrycode)${Font_Suffix}\n"
        return
    elif [ -n "$result" ]; then
        echo -n -e "\r Google Gemini:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Google Gemini:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
}

# === 16. Claude 检测 ===
function WebTest_Claude() {
    local response=$(curl ${CURL_DEFAULT_OPTS} -s -o /dev/null -w "%{http_code}" -A "${UA_BROWSER}" "https://claude.ai/")
    if [ -z "$response" ]; then
        echo -n -e "\r Claude:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi
    if [ "$response" -eq 200 ]; then
        echo -n -e "\r Claude:\t\t\t\t${Font_Green}Yes${Font_Suffix}\n"
    else
        echo -n -e "\r Claude:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    fi
}

# === 17. Wikipedia Editability 检测 ===
function WebTest_Wikipedia_Editable() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://zh.wikipedia.org/w/index.php?title=Wikipedia%3A%E6%B2%99%E7%9B%92&action=edit' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Wikipedia Editability:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo "$tmpresult" | grep -i 'Banned')
    if [ -z "$result" ]; then
        echo -n -e "\r Wikipedia Editability:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Wikipedia Editability:\t\t\t${Font_Red}No${Font_Suffix}\n"
}

# === 18. Google Play Store 检测 ===
function WebTest_GooglePlayStore() {
    local result=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://play.google.com/' -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'accept-language: en-US;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: document' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-site: none' -H 'sec-fetch-user: ?1' -H 'upgrade-insecure-requests: 1' --user-agent "${UA_BROWSER}" | grep -oP '<div class="yVZQTb">\K[^<(]+')
    
    if [ -z "$result" ]; then
        echo -n -e "\r Google Play Store:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        return
    else
        echo -n -e "\r Google Play Store:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
        return
    fi
}

# === 19. Google Search CAPTCHA Free 检测 ===
function WebTest_GoogleSearchCAPTCHA() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.google.com/search?q=curl&oq=curl&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBBzg1MmowajGoAgCwAgE&sourceid=chrome&ie=UTF-8' -H 'accept: */*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: document' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-site: none' -H 'sec-fetch-user: ?1' -H 'upgrade-insecure-requests: 1' --user-agent "${UA_BROWSER}")
    
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isBlocked=$(echo "$tmpresult" | grep -iE 'unusual traffic from|is blocked|unaddressed abuse')
    local isOK=$(echo "$tmpresult" | grep -i 'curl')

    if [ -z "$isBlocked" ] && [ -z "$isOK" ]; then
        echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi
    if [ -n "$isBlocked" ]; then
        echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Red}No${Font_Suffix}\n"
        return
    fi
    if [ -n "$isOK" ]; then
        echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Green}Yes${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Google Search CAPTCHA Free:\t\t${Font_Red}Failed (Error: Unknown)${Font_Suffix}\n"
}

# === 20. Steam Currency 检测 ===
function GameTest_Steam() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        return
    fi

    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://store.steampowered.com/app/761830' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local result=$(echo "$tmpresult" | grep 'priceCurrency' | cut -d '"' -f4)
    if [ -z "$result" ]; then
        echo -n -e "\r Steam Currency:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        return
    fi

    echo -n -e "\r Steam Currency:\t\t\t${Font_Green}${result}${Font_Suffix}\n"
}

# === 主要检测函数集合 ===
function run_all_tests() {
    echo "============[ Multination Region Tests ]============"
    
    # 运行所有检测
    MediaUnlockTest_Dazn &
    MediaUnlockTest_DisneyPlus &
    MediaUnlockTest_Netflix &
    MediaUnlockTest_YouTube_Premium &
    MediaUnlockTest_PrimeVideo &
    MediaUnlockTest_TVBAnywhere &
    MediaUnlockTest_Spotify &
    RegionTest_oneTrust &
    RegionTest_iQYI &
    wait
    
    # 第二批检测
    RegionTest_Bing &
    RegionTest_Apple &
    RegionTest_YouTubeCDN &
    RegionTest_NetflixCDN &
    WebTest_OpenAI &
    WebTest_Gemini &
    WebTest_Claude &
    WebTest_Wikipedia_Editable &
    WebTest_GooglePlayStore &
    WebTest_GoogleSearchCAPTCHA &
    GameTest_Steam &
    wait
    
    echo "======================================="
}

# === 辅助函数 ===
# 检查命令是否存在
function command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# 生成UUID（简化版）
function gen_uuid() {
    if [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
        return 0
    fi
    if command_exists uuidgen; then
        uuidgen
        return 0
    fi
    # 简单的随机字符串作为备选
    head /dev/urandom | tr -dc A-Za-z0-9 | head -c 36
}

# 主执行函数
function main() {
    echo "Stream Platform & Game Region Restriction Test"
    echo "=============================================="
    echo "Testing started at: $(date)"
    echo ""
    
    # 设置变量
    USE_IPV6=0  # 根据需要设置
    
    # 运行所有检测
    run_all_tests
    
    echo ""
    echo "Testing completed at: $(date)"
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
