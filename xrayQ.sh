#!/usr/bin/env bash

DEFAULT_START_PORT=20000
DEFAULT_SOCKS_USERNAME="userb"
DEFAULT_SOCKS_PASSWORD="passwordb"
DEFAULT_WS_PATH="/ws"
DEFAULT_UUID="$(cat /proc/sys/kernel/random/uuid)"
DEFAULT_SS_PASSWORD="$(cat /proc/sys/kernel/random/uuid)"
DEFAULT_SS_METHOD="aes-256-gcm"

IP_ADDRESSES=($(hostname -I))

install_xray() {
	echo "安装 Xray..."
	apt-get install unzip -y || yum install unzip -y
	wget -q https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip
	unzip -o Xray-linux-64.zip
	mv xray /usr/local/bin/xrayL
	chmod +x /usr/local/bin/xrayL
	cat <<EOF >/etc/systemd/system/xrayL.service
[Unit]
Description=XrayL Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xrayL -c /etc/xrayL/config.toml
Restart=on-failure
User=nobody
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable xrayL.service
	systemctl start xrayL.service
	echo "Xray 安装完成。"
}

config_xray() {
	local config_type="$1"
	local config_content=""

	mkdir -p /etc/xrayL

	if [ "$config_type" != "socks" ] && [ "$config_type" != "vmess" ] && [ "$config_type" != "ss" ]; then
		echo "类型错误！仅支持 socks、vmess 和 ss。"
		exit 1
	fi

	read -r -p "起始端口 (默认 $DEFAULT_START_PORT): " START_PORT
	START_PORT=${START_PORT:-$DEFAULT_START_PORT}

	if [ "$config_type" == "socks" ]; then
		read -r -p "SOCKS 账号 (默认 $DEFAULT_SOCKS_USERNAME): " SOCKS_USERNAME
		SOCKS_USERNAME=${SOCKS_USERNAME:-$DEFAULT_SOCKS_USERNAME}

		read -r -p "SOCKS 密码 (默认 $DEFAULT_SOCKS_PASSWORD): " SOCKS_PASSWORD
		SOCKS_PASSWORD=${SOCKS_PASSWORD:-$DEFAULT_SOCKS_PASSWORD}
	elif [ "$config_type" == "vmess" ]; then
		read -r -p "UUID (默认随机): " UUID
		UUID=${UUID:-$DEFAULT_UUID}

		read -r -p "WebSocket 路径 (默认 $DEFAULT_WS_PATH): " WS_PATH
		WS_PATH=${WS_PATH:-$DEFAULT_WS_PATH}
	elif [ "$config_type" == "ss" ]; then
		read -r -p "SS 密码 (默认随机): " SS_PASSWORD
		SS_PASSWORD=${SS_PASSWORD:-$DEFAULT_SS_PASSWORD}

		read -r -p "SS 加密方式 (默认 aes256 / aes-256-gcm): " SS_METHOD
		SS_METHOD=${SS_METHOD:-$DEFAULT_SS_METHOD}
		case "$SS_METHOD" in
			aes256|aes-256)
				SS_METHOD="aes-256-gcm"
				;;
			aes128|aes-128)
				SS_METHOD="aes-128-gcm"
				;;
			chacha20)
				SS_METHOD="chacha20-poly1305"
				;;
		esac
	fi

	for ((i = 0; i < ${#IP_ADDRESSES[@]}; i++)); do
		local port=$((START_PORT + i))
		local tag="tag_$((i + 1))"

		config_content+="[[inbounds]]\n"
		config_content+="port = $port\n"
		case "$config_type" in
			socks)
				config_content+="protocol = \"socks\"\n"
				config_content+="tag = \"$tag\"\n"
				config_content+="[inbounds.settings]\n"
				config_content+="auth = \"password\"\n"
				config_content+="udp = true\n"
				config_content+="ip = \"${IP_ADDRESSES[i]}\"\n"
				config_content+="[[inbounds.settings.accounts]]\n"
				config_content+="user = \"$SOCKS_USERNAME\"\n"
				config_content+="pass = \"$SOCKS_PASSWORD\"\n"
				;;
			vmess)
				config_content+="protocol = \"vmess\"\n"
				config_content+="tag = \"$tag\"\n"
				config_content+="[inbounds.settings]\n"
				config_content+="[[inbounds.settings.clients]]\n"
				config_content+="id = \"$UUID\"\n"
				config_content+="[inbounds.streamSettings]\n"
				config_content+="network = \"ws\"\n"
				config_content+="[inbounds.streamSettings.wsSettings]\n"
				config_content+="path = \"$WS_PATH\"\n"
				;;
			ss)
				config_content+="protocol = \"shadowsocks\"\n"
				config_content+="tag = \"$tag\"\n"
				config_content+="[inbounds.settings]\n"
				config_content+="method = \"$SS_METHOD\"\n"
				config_content+="password = \"$SS_PASSWORD\"\n"
				config_content+="network = \"tcp,udp\"\n"
				;;
		esac

		config_content+="\n"
		config_content+="[[outbounds]]\n"
		config_content+="sendThrough = \"${IP_ADDRESSES[i]}\"\n"
		config_content+="protocol = \"freedom\"\n"
		config_content+="tag = \"$tag\"\n\n"
		config_content+="[[routing.rules]]\n"
		config_content+="type = \"field\"\n"
		config_content+="inboundTag = \"$tag\"\n"
		config_content+="outboundTag = \"$tag\"\n\n"
	done

	printf '%b' "$config_content" >/etc/xrayL/config.toml
	systemctl restart xrayL.service
	systemctl --no-pager status xrayL.service

	echo ""
	echo "生成 $config_type 配置完成"
	echo "起始端口:$START_PORT"
	echo "结束端口:$((START_PORT + ${#IP_ADDRESSES[@]} - 1))"

	if [ "$config_type" == "socks" ]; then
		echo "socks账号:$SOCKS_USERNAME"
		echo "socks密码:$SOCKS_PASSWORD"
	elif [ "$config_type" == "vmess" ]; then
		echo "UUID:$UUID"
		echo "ws路径:$WS_PATH"
	elif [ "$config_type" == "ss" ]; then
		echo "ss 密码:$SS_PASSWORD"
		echo "ss 加密方式:$SS_METHOD"
		echo "说明: Xray 会把 aes256 归一为 aes-256-gcm。"
	fi

	echo ""
}

main() {
	[ -x "$(command -v xrayL)" ] || install_xray

	if [ $# -eq 1 ]; then
		config_type="$1"
	else
		read -r -p "选择生成的节点类型 (socks/vmess/ss): " config_type
	fi

	if [ "$config_type" == "vmess" ]; then
		config_xray "vmess"
	elif [ "$config_type" == "socks" ]; then
		config_xray "socks"
	elif [ "$config_type" == "ss" ]; then
		config_xray "ss"
	else
		echo "未正确选择类型，使用默认 socks 配置。"
		config_xray "socks"
	fi
}

main "$@"
