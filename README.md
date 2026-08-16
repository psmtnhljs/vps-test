# vps-test

面向 Linux VPS 的实用运维脚本集合，包含 SSH、Fail2Ban、DDNS、IP 检测、媒体解锁检测、Xray 配置、Nginx 端口转发以及云厂商组件清理工具。

## 快速开始

```bash
git clone https://github.com/psmtnhljs/vps-test.git
cd vps-test
chmod +x *.sh
```

大多数脚本需要 root 权限。通过 SSH 修改系统配置前，请保留一个可回退的登录窗口或云控制台。

## 一键运行远程脚本

只有部分不修改系统配置的检测脚本适合直接通过 GitHub Raw 运行，例如 `ip.sh` 和 `tk.sh`：

```bash
# IP 信息查询
bash <(curl -Ls https://raw.githubusercontent.com/psmtnhljs/vps-test/main/ip.sh)

# TikTok 地区检测
bash <(curl -Ls https://raw.githubusercontent.com/psmtnhljs/vps-test/main/tk.sh)
```

大部分脚本会安装软件或修改系统配置，建议先用 `wget` 下载到本地，检查内容后再运行。例如：

```bash
# 下载 Nginx 转发脚本
wget -O nginx-relay.sh https://raw.githubusercontent.com/psmtnhljs/vps-test/main/nginx-relay.sh
less nginx-relay.sh
chmod +x nginx-relay.sh
sudo bash nginx-relay.sh

# 下载其他脚本时使用相同方式
wget -O ddns.sh https://raw.githubusercontent.com/psmtnhljs/vps-test/main/ddns.sh
wget -O root.sh https://raw.githubusercontent.com/psmtnhljs/vps-test/main/root.sh
wget -O fail2ban-sshctl.sh https://raw.githubusercontent.com/psmtnhljs/vps-test/main/fail2ban-sshctl.sh
```

下载到本地后，请根据脚本用途决定是否使用 `sudo`。远程脚本会直接在当前服务器上执行或覆盖同名文件，生产环境使用前务必检查 Raw 文件内容，并确认仓库地址可信。

## 脚本列表

| 文件 | 用途 | 权限 |
| --- | --- | --- |
| `nginx-relay.sh` | 使用 Nginx stream 转发 TCP/UDP 端口，支持静态 IP、域名/DDNS、IPv4/IPv6 和多出口 IP | root |
| `root.sh` | 交互式配置 SSH 登录认证方式 | root |
| `fail2ban-sshctl.sh` | 安装、配置、查看和卸载 SSH 的 Fail2Ban 防护 | root |
| `ddns.sh` | 使用 Cloudflare API 更新动态 DNS 记录 | 普通用户或 root |
| `media.sh` | 检测 Netflix、Disney+、YouTube Premium、Prime Video 等服务 | 普通用户 |
| `tk.sh` | 检测服务器出口 IP 的 TikTok 地区信息 | 普通用户 |
| `xrayQ.sh` | 安装并配置 Xray 的 socks、vmess 或 ss 服务 | root |
| `ip.sh` | 查询指定 IP 或本机公网 IP 信息 | 普通用户 |
| `delete.sh` | 清理常见云厂商代理、监控和安全组件 | root |
| `uninstall-xmr.sh` | 清理 MoneroOcean / XMRig 相关服务和文件 | root |
| `cc.py` | 历史脚本，暂不提供使用说明 | — |

## Nginx 端口转发

运行：

```bash
sudo bash nginx-relay.sh
```

首次运行会检测服务器是 IPv4、IPv6 还是双栈，安装 Nginx 及 stream 模块，并让你选择保留 Web 服务或释放 80/443 端口、仅用于转发。工作模式会被保存，之后再次运行时默认跳过一级模式选择和重复安装。

二级菜单支持：

- 查看当前转发列表
- 创建静态 IPv4/IPv6 转发
- 创建域名或 DDNS 转发
- 删除转发
- 测试 Nginx 配置并重启
- 重新设置 Web 服务模式

创建转发时可以选择 TCP 或 UDP、本地监听端口、目标端口以及本机出站 IP。脚本会根据目标地址族自动匹配 `proxy_bind`：

- 纯 IPv4 服务器不显示 IPv6 出站选项。
- 纯 IPv6 服务器不允许创建 IPv4 服务转发。
- 双栈服务器可分别选择 IPv4 或 IPv6 出站地址。
- 多 IP 服务器会列出当前地址，创建时明确选择实际使用的地址。

每次新增或删除转发后，脚本会先执行 `nginx -t`。配置测试通过后，是否立即重启 Nginx 由用户确认。

脚本生成的文件通常位于：

```text
/etc/nginx/stream.d/nginx-relay.conf
/etc/nginx/stream.d/nginx-relay.db
/etc/nginx/.nginx-relay.state
/etc/nginx/nginx-relay-backups/
```

## 其他脚本用法

```bash
sudo bash root.sh
sudo bash fail2ban-sshctl.sh
bash ddns.sh
bash media.sh
bash tk.sh
sudo bash xrayQ.sh
bash ip.sh
sudo bash delete.sh
sudo bash uninstall-xmr.sh
```

### `ddns.sh`

首次运行按提示配置 Cloudflare API Key、邮箱、Zone、主机名、记录类型和定时任务。也支持旧的命令行参数：

```bash
bash ddns.sh -k <api-key> -u <email> -h <host.example.com> -z <example.com> -t A
bash ddns.sh -k <api-key> -u <email> -h <host.example.com> -z <example.com> -t AAAA
```

其他可用参数包括 `--install-cron`、`--remove-cron` 和 `--show-config`。Cloudflare 凭据请勿提交到 Git 仓库。

### `root.sh`

用于选择 SSH 的认证模式：

1. 密钥 + 密码
2. 仅密码
3. 仅密钥

脚本会修改 SSH 配置。执行前请确认当前 SSH 端口和登录方式，并准备回滚途径。

### `xrayQ.sh`

支持以下配置类型：

```bash
sudo bash xrayQ.sh socks
sudo bash xrayQ.sh vmess
sudo bash xrayQ.sh ss
```

### `tk.sh`

可以指定出口网卡：

```bash
bash tk.sh -I eth0
```

## 安全与风险提示

- 这些脚本会修改系统服务、网络配置或防火墙相关配置，建议先在测试 VPS 验证。
- `root.sh`、`delete.sh`、`uninstall-xmr.sh` 和 `nginx-relay.sh` 可能影响现有服务，请确认目标机器和配置后再执行。
- “仅转发”模式会尝试注释 Nginx 配置中的 80/443 `listen` 指令，并在 `/etc/nginx/nginx-relay-backups/` 保存备份。
- 动态域名转发依赖 Nginx 的变量 `proxy_pass` 和 DNS 解析；请确认目标域名及目标端口可用。
- 不要把 Cloudflare API Key、SSH 私钥或其他凭据写入仓库。

## 许可证

仓库当前未单独声明许可证。如需用于生产环境、二次分发或商业用途，请先与作者确认。
