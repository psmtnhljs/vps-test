# vps-test

一套面向 Linux VPS 的运维脚本合集，主要用于 SSH 安全配置、Fail2Ban 管理、Cloudflare DDNS、媒体解锁/地区检测、Xray 多出口配置，以及常见云厂商监控组件清理。

> 说明：仓库中保留了一些历史脚本和原始上游代码；本文档只整理适合日常运维的部分，并补充最常见的使用方式。

## 仓库内容

| 文件 | 作用 | 说明 |
| --- | --- | --- |
| `root.sh` | SSH 认证配置 | 交互式配置 SSH 登录方式，支持「密钥 + 密码」「仅密码」「仅密钥」三种模式，带配置备份和回滚保护。 |
| `fail2ban-sshctl.sh` | Fail2Ban 管理 | 安装/配置/查看/卸载 SSH 的 Fail2Ban 防护。 |
| `ddns.sh` | Cloudflare DDNS | 将域名解析自动更新到当前公网 IP，适合动态 IP 或小型 VPS。 |
| `media.sh` | 媒体解锁检测 | 检测 Netflix、Disney+、YouTube Premium、Prime Video、Spotify、OpenAI、Google Play 等服务的可访问情况。 |
| `tk.sh` | TikTok 地区检测 | 检测当前服务器出口 IP 的 TikTok 区域信息。 |
| `xrayQ.sh` | Xray 快速配置 | 自动安装 Xray，并生成 `socks` 或 `vmess` 配置，支持多出口 IP。 |
| `ip.sh` | IP 信息查询 | 通过 `ipinfo.io` 查询指定 IP 或本机公网 IP 信息。 |
| `delete.sh` | 云厂商组件卸载 | 清理常见云厂商/安全组件、监控代理等残留。 |
| `uninstall-xmr.sh` | 挖矿程序卸载 | 清理 MoneroOcean / XMRig 相关残留。 |
| `cc.py` | 历史脚本 | 上游保留文件，属于代理/请求相关脚本；出于安全考虑，这里不提供使用说明。 |

## 使用前准备

大多数脚本面向 Linux 服务器，建议先确认：

- 你有 root 或 `sudo` 权限
- 系统中已安装 `curl`、`wget`、`bash`、`systemctl` 等常用工具
- 执行前先想好是否需要保留现有 SSH 配置，尤其是 `root.sh`

如果你是通过远程 SSH 连接服务器，建议保留一条可回退的登录通道，再去改 SSH 策略。

## 快速使用

克隆后直接执行本地脚本：

```bash
git clone https://github.com/psmtnhljs/vps-test.git
cd vps-test
chmod +x *.sh
```

常见脚本的本地运行方式：

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

如果你更习惯在线执行，也可以直接拉取仓库中的脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/root.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/fail2ban-sshctl.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/ddns.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/media.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/tk.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/xrayQ.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/delete.sh)
bash <(curl -fsSL https://raw.githubusercontent.com/psmtnhljs/vps-test/main/uninstall-xmr.sh)
```

## 脚本说明

### 1. `root.sh`：SSH 认证配置

这个脚本会修改 `/etc/ssh/sshd_config`，并在执行前备份原配置。

可选模式：

1. 混合认证：密钥 + 密码
2. 仅密码认证
3. 仅密钥认证（推荐）

推荐在控制台可访问的情况下使用，并先确认自己知道当前 SSH 端口。

### 2. `fail2ban-sshctl.sh`：SSH 防爆破

用于管理 SSH 的 Fail2Ban 防护，适合希望快速给 SSH 加一层防护的场景。

通常直接运行脚本后按菜单操作即可。

### 3. `ddns.sh`：Cloudflare 动态解析

用于把 Cloudflare 解析记录自动更新为当前公网 IP。

运行前需要准备：

- Cloudflare API Key
- Cloudflare 账号邮箱
- 域名的 Zone 名称
- 要更新的主机名

示例思路：

```bash
bash ddns.sh -k <api-key> -u <email> -h <host.example.com> -z <example.com> -t A
```

IPv6 记录可将 `-t` 设为 `AAAA`。

### 4. `media.sh`：媒体解锁检测

用于查看当前服务器是否可访问常见流媒体或 Web 服务。

直接运行后会输出各项检测结果，适合做 VPS 出口环境判断。

### 5. `tk.sh`：TikTok 地区检测

用于查看服务器出口 IP 的 TikTok 地区信息。

支持通过 `-I` 指定网卡接口，例如：

```bash
bash tk.sh -I eth0
```

### 6. `xrayQ.sh`：Xray 快速配置

脚本会自动安装 Xray，并根据服务器现有公网 IP 生成配置。

支持两种配置类型：

- `socks`
- `vmess`

示例：

```bash
sudo bash xrayQ.sh socks
sudo bash xrayQ.sh vmess
```

执行时会根据提示输入端口、账号、密码、UUID 或 WebSocket 路径等信息。

### 7. `ip.sh`：IP 查询

用于查询指定 IP 的基础信息；直接回车则查询本机公网 IP。

### 8. `delete.sh`：清理云厂商组件

用于卸载一些常见的云厂商代理、监控和安全组件。适合你明确知道服务器上装了哪些组件、并且确认要清理时再使用。

### 9. `uninstall-xmr.sh`：卸载矿工

用于清理 MoneroOcean / XMRig 相关服务和目录。

## 注意事项

- `root.sh` 会直接修改 SSH 配置，务必先准备好回滚手段。
- `ddns.sh` 需要 Cloudflare 凭据，请妥善保管。
- `delete.sh` 和 `uninstall-xmr.sh` 会删除系统中的相关组件，请确认目标无误后再执行。
- 仓库里保留的历史脚本不一定适合所有场景，建议先在测试机验证。

## 许可证

仓库未单独标注许可证时，默认请先与作者确认后再用于生产环境或二次分发。
