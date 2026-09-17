#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# root.sh 回归测试
#
# 覆盖场景：
#   1) PATH 中不含 /usr/sbin、/sbin（`bash <(curl ...)` / 非登录 shell 的
#      典型环境）时，脚本仍能定位 sshd、通过配置校验并完成"仅密码认证"。
#   2) sshd 确实不存在时，脚本应给出明确错误并退出，而不是继续执行后
#      在 `sshd -t` 处报 "未找到命令"。
#
# 用法:
#   bash tests/test_root_sh.sh [被测试的脚本路径]
# 默认测试仓库根目录下的 root.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SOURCE_SCRIPT="${1:-${REPO_ROOT}/root.sh}"

if [[ ! -f "$SOURCE_SCRIPT" ]]; then
    echo "找不到待测脚本: $SOURCE_SCRIPT" >&2
    exit 2
fi

PASS=0
FAIL=0
ok()   { echo -e "  \033[32m[PASS]\033[0m $1"; PASS=$((PASS + 1)); }
bad()  { echo -e "  \033[31m[FAIL]\033[0m $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "\033[34m== $1\033[0m"; }

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    if [[ "$haystack" == *"$needle"* ]]; then ok "$label"; else
        bad "$label (未找到: $needle)"
        echo "----- 实际输出 -----"; echo "$haystack" | tail -40; echo "--------------------"
    fi
}
assert_not_contains() {
    local haystack="$1" needle="$2" label="$3"
    if [[ "$haystack" != *"$needle"* ]]; then ok "$label"; else
        bad "$label (不应出现: $needle)"
    fi
}
assert_eq() {
    local actual="$1" expected="$2" label="$3"
    if [[ "$actual" == "$expected" ]]; then ok "$label"; else
        bad "$label (期望: '$expected', 实际: '$actual')"
    fi
}

# 读取真实 sshd 计算出的生效值（sshd -T），用于验证配置是否真的生效
effective() {
    /usr/sbin/sshd -T -f "$1" 2>/dev/null \
        | awk -v k="$2" 'tolower($1)==tolower(k) {print tolower($2); exit}'
}

# ------------------------------------------------------------------
# 沙箱：把脚本中的绝对路径重定向到临时目录，并准备各类 stub 命令
# ------------------------------------------------------------------
make_sandbox() {
    local work="$1" sshd_mode="$2" apt_ok="$3"
    local fake_sshd="$work/no-sshd/sshd"

    mkdir -p "$work"/{bin,etc/ssh,var/log,root,etc/ssh/sshd_config.d}

    # 模拟 Debian/Ubuntu 的真实结构：顶部 Include + drop-in 里的冲突设置。
    # sshd 取"首个出现"的值，因此脚本写下的设置必须优先于 drop-in 才能生效。
    cat > "$work/etc/ssh/sshd_config" <<EOF
Include ${work}/etc/ssh/sshd_config.d/*.conf
# 测试用最小 sshd 配置
Port 22
# PermitRootLogin prohibit-password
# PasswordAuthentication no
# PubkeyAuthentication yes
UsePAM yes
EOF

    cat > "$work/etc/ssh/sshd_config.d/50-test.conf" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication yes
PubkeyAuthentication yes
EOF

    # 记录初始配置，用于校验失败时配置未被改动
    cp "$work/etc/ssh/sshd_config" "$work/sshd_config.orig"

    # 重写脚本内的绝对路径（仅测试用副本）
    sed -e "s|/etc/ssh/sshd_config|${work}/etc/ssh/sshd_config|g" \
        -e "s|/var/log/ssh_auth_setup.log|${work}/var/log/ssh_auth_setup.log|g" \
        -e "s|/root/ssh_keys|${work}/root/ssh_keys|g" \
        -e "s|/root/.ssh|${work}/root/.ssh|g" \
        "$SOURCE_SCRIPT" > "$work/root.sh"

    # 供 apt-get stub 安装用的假 sshd
    printf '#!/bin/sh\nexit 0\n' > "$work/stub_sshd"
    chmod +x "$work/stub_sshd"

    case "$sshd_mode" in
        missing)
            # 系统上完全没有 sshd：候选路径不存在，且 command -v 也找不到
            sed -i -e 's|/usr/sbin/sshd|/nonexistent/sshd|' \
                   -e 's|/sbin/sshd|/nonexistent/sshd|' \
                   -e 's|/usr/local/sbin/sshd|/nonexistent/sshd|' \
                   -e 's|/usr/local/bin/sshd|/nonexistent/sshd|' \
                   -e 's|/usr/bin/sshd|/nonexistent/sshd|' \
                   -e 's|:/usr/sbin:/sbin:/usr/local/sbin||' \
                   "$work/root.sh"
            ;;
        installable)
            # sshd 缺失但可以通过安装补齐：候选路径指向假的 sshd，
            # 同时让 PATH 查找也失败（安装后才由 apt-get stub 创建）
            sed -i -e "s|/usr/sbin/sshd|${fake_sshd}|" \
                   -e "s|/sbin/sshd|${fake_sshd}|" \
                   -e "s|/usr/local/sbin/sshd|${fake_sshd}|" \
                   -e "s|/usr/local/bin/sshd|${fake_sshd}|" \
                   -e "s|/usr/bin/sshd|${fake_sshd}|" \
                   -e 's|command -v sshd |command -v __no_sshd_installed__ |' \
                   "$work/root.sh"
            ;;
    esac

    # stub: passwd（避免真的改密码）
    cat > "$work/bin/passwd" <<'EOF'
#!/bin/sh
echo "[stub] passwd $*"
exit 0
EOF

    # stub: systemctl
    cat > "$work/bin/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
    list-unit-files) echo "ssh.service    enabled"; exit 0 ;;
    is-active)       exit 0 ;;
    *)               echo "[stub] systemctl $*"; exit 0 ;;
esac
EOF

    # stub: service
    cat > "$work/bin/service" <<'EOF'
#!/bin/sh
echo "[stub] service $*"
exit 0
EOF

    # stub: clear（避免 TERM 问题）
    cat > "$work/bin/clear" <<'EOF'
#!/bin/sh
exit 0
EOF

    # stub: apt-get（记录调用；install 时按需"装上"假 sshd）
    cat > "$work/bin/apt-get" <<EOF
#!/bin/sh
echo "apt-get \$*" >> "${work}/apt-get.calls"
if [ "${apt_ok}" != "yes" ]; then
    exit 1
fi
if [ "\$1" = "install" ] && [ "${sshd_mode}" = "installable" ]; then
    mkdir -p "$(dirname "$fake_sshd")"
    cp "${work}/stub_sshd" "${fake_sshd}"
    chmod +x "${fake_sshd}"
fi
exit 0
EOF

    chmod +x "$work"/bin/*
}

# 关键：模拟 `bash <(curl ...)` 的环境 —— PATH 不含 /usr/sbin 和 /sbin
run_script() {
    local work="$1" input="$2"
    printf '%s\n' "$input" | env -i \
        PATH="$work/bin:/usr/bin:/bin" \
        HOME="$work/root" \
        TERM=xterm \
        LANG=C.UTF-8 \
        bash "$work/root.sh" 2>&1
}

# ------------------------------------------------------------------
info "待测脚本: $SOURCE_SCRIPT"
info "场景 1: PATH 不含 sbin，sshd 仅存在于 /usr/sbin/sshd"
# ------------------------------------------------------------------
W1="$(mktemp -d)"
make_sandbox "$W1" yes yes
OUT1="$(run_script "$W1" 2)"
RC1=$?

assert_eq "$RC1" "0" "脚本应以 0 退出"
assert_contains "$OUT1" "依赖检查通过" "依赖检查应通过（不再误报缺少 chpasswd/sshd）"
assert_not_contains "$OUT1" "未找到命令" "不应出现 '未找到命令'"
assert_not_contains "$OUT1" "SSH 配置验证失败" "配置校验不应失败"
assert_contains "$OUT1" "SSH 服务已重载" "SSH 服务应重载成功"
assert_contains "$OUT1" "仅密码认证模式配置完成" "应完成模式 2 配置"

CFG1="$W1/etc/ssh/sshd_config"
assert_contains "$(cat "$CFG1")" "PasswordAuthentication yes" "配置写入 PasswordAuthentication yes"
assert_contains "$(cat "$CFG1")" "PubkeyAuthentication no" "配置写入 PubkeyAuthentication no"
assert_contains "$(cat "$CFG1")" "PermitRootLogin yes" "配置写入 PermitRootLogin yes"
assert_contains "$(cat "$CFG1")" "UsePAM yes" "配置写入 UsePAM yes"

if /usr/sbin/sshd -t -f "$CFG1" >/dev/null 2>&1; then
    ok "生成的配置通过真实 sshd 语法校验"
else
    bad "生成的配置未通过真实 sshd 语法校验"
fi

# 关键：drop-in 文件里写的是相反的值，脚本的设置必须真正生效
assert_eq "$(effective "$CFG1" "permitrootlogin")" "yes" "生效值 PermitRootLogin=yes（未被 drop-in 覆盖）"
assert_eq "$(effective "$CFG1" "passwordauthentication")" "yes" "生效值 PasswordAuthentication=yes（未被 drop-in 覆盖）"
assert_eq "$(effective "$CFG1" "pubkeyauthentication")" "no" "生效值 PubkeyAuthentication=no（未被 drop-in 覆盖）"

if compgen -G "$W1/etc/ssh/sshd_config.backup.*" > /dev/null; then
    ok "配置文件已备份"
else
    bad "未生成配置文件备份"
fi

if [[ -f "$W1/apt-get.calls" ]]; then
    bad "依赖齐全时不应调用 apt-get（实际调用了: $(cat "$W1/apt-get.calls" | tr '\n' ' ')）"
else
    ok "依赖齐全时未触发安装"
fi
rm -rf "$W1"

# ------------------------------------------------------------------
info "场景 2: 系统上确实没有 sshd，且自动安装失败"
# ------------------------------------------------------------------
W2="$(mktemp -d)"
make_sandbox "$W2" missing no
OUT2="$(run_script "$W2" 2)"
RC2=$?

if [[ "$RC2" -ne 0 ]]; then ok "应以非 0 退出（实际 $RC2）"; else bad "应非 0 退出（实际 0）"; fi
assert_not_contains "$OUT2" "未找到命令" "不应出现 '未找到命令'"
assert_contains "$OUT2" "缺少依赖" "应提示缺少依赖"
assert_contains "$OUT2" "依赖安装失败" "安装失败时应给出明确错误"
if [[ "$OUT2" != *"配置完成"* ]]; then
    ok "缺少 sshd 时不应继续完成配置"
else
    bad "缺少 sshd 时仍然完成了配置"
fi
# 配置不应被改动
if diff -q "$W2/sshd_config.orig" "$W2/etc/ssh/sshd_config" > /dev/null; then
    ok "失败时不修改 sshd_config"
else
    bad "失败时 sshd_config 被改动"
fi
rm -rf "$W2"

# ------------------------------------------------------------------
info "场景 3: 模式 1（混合认证）在 PATH 不含 sbin 时可用"
# ------------------------------------------------------------------
W3="$(mktemp -d)"
make_sandbox "$W3" yes yes
OUT3="$(run_script "$W3" 1)"
RC3=$?
assert_eq "$RC3" "0" "脚本应以 0 退出"
assert_contains "$OUT3" "混合认证模式配置完成" "应完成模式 1 配置"
assert_contains "$(cat "$W3/etc/ssh/sshd_config")" "PubkeyAuthentication yes" "混合模式启用密钥认证"
assert_contains "$(cat "$W3/etc/ssh/sshd_config")" "PasswordAuthentication yes" "混合模式启用密码认证"
assert_eq "$(effective "$W3/etc/ssh/sshd_config" "permitrootlogin")" "yes" "混合模式生效值 PermitRootLogin=yes"
assert_eq "$(effective "$W3/etc/ssh/sshd_config" "pubkeyauthentication")" "yes" "混合模式生效值 PubkeyAuthentication=yes"
assert_not_contains "$OUT3" "未找到命令" "不应出现 '未找到命令'"
assert_not_contains "$OUT3" "配置未生效" "不应出现配置未生效告警"
rm -rf "$W3"

# ------------------------------------------------------------------
info "场景 4: 模式 3（仅密钥）关键流程，含 120 秒回滚子 shell"
# ------------------------------------------------------------------
W4="$(mktemp -d)"
make_sandbox "$W4" yes yes
# 输入: 3 = 仅密钥模式, yes = 确认密钥登录测试成功
OUT4="$(printf '3\nyes\n' | env -i \
    PATH="$W4/bin:/usr/bin:/bin" \
    HOME="$W4/root" TERM=xterm LANG=C.UTF-8 \
    timeout 60 bash "$W4/root.sh" 2>&1)"
RC4=$?
assert_eq "$RC4" "0" "脚本应以 0 退出（未因测试超时阻塞）"
assert_contains "$OUT4" "密钥已生成" "应生成 SSH 密钥"
assert_contains "$OUT4" "公钥已添加到 authorized_keys" "应写入 authorized_keys"
assert_contains "$OUT4" "仅密钥认证模式配置完成" "应完成模式 3 配置"
assert_contains "$(cat "$W4/etc/ssh/sshd_config")" "PasswordAuthentication no" "模式 3 最终禁用密码登录"
assert_contains "$(cat "$W4/etc/ssh/sshd_config")" "PubkeyAuthentication yes" "模式 3 启用密钥登录"
if compgen -G "$W4/root/ssh_keys/ssh_key_*" > /dev/null; then
    ok "私钥文件已生成"
else
    bad "私钥文件未生成"
fi
if compgen -G "$W4/root/ssh_keys/ssh_key_*.pem" > /dev/null; then
    ok "PEM 私钥导出在密钥目录内"
else
    bad "PEM 私钥未导出到密钥目录"
fi
# 回归：路径中出现 "." 时，旧代码会按最后一个 "." 截断，把 .pem/.ppk 写到
# 沙箱目录的上一层（例如 /tmp/tmp.pem），必须确保这种串味文件不存在
if [[ ! -e "${W4%.*}.pem" && ! -e "${W4%.*}.ppk" ]]; then
    ok "未在错误位置生成 .pem/.ppk（路径截断 bug 已修复）"
else
    bad "在错误位置生成了密钥文件: ${W4%.*}.pem/.ppk"
fi
if compgen -G "$W4/root/.ssh/authorized_keys" > /dev/null; then
    ok "authorized_keys 已生成"
else
    bad "authorized_keys 未生成"
fi
assert_not_contains "$OUT4" "未找到命令" "不应出现 '未找到命令'"
# drop-in 里写着 PasswordAuthentication yes，脚本必须真正把它禁用掉
assert_eq "$(effective "$W4/etc/ssh/sshd_config" "passwordauthentication")" "no" "生效值 PasswordAuthentication=no（未被 drop-in 覆盖）"
assert_eq "$(effective "$W4/etc/ssh/sshd_config" "pubkeyauthentication")" "yes" "生效值 PubkeyAuthentication=yes"
assert_contains "$OUT4" "密码登录: 已禁用" "应确认密码登录已真正禁用"
rm -rf "$W4"

# ------------------------------------------------------------------
info "场景 5: sshd 缺失但自动安装成功（验证安装后的重新校验）"
# ------------------------------------------------------------------
W5="$(mktemp -d)"
make_sandbox "$W5" installable yes
OUT5="$(run_script "$W5" 2)"
RC5=$?
assert_eq "$RC5" "0" "脚本应以 0 退出"
assert_contains "$OUT5" "缺少依赖" "应先提示缺少依赖"
assert_contains "$OUT5" "依赖安装完成" "安装后应重新校验并报告完成"
assert_contains "$OUT5" "仅密码认证模式配置完成" "依赖补齐后应完成配置"
assert_not_contains "$OUT5" "未找到命令" "不应出现 '未找到命令'"
rm -rf "$W5"

# ------------------------------------------------------------------
info "场景 6: puttygen 转换失败时模式 3 不应静默中断"
# ------------------------------------------------------------------
W6="$(mktemp -d)"
make_sandbox "$W6" yes yes
# 用必然失败的 puttygen 覆盖真实命令，模拟未安装/转换失败
cat > "$W6/bin/puttygen" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$W6/bin/puttygen"
OUT6="$(printf '3\nyes\n' | env -i \
    PATH="$W6/bin:/usr/bin:/bin" \
    HOME="$W6/root" TERM=xterm LANG=C.UTF-8 \
    timeout 60 bash "$W6/root.sh" 2>&1)"
RC6=$?
assert_eq "$RC6" "0" "puttygen 失败时脚本仍应以 0 退出"
assert_contains "$OUT6" "仅密钥认证模式配置完成" "puttygen 失败不应中断模式 3"
assert_not_contains "$OUT6" "已生成 PPK" "不应谎报生成 PPK"
if compgen -G "$W6/root/ssh_keys/ssh_key_*.pem" > /dev/null; then
    ok "PEM 私钥仍然正常导出"
else
    bad "PEM 私钥未导出"
fi
assert_eq "$(effective "$W6/etc/ssh/sshd_config" "passwordauthentication")" "no" "生效值 PasswordAuthentication=no（puttygen 失败不影响）"
rm -rf "$W6"

# ------------------------------------------------------------------
echo ""
echo "=========================================="
echo " 通过: $PASS   失败: $FAIL"
echo "=========================================="
[[ "$FAIL" -eq 0 ]]
