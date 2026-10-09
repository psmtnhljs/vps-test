#!/usr/bin/env bash
# MoneroOcean / XMRig 检测与可恢复清理工具。

set -u -o pipefail
umask 077

readonly VERSION="2.0.0"

MODE="check"
ASSUME_YES=0
TARGET_HOME="${HOME:-}"
TARGET_USER=""
BACKUP_ROOT=""
BACKUP_DIR=""
FOUND_MINER_DIR=0
FOUND_SYSTEM_UNIT=0
FOUND_USER_UNIT=0
FOUND_CRONTAB=0

declare -a FOUND_PROFILES=()
declare -a FOUND_PROCESSES=()

if [[ -t 1 ]]; then
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
    C_RESET=$'\033[0m'
else
    C_GREEN=""
    C_YELLOW=""
    C_RED=""
    C_CYAN=""
    C_RESET=""
fi

info() { printf '%s[i]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok() { printf '%s[✓]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die() { printf '%s[✗] %s%s\n' "$C_RED" "$*" "$C_RESET" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法：
  bash uninstall-xmr.sh --check
  sudo bash uninstall-xmr.sh --remove [--home /home/用户]

选项：
  --check             仅检测和预览，不停止进程、不删除文件（默认）
  --preview           与 --check 相同
  --remove            备份后清理 MoneroOcean / XMRig
  --yes               与 --remove 同用时跳过 REMOVE 二次确认
  --home DIR          指定需要检查的用户主目录
  --backup-dir DIR    指定备份根目录
  -h, --help          显示帮助
  -V, --version       显示版本

可恢复边界：
  - moneroocean 目录会移入备份，被修改的 shell 配置、crontab 和 service 文件会保留副本。
  - 已终止进程的运行状态不会自动恢复。
  - 脚本仅处理明确的 moneroocean/xmrig 项，不扫描或删除其他文件。
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check|--preview) MODE="check" ;;
        --remove) MODE="remove" ;;
        --yes) ASSUME_YES=1 ;;
        --home)
            [[ $# -ge 2 ]] || die "--home 需要路径"
            TARGET_HOME="$2"
            shift
            ;;
        --backup-dir)
            [[ $# -ge 2 ]] || die "--backup-dir 需要路径"
            BACKUP_ROOT="$2"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        -V|--version) printf 'uninstall-xmr.sh %s\n' "$VERSION"; exit 0 ;;
        *) die "未知参数：$1（使用 --help 查看帮助）" ;;
    esac
    shift
done

resolve_target() {
    if [[ ${EUID:-$(id -u)} -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" \
        && "$TARGET_HOME" == "/root" ]]; then
        TARGET_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
    fi

    [[ -n "$TARGET_HOME" && "$TARGET_HOME" == /* && "$TARGET_HOME" != "/" ]] \
        || die "用户主目录必须是非根目录的绝对路径"
    [[ -d "$TARGET_HOME" ]] || die "用户主目录不存在：$TARGET_HOME"

    TARGET_USER="$(stat -c '%U' "$TARGET_HOME" 2>/dev/null || true)"
    [[ -n "$TARGET_USER" && "$TARGET_USER" != "UNKNOWN" ]] || TARGET_USER="$(id -un)"

    if [[ -z "$BACKUP_ROOT" ]]; then
        if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
            BACKUP_ROOT="/var/backups/vps-test/${TARGET_USER}"
        else
            BACKUP_ROOT="${TARGET_HOME}/.local/state/vps-test-backups"
        fi
    fi
    [[ "$BACKUP_ROOT" == /* && "$BACKUP_ROOT" != "/" \
        && "$BACKUP_ROOT" != "${TARGET_HOME}/moneroocean"* ]] \
        || die "备份目录必须是安全的绝对路径，且不能位于 moneroocean 目录内"
    if ((ASSUME_YES)) && [[ "$MODE" != "remove" ]]; then
        die "--yes 只能与 --remove 一起使用"
    fi
}

user_crontab() {
    if [[ ${EUID:-$(id -u)} -eq 0 && "$TARGET_USER" != "$(id -un)" ]]; then
        crontab -u "$TARGET_USER" "$@"
    else
        crontab "$@"
    fi
}

detect_xmr() {
    local profile process
    FOUND_PROFILES=()
    FOUND_PROCESSES=()
    FOUND_MINER_DIR=0
    FOUND_SYSTEM_UNIT=0
    FOUND_USER_UNIT=0
    FOUND_CRONTAB=0

    [[ -e "${TARGET_HOME}/moneroocean" ]] && FOUND_MINER_DIR=1
    [[ -e "/etc/systemd/system/moneroocean_miner.service" ]] && FOUND_SYSTEM_UNIT=1
    [[ -e "${TARGET_HOME}/.config/systemd/user/moneroocean_miner.service" ]] && FOUND_USER_UNIT=1

    for profile in .profile .bashrc .bash_profile .zshrc; do
        if [[ -f "${TARGET_HOME}/${profile}" ]] \
            && grep -Eqi 'moneroocean|(^|[/[:space:]])xmrig([/[:space:]]|$)' "${TARGET_HOME}/${profile}"; then
            FOUND_PROFILES+=("${TARGET_HOME}/${profile}")
        fi
    done

    if command -v pgrep >/dev/null 2>&1; then
        for process in xmrig moneroocean_miner; do
            if pgrep -u "$TARGET_USER" -x "$process" >/dev/null 2>&1; then
                FOUND_PROCESSES+=("$process")
            fi
        done
    fi

    if command -v crontab >/dev/null 2>&1 \
        && user_crontab -l 2>/dev/null | grep -Eqi 'moneroocean|xmrig'; then
        FOUND_CRONTAB=1
    fi
}

found_count() {
    printf '%s' "$((${#FOUND_PROFILES[@]} + ${#FOUND_PROCESSES[@]} + FOUND_MINER_DIR + FOUND_SYSTEM_UNIT + FOUND_USER_UNIT + FOUND_CRONTAB))"
}

print_preview() {
    local item
    printf '%sMoneroOcean / XMRig 检测结果%s\n' "$C_CYAN" "$C_RESET"
    printf '目标用户：%s\n目标目录：%s\n' "$TARGET_USER" "$TARGET_HOME"
    printf '%s\n' '----------------------------------------'

    ((FOUND_MINER_DIR)) && printf '[目录] %s/moneroocean\n' "$TARGET_HOME"
    ((FOUND_SYSTEM_UNIT)) && printf '[服务] /etc/systemd/system/moneroocean_miner.service\n'
    ((FOUND_USER_UNIT)) && printf '[用户服务] %s/.config/systemd/user/moneroocean_miner.service\n' "$TARGET_HOME"
    for item in "${FOUND_PROFILES[@]}"; do
        printf '[Shell 配置] %s\n' "$item"
        grep -Eni 'moneroocean|(^|[/[:space:]])xmrig([/[:space:]]|$)' "$item" \
            | sed 's/^/  /' || true
    done
    for item in "${FOUND_PROCESSES[@]}"; do
        printf '[进程] %s (PID: %s)\n' "$item" \
            "$(pgrep -u "$TARGET_USER" -x "$item" 2>/dev/null | paste -sd, -)"
    done
    ((FOUND_CRONTAB)) && printf '[定时任务] %s 的 crontab 中含 moneroocean/xmrig 条目\n' "$TARGET_USER"

    if [[ "$(found_count)" -eq 0 ]]; then
        printf '未发现 MoneroOcean / XMRig 相关项。\n'
    fi
    printf '%s\n共发现 %s 项。\n' '----------------------------------------' "$(found_count)"
}

copy_for_backup() {
    local source="$1"
    local relative="${source#/}"
    local destination="${BACKUP_DIR}/rootfs/${relative}"
    mkdir -p -- "$(dirname "$destination")"
    cp -a -- "$source" "$destination"
}

create_backup() {
    local item
    BACKUP_DIR="${BACKUP_ROOT}/xmr.$(date +%Y%m%d_%H%M%S)"
    mkdir -p -- "$BACKUP_DIR/rootfs"

    for item in "${FOUND_PROFILES[@]}"; do copy_for_backup "$item"; done
    ((FOUND_SYSTEM_UNIT)) && copy_for_backup "/etc/systemd/system/moneroocean_miner.service"
    ((FOUND_USER_UNIT)) && copy_for_backup "${TARGET_HOME}/.config/systemd/user/moneroocean_miner.service"
    if ((FOUND_CRONTAB)); then
        user_crontab -l >"${BACKUP_DIR}/user-crontab.txt" 2>/dev/null || true
    fi

    {
        printf '创建时间：%s\n' "$(date -Is)"
        printf '目标用户：%s\n目标目录：%s\n' "$TARGET_USER" "$TARGET_HOME"
        printf '处理前进程：%s\n' "${FOUND_PROCESSES[*]:-无}"
        printf '注意：moneroocean 目录会在执行删除步骤时移入本备份目录。\n'
    } >"${BACKUP_DIR}/manifest.txt"

    cat >"${BACKUP_DIR}/RESTORE.txt" <<EOF
恢复前请先检查备份内容。
1. rootfs/ 下保存了 shell 配置和 service 文件的原路径，请手动复制回 /。
2. 如果存在 moneroocean/ 目录，可将它移回 ${TARGET_HOME}/moneroocean。
3. 如果存在 user-crontab.txt，请检查后使用 crontab 恢复。
4. 恢复系统 service 文件后需执行 systemctl daemon-reload，服务启用和运行状态需人工恢复。
EOF
    ok "备份目录已创建：$BACKUP_DIR"
}

remove_profile_entries() {
    local profile temporary
    for profile in "${FOUND_PROFILES[@]}"; do
        temporary="$(mktemp)"
        grep -Evi 'moneroocean|(^|[/[:space:]])xmrig([/[:space:]]|$)' "$profile" >"$temporary" || true
        cat "$temporary" >"$profile"
        rm -f -- "$temporary"
    done
}

remove_crontab_entries() {
    local temporary
    ((FOUND_CRONTAB)) || return 0
    temporary="$(mktemp)"
    user_crontab -l 2>/dev/null | grep -Evi 'moneroocean|xmrig' >"$temporary" || true
    user_crontab "$temporary"
    rm -f -- "$temporary"
}

remove_xmr() {
    local process

    if ((FOUND_SYSTEM_UNIT)) && command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now moneroocean_miner.service >/dev/null 2>&1 || true
    fi
    for process in "${FOUND_PROCESSES[@]}"; do
        pkill -TERM -u "$TARGET_USER" -x "$process" >/dev/null 2>&1 || true
    done
    sleep 1
    for process in "${FOUND_PROCESSES[@]}"; do
        if pgrep -u "$TARGET_USER" -x "$process" >/dev/null 2>&1; then
            pkill -KILL -u "$TARGET_USER" -x "$process" >/dev/null 2>&1 || true
        fi
    done

    remove_profile_entries
    remove_crontab_entries

    if ((FOUND_MINER_DIR)); then
        mv -- "${TARGET_HOME}/moneroocean" "${BACKUP_DIR}/moneroocean"
    fi
    ((FOUND_SYSTEM_UNIT)) && rm -f -- "/etc/systemd/system/moneroocean_miner.service"
    ((FOUND_USER_UNIT)) && rm -f -- "${TARGET_HOME}/.config/systemd/user/moneroocean_miner.service"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
}

main() {
    local answer
    resolve_target
    if [[ "$MODE" == "remove" && ${EUID:-$(id -u)} -ne 0 ]]; then
        die "清理模式需要 root 权限"
    fi
    detect_xmr
    print_preview

    [[ "$MODE" == "remove" ]] || {
        info "当前是仅检测模式，没有修改文件或进程。"
        return 0
    }
    [[ "$(found_count)" -gt 0 ]] || { ok "无需清理"; return 0; }
    warn "清理将终止目标用户的 xmrig/moneroocean_miner 进程，并移除上述启动项。"
    if ((!ASSUME_YES)); then
        read -r -p "请确认上述清单，输入 REMOVE 继续：" answer
        [[ "$answer" == "REMOVE" ]] || { info "已取消，未修改系统"; return 0; }
    fi

    create_backup
    remove_xmr
    detect_xmr
    if [[ "$(found_count)" -eq 0 ]]; then
        ok "MoneroOcean / XMRig 清理完成"
    else
        warn "仍有未清理项，请再次运行 --check 查看"
    fi
    printf '备份与恢复说明：%s\n' "$BACKUP_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
