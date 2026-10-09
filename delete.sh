#!/usr/bin/env bash
# 常见云厂商代理、监控和安全组件检测/清理工具。
# 原始版本来源：https://github.com/spiritLHLS/one-click-installation-script

set -u -o pipefail
umask 077

readonly VERSION="2.0.0"
readonly DEFAULT_BACKUP_ROOT="/var/backups/vps-test"

MODE="check"
ASSUME_YES=0
BACKUP_ROOT="$DEFAULT_BACKUP_ROOT"
BACKUP_ARCHIVE=""
FOUND_CRONTAB=0
FOUND_SNAP=0
LIMITED_CHECK=0

declare -a FOUND_PATHS=()
declare -a FOUND_SERVICES=()
declare -a FOUND_PROCESSES=()

readonly -a CANDIDATE_PATHS=(
    "/usr/local/qcloud"
    "/etc/cron.d/sgagenttask"
    "/etc/KsyunAgent"
    "/usr/local/uniagent"
    "/usr/local/share/jcloud"
    "/usr/local/aegis"
    "/opt/aegis"
    "/usr/local/cloudmonitor"
    "/usr/local/share/aliyun-assist"
    "/usr/local/share/assist-daemon"
    "/etc/init.d/aegis"
    "/etc/init.d/agentwatch"
    "/etc/systemd/system/aegis.service"
    "/etc/systemd/system/aliyun.service"
    "/etc/systemd/system/aliyun-util.service"
    "/etc/systemd/system/agentwatch.service"
    "/usr/sbin/aliyun_installer"
    "/usr/sbin/aliyun-service"
    "/usr/sbin/aliyun-service.backup"
    "/etc/aliyun-util"
)

readonly -a CANDIDATE_SERVICES=(
    "aegis.service"
    "agentwatch.service"
    "aliyun.service"
    "aliyun-util.service"
    "ecs_mq.service"
    "oracle-cloud-agent.service"
    "oracle-cloud-agent-updater.service"
    "jcs-agent-core.service"
    "jcs-entry.service"
    "jcs-shutdown-scripts.service"
    "barad_agent.service"
    "sgagent.service"
)

readonly -a CANDIDATE_PROCESSES=(
    "aegis_cli"
    "aegis_client"
    "aegis_update"
    "aegis_quartz"
    "AliYunDun"
    "AliYunDunMonitor"
    "AliYunDunUpdate"
    "AliHids"
    "AliHips"
    "aliyun-service"
    "assist_daemon"
    "assist-daemon"
    "agentwatch"
    "jdog"
    "telescoped"
)

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
  bash delete.sh --check
  sudo bash delete.sh --remove

选项：
  --check             仅检测并预览，不停止服务、不删除文件（默认）
  --preview           与 --check 相同
  --remove            备份可见文件后执行清理
  --yes               与 --remove 同用时跳过 REMOVE 二次确认
  --backup-dir DIR    指定备份目录（默认 /var/backups/vps-test）
  -h, --help          显示帮助
  -V, --version       显示版本

可恢复边界：
  - 检测到的文件和 root crontab 会在删除前归档。
  - 服务启用/运行状态会记录，但不会自动恢复。
  - Snap 包、云端注册关系和厂商控制台设置无法通过文件备份恢复。
  - 脚本不修改 hostname，不禁用 cloud-init，不删除 qemu-guest-agent。
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check|--preview) MODE="check" ;;
        --remove) MODE="remove" ;;
        --yes) ASSUME_YES=1 ;;
        --backup-dir)
            [[ $# -ge 2 ]] || die "--backup-dir 需要路径"
            BACKUP_ROOT="$2"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        -V|--version) printf 'delete.sh %s\n' "$VERSION"; exit 0 ;;
        *) die "未知参数：$1（使用 --help 查看帮助）" ;;
    esac
    shift
done

[[ "$BACKUP_ROOT" == /* && "$BACKUP_ROOT" != "/" ]] \
    || die "备份目录必须是非根目录的绝对路径"
if ((ASSUME_YES)) && [[ "$MODE" != "remove" ]]; then
    die "--yes 只能与 --remove 一起使用"
fi

service_exists() {
    local service="$1"
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl list-unit-files --type=service --no-legend "$service" 2>/dev/null \
        | awk '{print $1}' | grep -Fxq "$service"
}

detect_components() {
    local item
    FOUND_PATHS=()
    FOUND_SERVICES=()
    FOUND_PROCESSES=()
    FOUND_CRONTAB=0
    FOUND_SNAP=0
    LIMITED_CHECK=0

    for item in "${CANDIDATE_PATHS[@]}"; do
        [[ -e "$item" || -L "$item" ]] && FOUND_PATHS+=("$item")
    done

    for item in "${CANDIDATE_SERVICES[@]}"; do
        service_exists "$item" && FOUND_SERVICES+=("$item")
    done

    if command -v pgrep >/dev/null 2>&1; then
        for item in "${CANDIDATE_PROCESSES[@]}"; do
            pgrep -x "$item" >/dev/null 2>&1 && FOUND_PROCESSES+=("$item")
        done
    fi

    if [[ ${EUID:-$(id -u)} -eq 0 ]] && command -v crontab >/dev/null 2>&1 \
        && crontab -l 2>/dev/null | grep -Eq '/usr/local/qcloud|aegis|aliyun|cloudmonitor'; then
        FOUND_CRONTAB=1
    fi

    [[ ${EUID:-$(id -u)} -eq 0 ]] || LIMITED_CHECK=1

    if command -v snap >/dev/null 2>&1 \
        && snap list oracle-cloud-agent >/dev/null 2>&1; then
        FOUND_SNAP=1
    fi
}

found_count() {
    printf '%s' "$((${#FOUND_PATHS[@]} + ${#FOUND_SERVICES[@]} + ${#FOUND_PROCESSES[@]} + FOUND_CRONTAB + FOUND_SNAP))"
}

print_preview() {
    local item
    printf '%s云厂商组件检测结果%s\n' "$C_CYAN" "$C_RESET"
    printf '%s\n' '----------------------------------------'

    for item in "${FOUND_PATHS[@]}"; do printf '[文件] %s\n' "$item"; done
    for item in "${FOUND_SERVICES[@]}"; do
        printf '[服务] %s (enabled=%s, active=%s)\n' "$item" \
            "$(systemctl is-enabled "$item" 2>/dev/null || echo unknown)" \
            "$(systemctl is-active "$item" 2>/dev/null || echo inactive)"
    done
    for item in "${FOUND_PROCESSES[@]}"; do
        printf '[进程] %s (PID: %s)\n' "$item" "$(pgrep -x "$item" 2>/dev/null | paste -sd, -)"
    done
    ((FOUND_CRONTAB)) && printf '[定时任务] root crontab 中的云组件条目\n'
    ((FOUND_SNAP)) && printf '[Snap 包] oracle-cloud-agent\n'

    if [[ "$(found_count)" -eq 0 ]]; then
        printf '未发现脚本已知的云厂商代理、监控或安全组件。\n'
    fi
    printf '%s\n' '----------------------------------------'
    printf '共发现 %s 项。\n' "$(found_count)"
    ((LIMITED_CHECK)) && warn "当前为非 root 检测，无权访问的路径和 root crontab 未纳入结果"
}

validate_backup_location() {
    local path
    for path in "${FOUND_PATHS[@]}"; do
        if [[ "$BACKUP_ROOT" == "$path" || "$BACKUP_ROOT" == "$path"/* ]]; then
            die "备份目录不能位于待删除路径内：$path"
        fi
    done
}

create_backup() {
    local timestamp stage path relative parent service
    timestamp="$(date +%Y%m%d_%H%M%S)"
    mkdir -p -- "$BACKUP_ROOT"
    stage="$(mktemp -d)"
    BACKUP_ARCHIVE="${BACKUP_ROOT}/cloud-agents.${timestamp}.tar.gz"

    mkdir -p "$stage/rootfs"
    for path in "${FOUND_PATHS[@]}"; do
        relative="${path#/}"
        parent="$(dirname "$stage/rootfs/$relative")"
        mkdir -p -- "$parent"
        cp -a -- "$path" "$stage/rootfs/$relative" \
            || { rm -rf -- "$stage"; die "备份失败：$path，未执行删除"; }
    done

    if ((FOUND_CRONTAB)); then
        crontab -l >"$stage/root-crontab.txt" 2>/dev/null || true
    fi

    {
        printf '创建时间：%s\n' "$(date -Is)"
        printf '文件：\n'
        printf '  %s\n' "${FOUND_PATHS[@]}"
        printf '服务：\n'
        for service in "${FOUND_SERVICES[@]}"; do
            printf '  %s enabled=%s active=%s\n' "$service" \
                "$(systemctl is-enabled "$service" 2>/dev/null || echo unknown)" \
                "$(systemctl is-active "$service" 2>/dev/null || echo inactive)"
        done
        printf '进程：%s\n' "${FOUND_PROCESSES[*]:-无}"
        printf 'oracle-cloud-agent Snap：%s\n' "$FOUND_SNAP"
    } >"$stage/manifest.txt"

    cat >"$stage/RESTORE.txt" <<'EOF'
请先把本归档解压到临时目录并检查内容。
rootfs/ 下的文件保留了原绝对路径，可人工复制回 /。
如需恢复 root crontab，请检查 root-crontab.txt 后手动执行 crontab root-crontab.txt。
恢复 systemd 单元后执行 systemctl daemon-reload，并根据 manifest.txt 人工恢复启用状态。
Snap 包、已终止的进程和云端注册状态不在自动恢复范围内。
EOF

    tar -czf "$BACKUP_ARCHIVE" -C "$stage" . \
        || { rm -rf -- "$stage"; die "无法创建备份归档，未执行删除"; }
    rm -rf -- "$stage"
    ok "删除前备份已保存：$BACKUP_ARCHIVE"
}

remove_crontab_entries() {
    local temporary
    ((FOUND_CRONTAB)) || return 0
    temporary="$(mktemp)"
    crontab -l 2>/dev/null \
        | grep -Ev '/usr/local/qcloud|aegis|aliyun|cloudmonitor' >"$temporary" || true
    crontab "$temporary"
    rm -f -- "$temporary"
}

remove_components() {
    local item

    for item in "${FOUND_SERVICES[@]}"; do
        systemctl disable --now "$item" >/dev/null 2>&1 || warn "无法完全停止/禁用服务：$item"
    done

    for item in "${FOUND_PROCESSES[@]}"; do
        pkill -TERM -x "$item" >/dev/null 2>&1 || true
    done
    sleep 1
    for item in "${FOUND_PROCESSES[@]}"; do
        if pgrep -x "$item" >/dev/null 2>&1; then
            pkill -KILL -x "$item" >/dev/null 2>&1 || warn "无法终止进程：$item"
        fi
    done

    remove_crontab_entries

    if ((FOUND_SNAP)); then
        snap remove oracle-cloud-agent || warn "无法移除 Snap 包 oracle-cloud-agent"
    fi

    for item in "${FOUND_PATHS[@]}"; do
        rm -rf -- "$item" || warn "无法删除：$item"
    done
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
}

main() {
    local answer
    if [[ "$MODE" == "remove" && ${EUID:-$(id -u)} -ne 0 ]]; then
        die "清理模式需要 root 权限"
    fi
    detect_components
    print_preview

    [[ "$MODE" == "remove" ]] || {
        info "当前是仅检测模式，没有修改系统。"
        return 0
    }

    [[ "$(found_count)" -gt 0 ]] || { ok "无需清理"; return 0; }
    warn "清理可能使云厂商监控、远程助手、安全扫描或控制台功能失效。"
    warn "文件备份不能自动恢复 Snap 包和云端注册关系。"
    if ((!ASSUME_YES)); then
        read -r -p "请确认上述清单，输入 REMOVE 继续：" answer
        [[ "$answer" == "REMOVE" ]] || { info "已取消，未修改系统"; return 0; }
    fi

    validate_backup_location
    create_backup
    remove_components
    detect_components
    if [[ "$(found_count)" -eq 0 ]]; then
        ok "清理完成"
    else
        warn "仍有未清理项，请再次运行 --check 查看"
    fi
    printf '备份归档：%s\n' "$BACKUP_ARCHIVE"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
