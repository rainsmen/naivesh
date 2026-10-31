#!/bin/bash
#===============================================================================
# NaiveProxy 多用户管理增强版 - 完整修复与优化版
# 功能：多用户、多域名、自动化证书申请与续期、多端口复用、HTTP/3 支持、安全加固
#===============================================================================

export LANG=en_US.UTF-8
shopt -s nullglob

#===============================================================================
# 颜色定义
#===============================================================================
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;36m'
bblue='\033[0;34m'
plain='\033[0m'

red(){ echo -e "\033[31m\033[01m$1\033[0m";}
green(){ echo -e "\033[32m\033[01m$1\033[0m";}
yellow(){ echo -e "\033[33m\033[01m$1\033[0m";}
blue(){ echo -e "\033[36m\033[01m$1\033[0m";}
white(){ echo -e "\033[37m\033[01m$1\033[0m";}
readp(){ read -r -p "$(yellow "$1")" "$2";}
pause(){ read -r -p "按回车继续..." _; }

run_action(){
    "$@"
    local status=$?
    if [[ $status -ne 0 ]]; then
        red "操作失败，退出码: $status"
    fi
    pause
    return 0
}

#===============================================================================
# 配置路径定义
#===============================================================================
SCRIPT_PATH=""
[[ -f "${BASH_SOURCE[0]}" ]] && SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
REPO_URL="${REPO_URL:-https://raw.githubusercontent.com/rainsmen/naivesh/main}"
BUNDLED_CADDY_VERSION="v2.11.2"
# 预编译 caddy 发布在 GitHub Releases，不放入 git 仓库
RELEASE_URL="${RELEASE_URL:-https://github.com/rainsmen/naivesh/releases/download/caddy-${BUNDLED_CADDY_VERSION}}"

INSTALL_SCRIPT="/usr/local/bin/naiveproxy.sh"
SHORTCUT="/usr/bin/na"
SHARE_DIR="/usr/local/share/naiveproxy"
ASSET_DIRS=()
[[ -n $SCRIPT_DIR ]] && ASSET_DIRS+=("$SCRIPT_DIR/assets")
ASSET_DIRS+=("$SHARE_DIR/assets")

CONFIG_DIR="/etc/naiveproxy"
USERS_FILE="$CONFIG_DIR/users.conf"
DOMAINS_FILE="$CONFIG_DIR/domains.conf"
PORTS_FILE="$CONFIG_DIR/ports.conf"
FW_STATE_FILE="$CONFIG_DIR/firewall.state"
ACME_HOOK="$CONFIG_DIR/acme-hook.sh"
CADDYFILE="$CONFIG_DIR/Caddyfile"
BACKUP_CADDYFILE="$CONFIG_DIR/reCaddyfile"
SERVICEFILE="/etc/systemd/system/naiveproxy.service"
BINARY="/usr/bin/caddy"
CADDY_VERSION_FILE="/etc/caddy/version"
NAIVE_DIR="/root/naive"
ACME_HOME="/root/.acme.sh"
ACME_BIN="$ACME_HOME/acme.sh"
ACME_RELOAD_CMD="systemctl try-restart naiveproxy"
BBR_SYSCTL_FILE="/etc/sysctl.d/99-naiveproxy-bbr.conf"
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/99-naiveproxy-nat64.conf"
NAT64_MARK="# naiveproxy-nat64"
GO_MIN_MINOR=21

# 依赖包及其 SHA256 (与 assets/SHA256SUMS 保持一致)
declare -gA ASSET_SHA256=(
    [acme.sh]="9059b81b424904fc574b2d2c314878dbeb69404f44d7bc5125e36f8f51f7d268"
    [caddy2-naive-linux-amd64.tar.gz]="a8b4a273e59bcb0994da0f06afc942e71e01f80f78f35b7c82913c2b573cc75e"
    [caddy2-naive-linux-arm64.tar.gz]="119dad3dc2d67dc39ea4a77c53594dd743a6b30854fd0a0b53ce92c66b31c088"
)

declare -gA USER_PASS USER_EMAIL DOMAIN_BACKEND DOMAIN_CERT DOMAIN_KEY
declare -ga PROXY_PORTS

#===============================================================================
# 通用工具与输入校验
#===============================================================================
gen_random(){
    local charset=$1 len=$2 out
    out=$(LC_ALL=C tr -dc "$charset" < /dev/urandom 2>/dev/null | head -c "$len")
    [[ ${#out} -eq $len ]] || out=$(openssl rand -hex "$len" 2>/dev/null | head -c "$len")
    echo "$out"
}

valid_user(){ [[ $1 =~ ^[A-Za-z0-9_]{3,32}$ ]]; }
# 仅允许 URL 非保留字符，分享链接与 Caddyfile 均无需转义
valid_pass(){ [[ $1 =~ ^[A-Za-z0-9._~-]{5,64}$ ]]; }
valid_domain(){ [[ ${#1} -le 253 && $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}$ ]]; }
valid_port(){ [[ $1 =~ ^[1-9][0-9]{0,4}$ && $1 -le 65535 ]]; }
valid_email(){ [[ $1 =~ ^[^[:space:]@:|]+@[^[:space:]@:|]+\.[^[:space:]@:|]+$ ]]; }

# 去除协议头与路径，保留 host[:port]
normalize_backend(){
    local b=$1
    b="${b#https://}"
    b="${b#http://}"
    b="${b%%/*}"
    echo "${b,,}"
}

valid_backend(){
    local b=$1 host port
    host="${b%%:*}"
    if [[ $b == *:* ]]; then
        port="${b#*:}"
        valid_port "$port" || return 1
    fi
    valid_domain "$host" || [[ $host =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# 旧版本未校验写入的值：只要能作为单个 Caddyfile 词元就继续沿用
caddy_token_safe(){
    local s=$1
    [[ -n $s ]] || return 1
    [[ $s == \#* ]] && return 1
    case $s in
        *[[:space:]]*|*[\"\'\`{}\\]*) return 1 ;;
    esac
    return 0
}

urlencode(){
    local LC_ALL=C s=$1 out="" c i
    for (( i = 0; i < ${#s}; i++ )); do
        c=${s:i:1}
        case $c in
            [A-Za-z0-9._~-]) out+=$c ;;
            *) printf -v c '%%%02X' "'$c"; out+=$c ;;
        esac
    done
    echo "$out"
}

# 关联数组遍历顺序不固定，统一按字典序输出
sorted_users(){ [[ ${#USER_PASS[@]} -gt 0 ]] && printf '%s\n' "${!USER_PASS[@]}" | LC_ALL=C sort; }
sorted_domains(){ [[ ${#DOMAIN_BACKEND[@]} -gt 0 ]] && printf '%s\n' "${!DOMAIN_BACKEND[@]}" | LC_ALL=C sort; }

# 可写入 Caddyfile 的用户（每行一个）
usable_users(){
    local u
    while IFS= read -r u; do
        caddy_token_safe "$u" && caddy_token_safe "${USER_PASS[$u]}" && [[ $u != *:* ]] && echo "$u"
    done < <(sorted_users)
}

# 已配置有效证书、可写入 Caddyfile 的域名（每行一个）
usable_domains(){
    local d
    while IFS= read -r d; do
        valid_domain "$d" && valid_backend "${DOMAIN_BACKEND[$d]}" \
            && [[ -s ${DOMAIN_CERT[$d]} && -s ${DOMAIN_KEY[$d]} ]] \
            && caddy_token_safe "${DOMAIN_CERT[$d]}" && caddy_token_safe "${DOMAIN_KEY[$d]}" \
            && echo "$d"
    done < <(sorted_domains)
}

# 原子写入：先写同目录临时文件再 rename，权限 600
write_file_atomic(){
    local dest=$1 tmp
    tmp=$(mktemp "${dest}.XXXXXX") || return 1
    if ! cat > "$tmp"; then rm -f "$tmp"; return 1; fi
    chmod 600 "$tmp" && mv -f "$tmp" "$dest"
}

installed_caddy_version(){
    [[ -x $BINARY ]] && "$BINARY" version 2>/dev/null | awk 'NR==1 {print $1}'
}

#===============================================================================
# 全局变量 - 系统检测
#===============================================================================
# shellcheck disable=SC2034 # release 仅用于识别受支持的系统
get_system_info(){
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            ubuntu) release="Ubuntu" ;;
            debian) release="Debian" ;;
            centos|rhel|almalinux|rocky|fedora|ol|amzn) release="Centos" ;;
            *)
                if [[ ${ID_LIKE:-} =~ (rhel|centos|fedora) ]]; then
                    release="Centos"
                elif [[ ${ID_LIKE:-} =~ (debian|ubuntu) ]]; then
                    release="Debian"
                else
                    red "脚本不支持当前的系统 ($ID)，建议使用 Ubuntu、Debian 或 CentOS/RHEL 系系统。" && exit 1
                fi
                ;;
        esac
        op="${PRETTY_NAME:-$ID}"
    elif [[ -f /etc/redhat-release ]]; then
        release="Centos"
        op=$(cat /etc/redhat-release)
    elif [[ -f /etc/issue ]]; then
        if grep -q -i "debian" /etc/issue; then release="Debian"; op="Debian"
        elif grep -q -i "ubuntu" /etc/issue; then release="Ubuntu"; op="Ubuntu"
        elif grep -q -i -E "centos|red hat|redhat" /etc/issue; then release="Centos"; op="CentOS"
        else red "脚本不支持当前的系统，请选择使用 Ubuntu, Debian, CentOS 系统。" && exit 1; fi
    else
        red "脚本不支持当前的系统，请选择使用 Ubuntu, Debian, CentOS 系统。" && exit 1
    fi

    case "$(uname -m)" in
        x86_64) cpu="amd64" ;;
        aarch64|arm64) cpu="arm64" ;;
        *) red "目前脚本仅支持 x86_64 (amd64) 与 aarch64 (arm64) 架构" && exit 1 ;;
    esac

    kernel_version=$(uname -r | cut -d "-" -f1)
    vi=$(systemd-detect-virt 2>/dev/null || true)
    [[ -z $vi ]] && vi="none"
    refresh_bbr_status
}

refresh_bbr_status(){
    bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    [[ -z $bbr ]] && bbr="未知/不支持"
}

#===============================================================================
# IPv4/IPv6 地址与 WARP 状态检测
#===============================================================================
detect_ips(){
    ipv4=$(curl -s4m5 https://icanhazip.com 2>/dev/null || true)
    ipv6=$(curl -s6m5 https://icanhazip.com 2>/dev/null || true)
}

warpcheck(){
    wgcfv6=$(curl -s6m5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep warp | cut -d= -f2 || true)
    wgcfv4=$(curl -s4m5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep warp | cut -d= -f2 || true)
}

#===============================================================================
# 纯 IPv6 VPS 的 NAT64/DNS64 支持
#===============================================================================
ensure_nat64(){
    warpcheck
    [[ $wgcfv4 =~ on|plus || $wgcfv6 =~ on|plus ]] && return 0
    [[ -n $(curl -s4m5 https://icanhazip.com 2>/dev/null) ]] && return 0
    # GitHub 无 AAAA 记录，可直接判断能否访问仅 IPv4 的站点
    curl -m 5 -s -o /dev/null https://github.com 2>/dev/null && return 0

    yellow "检测到纯 IPv6 VPS 且无法访问 IPv4 站点，配置 NAT64/DNS64 解析..."
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && [[ -L /etc/resolv.conf ]]; then
        mkdir -p "${RESOLVED_DROPIN%/*}"
        printf '[Resolve]\nDNS=2a00:1098:2b::1 2a00:1098:2c::1\n' > "$RESOLVED_DROPIN"
        systemctl restart systemd-resolved 2>/dev/null || true
    elif ! grep -q "$NAT64_MARK" /etc/resolv.conf 2>/dev/null; then
        # 置于最前，避免被原有 nameserver 抢先应答
        local tmp
        tmp=$(mktemp) || return 1
        {
            echo "$NAT64_MARK begin"
            echo "nameserver 2a00:1098:2b::1"
            echo "nameserver 2a00:1098:2c::1"
            echo "$NAT64_MARK end"
            cat /etc/resolv.conf 2>/dev/null
        } > "$tmp"
        cat "$tmp" > /etc/resolv.conf
        rm -f "$tmp"
    fi
}

remove_nat64(){
    if [[ -f $RESOLVED_DROPIN ]]; then
        rm -f "$RESOLVED_DROPIN"
        systemctl restart systemd-resolved 2>/dev/null || true
    fi
    if grep -q "$NAT64_MARK" /etc/resolv.conf 2>/dev/null; then
        local tmp
        tmp=$(mktemp) || return 1
        awk -v m="$NAT64_MARK" '$0 == m " begin" {skip=1; next} $0 == m " end" {skip=0; next} !skip' /etc/resolv.conf > "$tmp"
        cat "$tmp" > /etc/resolv.conf
        rm -f "$tmp"
    fi
}

#===============================================================================
# 防火墙端口管理 (TCP 与 UDP / HTTP3)
# 只操作当前生效的一种防火墙；脚本新增的规则记录在 $FW_STATE_FILE，删除时只撤销这些规则
#===============================================================================
fw_backend(){
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo ufw
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        echo firewalld
    elif command -v iptables &>/dev/null; then
        echo iptables
    else
        echo none
    fi
}

fw_rule_exists(){
    local backend=$1 port=$2 proto=$3
    case $backend in
        ufw) ufw status 2>/dev/null | grep -qE "^${port}/${proto}[[:space:]]" ;;
        firewalld) firewall-cmd --permanent --query-port="${port}/${proto}" &>/dev/null ;;
        iptables) iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
    esac
}

fw_add(){
    local backend=$1 port=$2 proto=$3
    case $backend in
        ufw) ufw allow "${port}/${proto}" >/dev/null 2>&1 ;;
        firewalld)
            firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1
            firewall-cmd --add-port="${port}/${proto}" >/dev/null 2>&1 ;;
        iptables)
            iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
            if command -v ip6tables &>/dev/null && ! ip6tables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then
                ip6tables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
            fi ;;
    esac
}

fw_del(){
    local backend=$1 port=$2 proto=$3
    case $backend in
        ufw) ufw delete allow "${port}/${proto}" >/dev/null 2>&1 ;;
        firewalld)
            firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1
            firewall-cmd --remove-port="${port}/${proto}" >/dev/null 2>&1 ;;
        iptables)
            while iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; do :; done
            command -v ip6tables &>/dev/null && while ip6tables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; do :; done ;;
    esac
}

fw_persist(){
    [[ $1 == iptables ]] || return 0
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 && return 0
    elif [[ -d /etc/sysconfig ]] && systemctl is-enabled --quiet iptables 2>/dev/null; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null
        command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null
        return 0
    fi
    # 默认策略为 ACCEPT 时规则本身无实际作用，无需提示
    if iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT ACCEPT'; then
        return 0
    fi
    yellow "提示: 未检测到 iptables 持久化工具 (如 iptables-persistent)，重启后放行规则会丢失"
}

open_port(){
    local port=$1 proto_arg=${2:-both} backend proto protos=()
    valid_port "$port" || return 0
    backend=$(fw_backend)
    [[ $backend == none ]] && return 0
    [[ $proto_arg == both || $proto_arg == tcp ]] && protos+=(tcp)
    [[ $proto_arg == both || $proto_arg == udp ]] && protos+=(udp)

    for proto in "${protos[@]}"; do
        fw_rule_exists "$backend" "$port" "$proto" && continue
        if fw_add "$backend" "$port" "$proto"; then
            echo "$backend $port $proto" >> "$FW_STATE_FILE"
            chmod 600 "$FW_STATE_FILE" 2>/dev/null || true
        fi
    done
    fw_persist "$backend"
}

# 撤销脚本此前为该端口添加的规则 (用户原有的规则不会动)
close_port(){
    local port=$1 b p proto remaining=() changed=""
    [[ -f $FW_STATE_FILE ]] || return 0
    while read -r b p proto; do
        [[ -z $b ]] && continue
        if [[ -z $port || $p == "$port" ]]; then
            fw_del "$b" "$p" "$proto"
            changed="$b"
        else
            remaining+=("$b $p $proto")
        fi
    done < "$FW_STATE_FILE"
    if [[ ${#remaining[@]} -gt 0 ]]; then
        printf '%s\n' "${remaining[@]}" | write_file_atomic "$FW_STATE_FILE"
    else
        rm -f "$FW_STATE_FILE"
    fi
    [[ -n $changed ]] && fw_persist "$changed"
    return 0
}

open_proxy_ports(){
    open_port 80 tcp
    for p in "${PROXY_PORTS[@]:-443}"; do
        open_port "$p" both
    done
    blue "执行开放端口 80 (TCP) 与代理端口 ${PROXY_PORTS[*]:-443} (TCP/UDP HTTP/3) 完毕"
    echo "----------------------------------------------------"
}

openyn(){
    red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    readp "是否自动开放端口（80及代理端口 TCP/UDP）？\n1、是，自动放行 (回车默认)\n2、否，我自己手动\n请选择：" action
    if [[ -z $action ]] || [[ "$action" = "1" ]]; then
        open_proxy_ports
    elif [[ "$action" = "2" ]]; then
        echo
    else
        red "输入错误,请重新选择" && openyn
    fi
}

#===============================================================================
# BBR 拥塞控制启用
#===============================================================================
enable_bbr(){
    green "\n===== 启用 BBR 拥塞控制 ====="
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) == bbr ]]; then
        green "BBR 已经处于启用状态！"
        return 0
    fi

    modprobe tcp_bbr 2>/dev/null || true
    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        red "当前内核 ($kernel_version) 不支持 BBR (需要 4.9 及以上且包含 tcp_bbr 模块)"
        return 1
    fi

    yellow "正在配置开启 BBR..."
    # /etc/sysctl.conf 在部分新系统上不再于开机时加载，改用 sysctl.d
    mkdir -p /etc/sysctl.d
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > "$BBR_SYSCTL_FILE"
    sysctl -p "$BBR_SYSCTL_FILE" >/dev/null 2>&1 || true
    refresh_bbr_status

    if [[ $bbr == bbr ]]; then
        green "BBR 启用成功！配置文件: $BBR_SYSCTL_FILE"
    else
        red "BBR 配置已写入 $BBR_SYSCTL_FILE，但当前未生效 (容器类虚拟化通常无法修改)"
        return 1
    fi
}

#===============================================================================
# 依赖安装
# 参数: ask = 先询问再安装 (启动时)；auto = 直接安装 (一键安装时)
#===============================================================================
check_deps(){
    local mode=${1:-auto} miss=() pkgs=() cmd pkg mgr

    for cmd in curl wget tar systemctl ss ip awk grep sed qrencode crontab openssl sha256sum base64; do
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    [[ ${#miss[@]} -eq 0 ]] && return 0

    if command -v apt-get &>/dev/null; then mgr=apt
    elif command -v dnf &>/dev/null; then mgr=dnf
    elif command -v yum &>/dev/null; then mgr=yum
    else
        red "未找到 apt/yum/dnf，无法自动安装依赖: ${miss[*]}"
        return 1
    fi

    for cmd in "${miss[@]}"; do
        case "$cmd" in
            ss|ip) [[ $mgr == apt ]] && pkg=iproute2 || pkg=iproute ;;
            crontab) [[ $mgr == apt ]] && pkg=cron || pkg=cronie ;;
            awk) pkg=gawk ;;
            systemctl) pkg=systemd ;;
            sha256sum|base64) pkg=coreutils ;;
            *) pkg=$cmd ;;
        esac
        [[ " ${pkgs[*]} " == *" $pkg "* ]] || pkgs+=("$pkg")
    done

    if [[ $mode == ask ]]; then
        yellow "缺少依赖命令: ${miss[*]}"
        readp "是否立即安装软件包 ${pkgs[*]}？(Y/n):" yn
        [[ $yn == n || $yn == N ]] && return 1
    else
        yellow "正在安装缺少的依赖: ${pkgs[*]}"
    fi

    case $mgr in
        apt)
            apt-get update -y || return 1
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" || return 1 ;;
        dnf) dnf install -y "${pkgs[@]}" || return 1 ;;
        yum) yum install -y "${pkgs[@]}" || return 1 ;;
    esac

    # CentOS/RHEL 下 cronie 默认未启动
    systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
}

#===============================================================================
# 初始化配置目录与安全权限
#===============================================================================
init_config(){
    mkdir -p "$CONFIG_DIR" "$NAIVE_DIR" || return 1
    chmod 700 "$CONFIG_DIR" "$NAIVE_DIR" 2>/dev/null || true

    [[ ! -f $USERS_FILE ]] && touch "$USERS_FILE"
    [[ ! -f $DOMAINS_FILE ]] && touch "$DOMAINS_FILE"
    [[ ! -f $PORTS_FILE ]] && echo "443" > "$PORTS_FILE"
    chmod 600 "$USERS_FILE" "$DOMAINS_FILE" "$PORTS_FILE" 2>/dev/null || true

    # 自动加载已有配置并自愈历史遗留的服务单元、Crontab 与续期钩子 (均为本地操作)
    load_config
    sync_ports_with_caddyfile
    upgrade_service_file
    fix_acme_cron_and_hooks
    return 0
}

#===============================================================================
# 加载用户、域名与端口配置
#===============================================================================
load_config(){
    local p u e d b c k line
    PROXY_PORTS=()
    if [[ -f $PORTS_FILE ]]; then
        while read -r p; do
            valid_port "$p" && [[ " ${PROXY_PORTS[*]} " != *" $p "* ]] && PROXY_PORTS+=("$p")
        done < <(grep -v '^#' "$PORTS_FILE" 2>/dev/null)
    fi
    if [[ ${#PROXY_PORTS[@]} -eq 0 ]]; then
        p=$(get_proxy_port)
        PROXY_PORTS=("${p:-443}")
    fi

    USER_PASS=()
    USER_EMAIL=()
    if [[ -f $USERS_FILE ]]; then
        while IFS=: read -r u p e; do
            [[ -n $u && -n $p ]] || continue
            USER_PASS[$u]=$p
            USER_EMAIL[$u]=$e
        done < <(grep -v '^#' "$USERS_FILE" 2>/dev/null)
    fi

    # 新格式以 | 分隔 (后端可带端口)；兼容旧版以 : 分隔的记录
    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    if [[ -f $DOMAINS_FILE ]]; then
        while IFS= read -r line; do
            [[ -z $line || $line == \#* ]] && continue
            if [[ $line == *"|"* ]]; then
                IFS='|' read -r d b c k <<< "$line"
            else
                IFS=: read -r d b c k <<< "$line"
            fi
            [[ -n $d && -n $b ]] || continue
            DOMAIN_BACKEND[$d]=$b
            DOMAIN_CERT[$d]=$c
            DOMAIN_KEY[$d]=$k
        done < "$DOMAINS_FILE"
    fi
    return 0
}

save_users(){
    local u
    {
        echo "# 用户配置 - 格式: 用户名:密码:邮箱"
        while IFS= read -r u; do
            echo "${u}:${USER_PASS[$u]}:${USER_EMAIL[$u]:-}"
        done < <(sorted_users)
    } | write_file_atomic "$USERS_FILE"
}

save_domains(){
    local d
    {
        echo "# 域名配置 - 格式: 域名|后端|证书路径|密钥路径"
        while IFS= read -r d; do
            echo "${d}|${DOMAIN_BACKEND[$d]}|${DOMAIN_CERT[$d]:-}|${DOMAIN_KEY[$d]:-}"
        done < <(sorted_domains)
    } | write_file_atomic "$DOMAINS_FILE"
}

save_ports(){
    {
        echo "# 端口配置"
        printf '%s\n' "${PROXY_PORTS[@]}"
    } | write_file_atomic "$PORTS_FILE"
}

get_proxy_port(){
    local p
    p=$(awk '$1 == "https_port" { print $2; exit }' "$CADDYFILE" 2>/dev/null)
    valid_port "$p" && echo "$p" || echo 443
}

# 现有 Caddyfile 中站点地址使用的端口 (每行一个，按出现顺序去重)
caddyfile_ports(){
    [[ -f $CADDYFILE ]] || return 0
    awk '/^[^[:space:]#{].*\{[[:space:]]*$/ {
            line = $0; sub(/\{.*/, "", line); n = split(line, a, /[[:space:],]+/)
            for (i = 1; i <= n; i++) if (a[i] ~ /:[0-9]+$/) { p = a[i]; sub(/.*:/, "", p); if (!(p in seen)) { seen[p] = 1; print p } }
        }' "$CADDYFILE"
}

# 旧版本或手工修改可能导致 ports.conf 与正在使用的 Caddyfile 不一致；
# 以 Caddyfile 为准，避免重新生成配置时悄悄更换端口导致客户端断开
sync_ports_with_caddyfile(){
    local live=() p
    mapfile -t live < <(caddyfile_ports)
    for p in "${live[@]}"; do valid_port "$p" || return 0; done
    [[ ${#live[@]} -gt 0 && "${live[*]}" != "${PROXY_PORTS[*]}" ]] || return 0
    yellow "端口配置 (${PROXY_PORTS[*]}) 与当前 Caddyfile (${live[*]}) 不一致，已按 Caddyfile 更新端口配置"
    PROXY_PORTS=("${live[@]}")
    save_ports
}

#===============================================================================
# 依赖包获取与 SHA256 校验
#===============================================================================
download(){
    local url=$1 out=$2
    curl -fsSL --retry 2 -m 300 "$url" -o "$out" 2>/dev/null || wget -q -T 60 "$url" -O "$out"
}

verify_sha256(){
    local file=$1 expect=$2
    [[ -n $expect && -f $file ]] && [[ $(sha256sum "$file" | awk '{print $1}') == "$expect" ]]
}

asset_url(){
    case $1 in
        acme.sh) echo "$REPO_URL/assets/$1" ;;
        *) echo "$RELEASE_URL/$1" ;;
    esac
}

# 优先使用本地 assets (脚本目录或 $SHARE_DIR)，否则下载 (acme.sh 来自仓库，caddy 来自 Releases)
# 均需通过 SHA256 校验；下载成功后缓存到 $SHARE_DIR/assets
fetch_asset(){
    local name=$1 out=$2 expect dir url
    expect=${ASSET_SHA256[$name]}
    [[ -n $expect ]] || { red "未知的依赖包: $name"; return 1; }

    for dir in "${ASSET_DIRS[@]}"; do
        if verify_sha256 "$dir/$name" "$expect"; then
            blue "使用本地依赖包: $dir/$name"
            cp -f "$dir/$name" "$out" && return 0
        elif [[ -f $dir/$name ]]; then
            yellow "本地依赖包 $dir/$name 校验失败，已忽略"
        fi
    done

    url=$(asset_url "$name")
    yellow "正在下载 $url ..."
    download "$url" "$out" || { red "下载失败: $url"; rm -f "$out"; return 1; }
    if ! verify_sha256 "$out" "$expect"; then
        red "下载的 $name SHA256 校验失败，已终止 (若使用自己的仓库，需同步更新脚本内的 ASSET_SHA256)"
        rm -f "$out"
        return 1
    fi
    if mkdir -p "$SHARE_DIR/assets" 2>/dev/null; then
        cp -f "$out" "$SHARE_DIR/assets/$name" 2>/dev/null || true
    fi
}

#===============================================================================
# 安装 Caddy2-Naiveproxy
#===============================================================================
install_caddy(){
    green "\n===== 安装 Caddy2-Naiveproxy ====="
    yellow "请选择安装方式:"
    yellow "1. 使用预编译版本 (快速，推荐，${BUNDLED_CADDY_VERSION})"
    yellow "2. 在线编译版本 (慢，自动构建最新内核)"
    readp "请选择 [1/2] (默认1):" chcaddy

    if [[ -z $chcaddy || $chcaddy == "1" ]]; then
        install_caddy_prebuilt
    elif [[ $chcaddy == "2" ]]; then
        install_caddy_build
    else
        red "输入错误"
        return 1
    fi
}

install_caddy_prebuilt(){
    local tmpdir
    tmpdir=$(mktemp -d) || return 1
    if ! fetch_asset "caddy2-naive-linux-${cpu}.tar.gz" "$tmpdir/caddy.tar.gz"; then
        rm -rf "$tmpdir"
        return 1
    fi
    if ! tar -zxf "$tmpdir/caddy.tar.gz" -C "$tmpdir" caddy || [[ ! -f $tmpdir/caddy ]]; then
        red "解压 Caddy 失败"
        rm -rf "$tmpdir"
        return 1
    fi
    chmod 755 "$tmpdir/caddy"
    # rename 替换，避免覆盖正在运行的二进制
    mv -f "$tmpdir/caddy" "$BINARY" || { rm -rf "$tmpdir"; return 1; }
    rm -rf "$tmpdir"
    record_caddy_version
    green "Caddy 安装完成: $(installed_caddy_version)"
}

record_caddy_version(){
    mkdir -p "${CADDY_VERSION_FILE%/*}"
    installed_caddy_version > "$CADDY_VERSION_FILE" 2>/dev/null || true
}

#===============================================================================
# Go 环境 (在线编译用)
# 发行版源中的 golang 通常过旧，统一安装官方版本并开启 GOTOOLCHAIN=auto
#===============================================================================
go_minor_version(){
    command -v go &>/dev/null || return 1
    go env GOVERSION 2>/dev/null | sed -n 's/^go1\.\([0-9]\+\).*/\1/p'
}

install_go_official(){
    local base ver json sha tmpdir file
    for base in https://go.dev/dl https://golang.google.cn/dl; do
        json=$(curl -fsSL -m 20 "${base}/?mode=json" 2>/dev/null) || continue
        ver=$(echo "$json" | grep -o '"version": *"go[0-9.]*"' | head -n 1 | grep -o 'go[0-9.]*')
        [[ -n $ver ]] && break
    done
    [[ -n $ver ]] || { red "无法获取 Go 最新版本信息"; return 1; }

    file="${ver}.linux-${cpu}.tar.gz"
    sha=$(echo "$json" | tr -d '\n ' | grep -o "\"filename\":\"${file}\"[^}]*" | grep -o '"sha256":"[0-9a-f]*"' | cut -d'"' -f4)
    [[ -n $sha ]] || { red "无法获取 $file 的 SHA256"; return 1; }

    yellow "正在下载官方 Go: $file ..."
    tmpdir=$(mktemp -d) || return 1
    if ! download "https://dl.google.com/go/${file}" "$tmpdir/go.tar.gz" || ! verify_sha256 "$tmpdir/go.tar.gz" "$sha"; then
        red "Go 下载失败或校验不通过"
        rm -rf "$tmpdir"
        return 1
    fi
    rm -rf /usr/local/go && tar -C /usr/local -xzf "$tmpdir/go.tar.gz"
    local ret=$?
    rm -rf "$tmpdir"
    [[ $ret -eq 0 ]] || return 1

    # shellcheck disable=SC2016 # $PATH 需在登录时展开
    echo 'export PATH=/usr/local/go/bin:$PATH' > /etc/profile.d/naiveproxy-go.sh
    export PATH="/usr/local/go/bin:$PATH"
}

ensure_go(){
    [[ -x /usr/local/go/bin/go ]] && export PATH="/usr/local/go/bin:$PATH"
    local minor
    minor=$(go_minor_version)
    if [[ -z $minor || $minor -lt $GO_MIN_MINOR ]]; then
        yellow "未找到 Go 或版本低于 1.${GO_MIN_MINOR}，安装官方 Go..."
        install_go_official || return 1
    fi
    export GOTOOLCHAIN=auto GO111MODULE=on
    if ! curl -fsS -m 5 -o /dev/null https://proxy.golang.org 2>/dev/null; then
        export GOPROXY=https://goproxy.cn,direct
    fi
    green "Go 环境: $(go version)"
}

install_caddy_build(){
    yellow "开始在线编译..."
    local total_mem swapfile="/var/naiveproxy-build.swap" swap_created=0
    total_mem=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}')
    if [[ ${total_mem:-0} -gt 0 && $total_mem -lt 1500 ]]; then
        yellow "当前物理内存仅 ${total_mem}MB，临时配置 2GB Swap 防止编译时 OOM..."
        if fallocate -l 2G "$swapfile" 2>/dev/null || dd if=/dev/zero of="$swapfile" bs=1M count=2048 2>/dev/null; then
            chmod 600 "$swapfile"
            if mkswap "$swapfile" >/dev/null 2>&1 && swapon "$swapfile" 2>/dev/null; then
                swap_created=1
            else
                yellow "Swap 启用失败，继续尝试编译"
                rm -f "$swapfile"
            fi
        fi
    fi

    local tmpdir ret=1
    if ensure_go && go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest; then
        local xcaddy_bin
        xcaddy_bin="$(go env GOPATH)/bin/xcaddy"
        tmpdir=$(mktemp -d)
        if "$xcaddy_bin" build --output "$tmpdir/caddy" \
            --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive \
            && "$tmpdir/caddy" list-modules 2>/dev/null | grep -q '^http.handlers.forward_proxy$'; then
            mv -f "$tmpdir/caddy" "$BINARY" && ret=0
        fi
        rm -rf "$tmpdir"
    fi

    if [[ $swap_created -eq 1 ]]; then
        swapoff "$swapfile" 2>/dev/null || true
        rm -f "$swapfile"
    fi

    if [[ $ret -eq 0 ]]; then
        record_caddy_version
        green "在线编译安装完成: $(installed_caddy_version)"
    else
        red "编译失败"
        return 1
    fi
}

#===============================================================================
# 安装 systemd 服务
#===============================================================================
write_service_file(){
    mkdir -p "${SERVICEFILE%/*}" || return 1
    cat > "$SERVICEFILE" <<EOF
[Unit]
Description=NaiveProxy Multi-User Service
Documentation=https://github.com/klzgrad/naiveproxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BINARY run --config $CADDYFILE --adapter caddyfile
# --force: 配置未变时也重新加载 (续期后需重新读取证书文件)
ExecReload=$BINARY reload --force --config $CADDYFILE --adapter caddyfile
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

install_service(){
    green "\n===== 安装服务 ====="
    write_service_file || return 1
    systemctl enable naiveproxy >/dev/null 2>&1 || return 1
    green "服务安装完成"
}

# 旧版服务单元的 reload 不带 --force，续期后不会加载新证书
upgrade_service_file(){
    [[ -f $SERVICEFILE ]] || return 0
    if ! grep -q 'reload --force' "$SERVICEFILE" || grep -q '^Requires=network-online.target' "$SERVICEFILE"; then
        write_service_file >/dev/null 2>&1 || true
    fi
}

#===============================================================================
# 端口冲突检测 (TCP 与 UDP；忽略 naiveproxy 自身)
#===============================================================================
check_port(){
    local port=$1 self_pid
    self_pid=$(systemctl show -p MainPID --value naiveproxy 2>/dev/null)
    [[ $self_pid =~ ^[1-9][0-9]*$ ]] || self_pid=""
    ss -Htulnp 2>/dev/null | awk -v port="$port" -v self="$self_pid" '
        {
            n = split($5, a, ":")
            if (a[n] != port) next
            if (self != "" && $0 ~ ("pid=" self ",")) next
            found = 1
        }
        END { exit found ? 1 : 0 }'
}

#===============================================================================
# 用户与域名输入 (一键安装与菜单共用同一套校验)
#===============================================================================
prompt_user_pass(){
    readp "请输入用户名（3-32位字母数字下划线，回车随机生成）:" NEW_USER
    if [[ -z $NEW_USER ]]; then
        NEW_USER=$(gen_random 'a-z0-9' 6)
        blue "随机生成用户名: $NEW_USER"
    fi
    valid_user "$NEW_USER" || { red "用户名不合法，必须由 3-32 位字母、数字或下划线组成"; return 1; }

    readp "请输入密码（5-64位，限字母数字及 . _ ~ -，回车随机生成）:" NEW_PASS
    if [[ -z $NEW_PASS ]]; then
        NEW_PASS=$(gen_random 'a-zA-Z0-9' 16)
        blue "随机生成密码: $NEW_PASS"
    fi
    valid_pass "$NEW_PASS" || { red "密码不合法（5-64位，仅限字母、数字及 . _ ~ -）"; return 1; }
}

prompt_domain_backend(){
    readp "请输入解析到本 VPS 的域名（如 proxy.example.com）:" NEW_DOMAIN
    NEW_DOMAIN="${NEW_DOMAIN,,}"
    [[ -z $NEW_DOMAIN ]] && { red "域名不能为空"; return 1; }
    valid_domain "$NEW_DOMAIN" || { red "域名格式错误"; return 1; }

    readp "请输入反代伪装网址（回车默认 speed.cloudflare.com）:" NEW_BACKEND
    [[ -z $NEW_BACKEND ]] && NEW_BACKEND="speed.cloudflare.com"
    NEW_BACKEND=$(normalize_backend "$NEW_BACKEND")
    valid_backend "$NEW_BACKEND" || { red "伪装网址格式错误，应为 域名[:端口]"; return 1; }
}

#===============================================================================
# 用户管理
#===============================================================================
add_user(){
    echo
    yellow "===== 添加用户 ====="
    prompt_user_pass || return 1
    [[ -n ${USER_PASS[$NEW_USER]} ]] && yellow "用户 $NEW_USER 已存在，本次操作将修改其密码"

    readp "请输入邮箱（可选，回车跳过）:" email
    if [[ -n $email ]] && ! valid_email "$email"; then
        red "邮箱格式错误"
        return 1
    fi

    USER_PASS[$NEW_USER]=$NEW_PASS
    [[ -n $email ]] && USER_EMAIL[$NEW_USER]=$email
    save_users || return 1
    green "用户 $NEW_USER 保存成功"
    yellow "提示: 增删用户后请执行【12】生成配置并重启以生效！"
}

del_user(){
    echo
    yellow "===== 删除用户 ====="
    list_users
    [[ ${#USER_PASS[@]} -eq 0 ]] && return 0

    readp "请输入要删除的用户名:" user
    [[ -z $user ]] && { red "用户名不能为空"; return 1; }
    [[ -z ${USER_PASS[$user]} ]] && { red "用户 $user 不存在"; return 1; }

    readp "确认删除用户 $user ？(输入y确认):" confirm
    [[ $confirm != y && $confirm != Y ]] && { blue "已取消"; return 0; }

    unset 'USER_PASS[$user]' 'USER_EMAIL[$user]'
    save_users || return 1
    green "用户 $user 已删除"
    yellow "提示: 请执行【12】生成配置并重启以使变更生效！"
}

list_users(){
    echo
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        yellow "暂无用户"
        return 0
    fi
    green "─────────── 用户列表 ───────────"
    local u
    while IFS= read -r u; do
        blue "用户: $u  密码: ${USER_PASS[$u]}  邮箱: ${USER_EMAIL[$u]:-未设置}"
    done < <(sorted_users)
    green "────────────────────────────────"
}

#===============================================================================
# 域名管理
#===============================================================================
add_domain(){
    echo
    yellow "===== 添加域名 ====="
    prompt_domain_backend || return 1

    DOMAIN_BACKEND[$NEW_DOMAIN]=$NEW_BACKEND
    DOMAIN_CERT[$NEW_DOMAIN]="${DOMAIN_CERT[$NEW_DOMAIN]:-}"
    DOMAIN_KEY[$NEW_DOMAIN]="${DOMAIN_KEY[$NEW_DOMAIN]:-}"
    save_domains || return 1
    green "域名 $NEW_DOMAIN 添加成功（反代伪装: https://$NEW_BACKEND）"
    yellow "请选择【11】申请或配置该域名的 TLS 证书"
}

del_domain(){
    echo
    yellow "===== 删除域名 ====="
    list_domains
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && return 0

    readp "请输入要删除的域名:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]} ]] && { red "域名 $domain 不存在"; return 1; }

    readp "确认删除域名 $domain ？(输入y确认):" confirm
    [[ $confirm != y && $confirm != Y ]] && { blue "已取消"; return 0; }

    unset 'DOMAIN_BACKEND[$domain]' 'DOMAIN_CERT[$domain]' 'DOMAIN_KEY[$domain]'
    save_domains || return 1
    green "域名 $domain 已删除"
    yellow "提示: 请执行【12】生成配置并重启以生效！"
}

get_cert_status_desc(){
    local c_file="$1" end_date exp_epoch days_left
    if [[ -z $c_file || ! -f $c_file ]]; then
        echo -e "${red}未申请${plain}"
        return
    fi
    end_date=$(openssl x509 -enddate -noout -in "$c_file" 2>/dev/null | cut -d= -f2)
    exp_epoch=$(date -d "$end_date" +%s 2>/dev/null)
    if [[ -z $end_date || -z $exp_epoch ]]; then
        echo -e "${green}已配置${plain}"
        return
    fi
    days_left=$(( (exp_epoch - $(date +%s)) / 86400 ))
    if [[ $days_left -lt 0 ]]; then
        echo -e "${red}已过期 (失效 $(( -days_left )) 天)${plain}"
    elif [[ $days_left -le 30 ]]; then
        echo -e "${yellow}即将到期 (剩余 ${days_left} 天，待自动续期)${plain}"
    else
        echo -e "${green}有效 (剩余 ${days_left} 天)${plain}"
    fi
}

list_domains(){
    echo
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        yellow "暂无域名"
        return 0
    fi
    green "─────────── 域名列表 ───────────"
    local d
    while IFS= read -r d; do
        echo -e "  ${blue}域名:${plain} $d  ${blue}反代后端:${plain} ${DOMAIN_BACKEND[$d]}  ${blue}证书状态:${plain} $(get_cert_status_desc "${DOMAIN_CERT[$d]}")"
    done < <(sorted_domains)
    green "────────────────────────────────"
}

#===============================================================================
# acme.sh Standalone 签发/续期钩子
# pre: 仅停止实际占用 80 端口的 Web 服务并记录；post: 只恢复被停止的服务
#===============================================================================
write_acme_hook(){
    mkdir -p "$CONFIG_DIR"
    cat > "$ACME_HOOK" <<'EOF'
#!/bin/sh
# 由 naiveproxy.sh 生成：acme.sh standalone 模式需要临时空出 80 端口
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
STATE=/run/naiveproxy-acme-stopped
case "$1" in
    pre)
        : > "$STATE"
        pids=$(ss -Htlnp 'sport = :80' 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
        [ -z "$pids" ] && exit 0
        for svc in nginx apache2 httpd caddy naiveproxy; do
            systemctl is-active --quiet "$svc" 2>/dev/null || continue
            main=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)
            for p in $pids; do
                ppid=$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null)
                if [ "$p" = "$main" ] || [ "$ppid" = "$main" ]; then
                    systemctl stop "$svc" && echo "$svc" >> "$STATE"
                    break
                fi
            done
        done
        ;;
    post)
        if [ -f "$STATE" ]; then
            while read -r svc; do
                [ -n "$svc" ] && systemctl start "$svc"
            done < "$STATE"
            rm -f "$STATE"
        fi
        ;;
esac
exit 0
EOF
    chmod 700 "$ACME_HOOK"
}

#===============================================================================
# acme.sh 域名配置读写 (格式与 acme.sh 的 _save_conf/_read_conf 一致)
#===============================================================================
acme_domain_conf(){
    local d=$1
    if [[ -f $ACME_HOME/$d/$d.conf ]]; then
        echo "$ACME_HOME/$d/$d.conf"
    elif [[ -f $ACME_HOME/${d}_ecc/$d.conf ]]; then
        echo "$ACME_HOME/${d}_ecc/$d.conf"
    else
        return 1
    fi
}

acme_conf_get(){
    local conf=$1 key=$2 v
    v=$(grep "^${key}=" "$conf" 2>/dev/null | tail -n 1)
    v=${v#*=}
    v=${v#\'}
    v=${v%\'}
    if [[ $v == __ACME_BASE64__START_*__ACME_BASE64__END_ ]]; then
        v=${v#__ACME_BASE64__START_}
        v=${v%__ACME_BASE64__END_}
        v=$(echo "$v" | base64 -d 2>/dev/null)
    fi
    printf '%s' "$v"
}

acme_conf_set(){
    local conf=$1 key=$2 val=$3 b64=$4 tmp
    [[ -n $b64 ]] && val="__ACME_BASE64__START_$(printf '%s' "$val" | base64 -w0)__ACME_BASE64__END_"
    tmp=$(mktemp "${conf}.XXXXXX") || return 1
    awk -v k="$key" -v line="${key}='${val}'" '
        index($0, k "=") == 1 { if (!done) print line; done = 1; next }
        { print }
        END { if (!done) print line }' "$conf" > "$tmp" && mv -f "$tmp" "$conf"
}

#===============================================================================
# 自动检测并修复 Crontab 任务与证书自动续期钩子 (不联网、不重启服务)
#===============================================================================
fix_acme_cron_and_hooks(){
    [[ -x $ACME_BIN ]] || return 0
    write_acme_hook

    if command -v crontab &>/dev/null; then
        systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
        # 清洗旧版本在用户级 crontab 中误写 root 用户名字段的任务
        if crontab -l 2>/dev/null | grep -E -q "root[[:space:]]+(bash[[:space:]]+)?.*acme\.sh"; then
            yellow "检测到历史 crontab 包含错误语法，正在自动清理修复..."
            crontab -l 2>/dev/null | grep -E -v "root[[:space:]]+(bash[[:space:]]+)?.*acme\.sh" | crontab - 2>/dev/null || true
        fi
        if ! crontab -l 2>/dev/null | grep -q "acme\.sh.*--cron"; then
            "$ACME_BIN" --install-cronjob >/dev/null 2>&1 || true
        fi
    fi

    # 为已有域名补齐/更新续期配置：证书安装路径、重载命令、standalone 前后钩子
    local d conf c_path k_path changed v
    for d in "${!DOMAIN_BACKEND[@]}"; do
        c_path=${DOMAIN_CERT[$d]}
        k_path=${DOMAIN_KEY[$d]}
        [[ -s $c_path && -s $k_path ]] || continue
        conf=$(acme_domain_conf "$d") || continue
        # 证书来自其他位置 (手动指定) 时不接管
        v=$(acme_conf_get "$conf" Le_RealFullChainPath)
        [[ -n $v && $v != "$c_path" ]] && continue

        changed=0
        if [[ -z $v ]]; then
            acme_conf_set "$conf" Le_RealFullChainPath "$c_path" && acme_conf_set "$conf" Le_RealKeyPath "$k_path" && changed=1
        fi
        if [[ $(acme_conf_get "$conf" Le_ReloadCmd) != "$ACME_RELOAD_CMD" ]]; then
            acme_conf_set "$conf" Le_ReloadCmd "$ACME_RELOAD_CMD" base64 && changed=1
        fi
        if [[ $(acme_conf_get "$conf" Le_Webroot) == no ]]; then
            if [[ $(acme_conf_get "$conf" Le_PreHook) != "$ACME_HOOK pre" ]]; then
                acme_conf_set "$conf" Le_PreHook "$ACME_HOOK pre" base64 && changed=1
            fi
            if [[ $(acme_conf_get "$conf" Le_PostHook) != "$ACME_HOOK post" ]]; then
                acme_conf_set "$conf" Le_PostHook "$ACME_HOOK post" base64 && changed=1
            fi
        fi
        [[ $changed -eq 1 ]] && yellow "已更新域名 $d 的证书自动续期配置"
    done
    return 0
}

#===============================================================================
# acme.sh 安装与签发
#===============================================================================
ensure_acme(){
    local email="$1" tmpdir

    if [[ ! -f $ACME_BIN ]]; then
        command -v crontab &>/dev/null || { red "缺少 crontab，无法配置证书自动续期，请先安装 cron/cronie"; return 1; }
        yellow "正在安装 acme.sh 证书工具..."
        tmpdir=$(mktemp -d) || return 1
        if ! fetch_asset acme.sh "$tmpdir/acme.sh"; then
            rm -rf "$tmpdir"
            return 1
        fi
        chmod 700 "$tmpdir/acme.sh"
        (cd "$tmpdir" && ./acme.sh --install -m "$email" --home "$ACME_HOME" --no-profile)
        local ret=$?
        rm -rf "$tmpdir"
        [[ $ret -eq 0 ]] || { red "acme.sh 安装失败"; return 1; }
    fi

    [[ -x $ACME_BIN ]] || chmod +x "$ACME_BIN" 2>/dev/null
    [[ -x $ACME_BIN ]] || { red "acme.sh 安装失败: $ACME_BIN 不存在或不可执行"; return 1; }
    "$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
    fix_acme_cron_and_hooks
}

# 返回 0 = 已签发或证书仍有效
issue_cert_standalone(){
    local domain="$1" email="$2" force=() ret

    ensure_acme "$email" || return 1
    open_port 80 tcp

    if acme_domain_conf "$domain" >/dev/null; then
        readp "acme.sh 中已有 $domain 的证书，是否强制重新签发？(y/N):" yn
        [[ $yn == y || $yn == Y ]] && force=(--force)
    fi

    yellow "使用 Standalone 模式通过 Let's Encrypt 申请证书..."
    "$ACME_BIN" --issue --server letsencrypt -d "$domain" --standalone -k 2048 "${force[@]}" \
        --pre-hook "$ACME_HOOK pre" --post-hook "$ACME_HOOK post"
    ret=$?
    if [[ $ret -eq 2 ]]; then
        blue "证书仍在有效期内，跳过签发，直接安装现有证书"
        return 0
    fi
    return $ret
}

#===============================================================================
# 申请或配置证书
# 参数: [域名] [norestart]；一键安装时传入域名并由调用方负责生成配置与启动
#===============================================================================
apply_cert(){
    local domain=$1 norestart=$2
    echo
    yellow "===== 申请 / 配置证书 ====="
    if [[ -z $domain ]]; then
        list_domains
        [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { red "请先添加域名"; return 1; }
        readp "请输入要配置证书的域名:" domain
    fi
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]} ]] && { red "域名 $domain 未添加，请先在菜单【8】中添加"; return 1; }
    valid_domain "$domain" || { red "域名 $domain 格式不合法，请删除后重新添加"; return 1; }

    echo
    yellow "请选择证书来源:"
    yellow "1. acme.sh 自动申请并安装 (带自动续期钩子，推荐)"
    yellow "2. 手动指定现有证书路径 (自定义 crt 与 key)"
    readp "请选择 [1/2] (默认1):" ctype

    local cert_dir="$CONFIG_DIR/certs/$domain"
    local cert_path="$cert_dir/cert.crt"
    local key_path="$cert_dir/private.key"
    mkdir -p "$cert_dir" && chmod 700 "$cert_dir"

    if [[ -z $ctype || $ctype == "1" ]]; then
        readp "请输入申请通知邮箱（回车默认 admin@$domain）:" email
        [[ -z $email ]] && email="admin@${domain}"
        valid_email "$email" || { red "邮箱格式错误"; return 1; }

        green "正在为域名 $domain 申请证书..."
        if ! issue_cert_standalone "$domain" "$email"; then
            red "证书申请失败，请排查："
            yellow "1. 域名 DNS 是否已准确解析到本服务器公网 IP"
            yellow "2. 本机及云服务商安全组 80 端口是否完全放行"
            yellow "3. 检查是否达到 Let's Encrypt 频率限制"
            return 1
        fi

        # install-cert 记录安装路径与重载命令，续期后自动复制证书并重启服务
        if ! "$ACME_BIN" --install-cert -d "$domain" \
            --key-file "$key_path" \
            --fullchain-file "$cert_path" \
            --reloadcmd "$ACME_RELOAD_CMD"; then
            red "acme.sh install-cert 执行失败，证书未安装"
            return 1
        fi
        green "已注册 acme.sh 自动续期与服务重启钩子"
    elif [[ $ctype == "2" ]]; then
        readp "请输入证书公钥文件路径 (如 /root/cert.crt):" user_cert
        readp "请输入证书私钥文件路径 (如 /root/private.key):" user_key
        [[ ! -f $user_cert ]] && { red "证书文件 $user_cert 不存在"; return 1; }
        [[ ! -f $user_key ]] && { red "私钥文件 $user_key 不存在"; return 1; }
        openssl x509 -noout -in "$user_cert" 2>/dev/null || { red "$user_cert 不是有效的 PEM 证书"; return 1; }
        cp -f "$user_cert" "$cert_path" || return 1
        cp -f "$user_key" "$key_path" || return 1
        yellow "提示: 手动指定的证书不会自动续期，到期前请重新配置"
    else
        red "输入错误"
        return 1
    fi

    chmod 600 "$key_path" 2>/dev/null || true
    chmod 644 "$cert_path" 2>/dev/null || true
    if [[ ! -s $cert_path || ! -s $key_path ]]; then
        red "证书写入失败，证书文件大小异常"
        return 1
    fi

    DOMAIN_CERT[$domain]=$cert_path
    DOMAIN_KEY[$domain]=$key_path
    save_domains || return 1
    green "证书配置成功: $cert_path"

    [[ $norestart == norestart ]] && return 0
    if [[ -f $SERVICEFILE ]]; then
        if generate_caddyfile && restart_service; then
            green "新证书已生效"
        else
            red "配置生成或服务重启失败，请检查上方错误信息"
            return 1
        fi
    fi
}

#===============================================================================
# 生成 Caddyfile 配置
# 先写临时文件并校验，通过后再替换正式配置；失败时原配置保持不变
#===============================================================================
generate_caddyfile(){
    green "\n===== 生成 Caddyfile 配置 ====="
    load_config

    local users=() domains=() u d p
    mapfile -t users < <(usable_users)
    mapfile -t domains < <(usable_domains)

    while IFS= read -r u; do
        [[ " ${users[*]} " == *" $u "* ]] || yellow "跳过用户 $u (用户名或密码含有无法写入配置的字符，请重新设置)"
    done < <(sorted_users)
    while IFS= read -r d; do
        [[ " ${domains[*]} " == *" $d "* ]] || yellow "跳过域名 $d (证书未配置或域名/后端格式不合法)"
    done < <(sorted_domains)

    [[ ${#users[@]} -eq 0 ]] && { red "请先添加至少一个有效用户"; return 1; }
    [[ ${#domains[@]} -eq 0 ]] && { red "无可用已配置证书的域名，无法生成配置"; return 1; }
    [[ ${#PROXY_PORTS[@]} -eq 0 ]] && PROXY_PORTS=(443)

    local tmp
    tmp=$(mktemp "${CADDYFILE}.XXXXXX") || return 1
    {
        echo "{"
        echo "    order forward_proxy before reverse_proxy"
        echo "    http_port ${1:-80}"
        echo "    https_port ${PROXY_PORTS[0]}"
        echo "    auto_https off"
        echo "}"
        echo
        for d in "${domains[@]}"; do
            local headers=""
            for p in "${PROXY_PORTS[@]}"; do headers+="${d}:${p}, "; done
            echo "${headers%, } {"
            echo "    tls ${DOMAIN_CERT[$d]} ${DOMAIN_KEY[$d]}"
            echo "    forward_proxy {"
            for u in "${users[@]}"; do
                echo "        basic_auth ${u} ${USER_PASS[$u]}"
            done
            echo "        hide_ip"
            echo "        hide_via"
            echo "        probe_resistance"
            echo "    }"
            echo "    reverse_proxy https://${DOMAIN_BACKEND[$d]} {"
            echo "        header_up Host {upstream_hostport}"
            echo "    }"
            echo "}"
            echo
        done
    } > "$tmp"
    chmod 600 "$tmp"

    if [[ -x $BINARY ]]; then
        local out
        if ! out=$("$BINARY" validate --config "$tmp" --adapter caddyfile 2>&1); then
            red "错误: Caddyfile 校验失败，原配置未改动"
            echo "$out" | grep -v '"level":"info"' | tail -n 15
            rm -f "$tmp"
            return 1
        fi
    else
        yellow "未找到 $BINARY，跳过配置校验"
    fi

    [[ -f $CADDYFILE ]] && cp -f "$CADDYFILE" "$BACKUP_CADDYFILE" && chmod 600 "$BACKUP_CADDYFILE"
    mv -f "$tmp" "$CADDYFILE" || { rm -f "$tmp"; return 1; }
    green "Caddyfile 生成完成并通过语法校验: $CADDYFILE"
}

#===============================================================================
# 服务控制
#===============================================================================
suss_service(){
    systemctl restart naiveproxy
    sleep 2
    if systemctl is-active --quiet naiveproxy && [[ -f $CADDYFILE ]]; then
        green "NaiveProxy 服务启动成功"
        return 0
    fi
    red "NaiveProxy 服务启动失败"
    journalctl -u naiveproxy -n 20 --no-pager -e
    return 1
}

restart_service(){
    green "\n===== 重启服务 ====="
    systemctl daemon-reload
    suss_service
}

generate_and_restart(){
    generate_caddyfile || return 1
    restart_service || return 1
    show_share
}

start_service(){
    green "启动服务..."
    [[ -f $SERVICEFILE ]] || install_service || return 1
    systemctl start naiveproxy || { red "启动失败"; return 1; }
    green "服务已启动"
}

stop_service(){
    green "停止服务..."
    if systemctl stop naiveproxy; then
        green "服务已停止"
    else
        red "停止失败"
        return 1
    fi
}

#===============================================================================
# 显示分享信息
#===============================================================================
show_share(){
    if ! systemctl is-active --quiet naiveproxy || [[ ! -f $CADDYFILE ]]; then
        red "NaiveProxy 未正常运行，请先确认服务已启动" && return 1
    fi
    load_config

    echo
    red "======================================================================================"
    green "                         NaiveProxy 节点分享信息"
    red "======================================================================================"
    echo
    green "当前监听端口："
    blue "${PROXY_PORTS[*]}"

    local users=() domains=() u d p url userinfo fname
    mapfile -t users < <(usable_users)
    mapfile -t domains < <(usable_domains)
    if [[ ${#domains[@]} -eq 0 || ${#users[@]} -eq 0 ]]; then
        yellow "暂无可用的用户或已配置证书的域名"
        return 0
    fi

    local primary_domain="${domains[0]}"
    local primary_port="${PROXY_PORTS[0]:-443}"
    local url_file="$NAIVE_DIR/URL.txt"
    mkdir -p "$NAIVE_DIR"
    : > "$url_file"
    chmod 600 "$url_file"

    echo
    green "V2rayN 客户端配置 (已按用户分别保存至 $NAIVE_DIR/)："
    for u in "${users[@]}"; do
        userinfo="$(urlencode "$u"):$(urlencode "${USER_PASS[$u]}")"
        fname="${u//[^A-Za-z0-9_-]/_}"
        cat > "$NAIVE_DIR/v2rayn_${fname}.json" <<EOF
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://${userinfo}@${primary_domain}:${primary_port}"
}
EOF
        chmod 600 "$NAIVE_DIR/v2rayn_${fname}.json"
        echo -e "${yellow}--- 用户: $u (配置: $NAIVE_DIR/v2rayn_${fname}.json) ---${plain}"
        cat "$NAIVE_DIR/v2rayn_${fname}.json"
        echo
    done
    # 兼容原版 v2rayn.json (按字典序第一个用户)
    cp -f "$NAIVE_DIR/v2rayn_${users[0]//[^A-Za-z0-9_-]/_}.json" "$NAIVE_DIR/v2rayn.json"

    green "NaiveProxy 节点分享链接 (已写入 $url_file)："
    for u in "${users[@]}"; do
        userinfo="$(urlencode "$u"):$(urlencode "${USER_PASS[$u]}")"
        for d in "${domains[@]}"; do
            for p in "${PROXY_PORTS[@]}"; do
                url="naive+https://${userinfo}@${d}:${p}?padding=true#NaiveProxy-$(urlencode "$u")-${p}"
                echo "$url" >> "$url_file"
                yellow "$url"
            done
        done
    done
    if [[ ${#users[@]} -lt ${#USER_PASS[@]} ]]; then
        yellow "部分用户因用户名或密码含特殊字符未生成链接，请通过【5】重新设置密码"
    fi

    if command -v qrencode &>/dev/null; then
        echo
        green "二维码分享 (首个节点)："
        qrencode -o - -t ANSIUTF8 "$(head -n 1 "$url_file")"
        blue "提示: 全部节点链接已保存于 $url_file，可直接导入支持 Naive 协议的客户端"
    fi
    red "======================================================================================"
}

#===============================================================================
# 显示状态
#===============================================================================
show_status(){
    echo
    red "======================================================================================"
    green "                         NaiveProxy 运行与系统状态"
    red "======================================================================================"
    load_config

    local service_status="${red}未安装${plain}"
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        service_status="${green}运行中${plain}"
    elif [[ -f $SERVICEFILE ]]; then
        service_status="${yellow}已安装 (未运行)${plain}"
    fi
    echo -e "服务状态: $service_status  内核版本: ${blue}$(installed_caddy_version || echo 未安装)${plain}"

    echo ""
    echo -e "${bblue}─────────────────── 监听端口 ───────────────────${plain}"
    echo -e "  配置端口: ${green}${PROXY_PORTS[*]}${plain}"
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        ss -tunlp 2>/dev/null | grep caddy | awk '{print "  实际监听: " $1 " " $5}' | sort -u
    fi

    echo ""
    echo -e "${bblue}─────────────────── 用户列表 ───────────────────${plain}"
    local u d
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        echo -e "  ${yellow}暂无用户${plain}"
    else
        while IFS= read -r u; do
            echo -e "  ${green}用户:${plain} $u  ${green}密码:${plain} ${USER_PASS[$u]}  ${green}邮箱:${plain} ${USER_EMAIL[$u]:-未设置}"
        done < <(sorted_users)
    fi

    echo ""
    echo -e "${bblue}─────────────────── 域名列表 ───────────────────${plain}"
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        echo -e "  ${yellow}暂无域名${plain}"
    else
        while IFS= read -r d; do
            echo -e "  ${green}域名:${plain} $d  ${green}伪装后端:${plain} ${DOMAIN_BACKEND[$d]}  ${green}证书状态:${plain} $(get_cert_status_desc "${DOMAIN_CERT[$d]}")"
        done < <(sorted_domains)
    fi

    echo ""
    echo -e "${bblue}─────────────────── VPS 状态 ───────────────────${plain}"
    refresh_bbr_status
    echo -e "  ${green}系统:${plain} $op  ${green}内核:${plain} $kernel_version  ${green}架构:${plain} $cpu  ${green}虚拟化:${plain} $vi  ${green}BBR:${plain} $bbr"

    detect_ips
    warpcheck
    local w4="" w6=""
    [[ $wgcfv4 =~ on|plus ]] && w4="【WARP】"
    [[ $wgcfv6 =~ on|plus ]] && w6="【WARP】"
    echo -e "  ${green}IPv4:${plain} ${ipv4:-无} $w4  ${green}IPv6:${plain} ${ipv6:-无} $w6"
    red "======================================================================================"
}

#===============================================================================
# 多端口复用 (配置生成失败时回滚端口列表)
#===============================================================================
apply_ports_change(){
    local old_ports=("$@")
    save_ports || return 1
    if generate_caddyfile && restart_service; then
        show_share
        return 0
    fi
    red "端口变更未生效，已恢复为: ${old_ports[*]}"
    PROXY_PORTS=("${old_ports[@]}")
    save_ports
    generate_caddyfile >/dev/null && restart_service >/dev/null
    return 1
}

multi_port(){
    load_config
    local old_ports=("${PROXY_PORTS[@]}") p
    green "\n当前 NaiveProxy 代理正在监听的端口："
    blue "${PROXY_PORTS[*]}"

    echo
    readp "1. 添加新端口复用\n2. 删除已添加端口\n3. 恢复仅使用 443 端口\n0. 返回上层\n请选择 [0-3]:" choose

    if [[ $choose == "1" ]]; then
        readp "请输入要新增的端口 [1-65535]:" newport
        valid_port "$newport" || { red "端口格式错误，必须为 1-65535 的整数"; return 1; }
        [[ $newport == 80 ]] && { red "80 端口用于证书签发，不能作为代理端口"; return 1; }
        if [[ " ${PROXY_PORTS[*]} " == *" $newport "* ]]; then
            yellow "端口 $newport 已在监听列表中"
            return 0
        fi
        check_port "$newport" || { red "端口 $newport 已被系统其他进程占用"; return 1; }

        PROXY_PORTS+=("$newport")
        open_port "$newport" both
        apply_ports_change "${old_ports[@]}" || { close_port "$newport"; return 1; }
    elif [[ $choose == "2" ]]; then
        if [[ ${#PROXY_PORTS[@]} -le 1 ]]; then
            red "当前仅有 1 个端口 (${PROXY_PORTS[0]})，无法继续删除"
            return 1
        fi
        readp "请输入要删除的端口号 (${PROXY_PORTS[*]}):" del_p
        [[ -z $del_p ]] && { blue "已取消"; return 0; }
        [[ " ${PROXY_PORTS[*]} " == *" $del_p "* ]] || { red "未找到端口 $del_p"; return 1; }
        local new_ports=()
        for p in "${PROXY_PORTS[@]}"; do
            [[ $p != "$del_p" ]] && new_ports+=("$p")
        done
        PROXY_PORTS=("${new_ports[@]}")
        apply_ports_change "${old_ports[@]}" && close_port "$del_p"
    elif [[ $choose == "3" ]]; then
        if [[ " ${PROXY_PORTS[*]} " != *" 443 "* ]]; then
            check_port 443 || { red "端口 443 已被系统其他进程占用"; return 1; }
        fi
        PROXY_PORTS=(443)
        open_port 443 both
        apply_ports_change "${old_ports[@]}" || return 1
        for p in "${old_ports[@]}"; do
            [[ $p != 443 ]] && close_port "$p"
        done
        return 0
    fi
}

#===============================================================================
# 快捷命令与脚本更新
#===============================================================================
validate_script(){
    local f=$1
    [[ -s $f ]] && head -n 1 "$f" | grep -q '^#!/bin/bash' && grep -q 'NaiveProxy' "$f" && bash -n "$f" 2>/dev/null
}

# 安装脚本到 $INSTALL_SCRIPT，并复制当前架构所需的依赖包到 $SHARE_DIR，供 na 运行时使用
install_shortcut(){
    mkdir -p "${INSTALL_SCRIPT%/*}" || return 1
    if [[ -n $SCRIPT_PATH && $SCRIPT_PATH != "$INSTALL_SCRIPT" ]]; then
        cp -f "$SCRIPT_PATH" "$INSTALL_SCRIPT" || return 1
    elif [[ ! -f $INSTALL_SCRIPT ]]; then
        local tmp
        tmp=$(mktemp) || return 1
        if ! download "$REPO_URL/naiveproxy.sh" "$tmp" || ! validate_script "$tmp"; then
            rm -f "$tmp"
            return 1
        fi
        mv -f "$tmp" "$INSTALL_SCRIPT" || return 1
    fi
    chmod 755 "$INSTALL_SCRIPT" || return 1
    ln -sfn "$INSTALL_SCRIPT" "$SHORTCUT" || return 1

    local name dir
    mkdir -p "$SHARE_DIR/assets"
    for name in acme.sh "caddy2-naive-linux-${cpu}.tar.gz"; do
        verify_sha256 "$SHARE_DIR/assets/$name" "${ASSET_SHA256[$name]}" && continue
        for dir in "${ASSET_DIRS[@]}"; do
            [[ $dir == "$SHARE_DIR/assets" ]] && continue
            if verify_sha256 "$dir/$name" "${ASSET_SHA256[$name]}"; then
                cp -f "$dir/$name" "$SHARE_DIR/assets/$name"
                break
            fi
        done
    done
    return 0
}

update_script(){
    green "\n===== 更新脚本 ====="
    yellow "正在从仓库获取最新脚本: $REPO_URL/naiveproxy.sh ..."
    mkdir -p "${INSTALL_SCRIPT%/*}" || return 1
    local tmp
    tmp=$(mktemp "${INSTALL_SCRIPT}.XXXXXX") || return 1
    if ! download "$REPO_URL/naiveproxy.sh" "$tmp"; then
        rm -f "$tmp"
        red "获取脚本更新失败，请检查网络或仓库地址设置"
        return 1
    fi
    if ! validate_script "$tmp"; then
        rm -f "$tmp"
        red "下载的文件校验失败，更新终止"
        return 1
    fi
    chmod 755 "$tmp"
    # 始终更新安装副本；rename 替换不影响当前正在执行的脚本
    mv -f "$tmp" "$INSTALL_SCRIPT" || { rm -f "$tmp"; return 1; }
    ln -sfn "$INSTALL_SCRIPT" "$SHORTCUT" || return 1
    green "脚本已更新至 $INSTALL_SCRIPT，请重新运行快捷命令 na。"
    if [[ -n $SCRIPT_PATH && $SCRIPT_PATH != "$INSTALL_SCRIPT" ]]; then
        yellow "当前运行的 $SCRIPT_PATH 未被修改 (如为 git 克隆目录，请使用 git pull 更新)"
    fi
    exit 0
}

update_kernel(){
    green "\n===== 更新内核 ====="
    install_caddy || return 1
    if systemctl is-active --quiet naiveproxy; then
        suss_service || return 1
    fi
    green "内核更新成功"
}

#===============================================================================
# 一键安装向导
#===============================================================================
quick_install(){
    if [[ -s $CADDYFILE ]]; then
        yellow "检测到已存在 NaiveProxy 配置，继续安装将重新初始化用户、域名与端口配置。"
        readp "是否继续全新安装？(y/n):" rein
        [[ $rein != y && $rein != Y ]] && { blue "已取消"; return 0; }
    fi

    check_deps auto || return 1
    ensure_nat64
    install_caddy || return 1
    install_service || return 1

    echo
    yellow "===== 配置首个用户 ====="
    prompt_user_pass || return 1
    USER_PASS=()
    USER_EMAIL=()
    USER_PASS[$NEW_USER]=$NEW_PASS
    save_users || return 1

    echo
    yellow "===== 配置首个域名 ====="
    prompt_domain_backend || return 1
    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    DOMAIN_BACKEND[$NEW_DOMAIN]=$NEW_BACKEND
    save_domains || return 1

    echo
    yellow "===== 设置监听端口 ====="
    readp "请输入主端口 [1-65535]（回车默认 443）:" port
    [[ -z $port ]] && port="443"
    valid_port "$port" || { red "端口格式不合法"; return 1; }
    [[ $port == 80 ]] && { red "80 端口用于证书签发，不能作为代理端口"; return 1; }
    check_port "$port" || { red "端口 $port 已被其他进程占用"; return 1; }
    PROXY_PORTS=("$port")
    save_ports || return 1

    openyn
    apply_cert "$NEW_DOMAIN" norestart || return 1
    generate_caddyfile 80 || return 1

    if suss_service; then
        install_shortcut || yellow "快捷命令 na 安装失败，可手动执行 bash $INSTALL_SCRIPT"
        show_share
    else
        return 1
    fi
}

#===============================================================================
# 卸载
#===============================================================================
uninstall(){
    echo
    yellow "===== 卸载 NaiveProxy ====="
    readp "确认完全卸载 NaiveProxy？(输入y确认):" confirm
    [[ $confirm != y && $confirm != Y ]] && { blue "已取消"; return 0; }

    systemctl stop naiveproxy 2>/dev/null || true
    systemctl disable naiveproxy 2>/dev/null || true
    rm -f "$SERVICEFILE"
    systemctl daemon-reload

    # 移除本脚本申请的证书续期任务，否则续期时会调用已删除的钩子
    local d
    if [[ -x $ACME_BIN ]]; then
        for d in "${!DOMAIN_BACKEND[@]}"; do
            valid_domain "$d" || continue
            [[ ${DOMAIN_CERT[$d]} == "$CONFIG_DIR/certs/$d/cert.crt" ]] || continue
            "$ACME_BIN" --remove -d "$d" >/dev/null 2>&1 || true
            rm -rf "${ACME_HOME:?}/$d" "${ACME_HOME:?}/${d}_ecc"
        done
        readp "是否同时卸载 acme.sh？(本机其他服务使用 acme.sh 管理证书时请选 n) (y/N):" rm_acme
        if [[ $rm_acme == y || $rm_acme == Y ]]; then
            "$ACME_BIN" --uninstall >/dev/null 2>&1 || true
            rm -rf "${ACME_HOME:?}"
        fi
    fi

    close_port
    remove_nat64

    rm -f "$BINARY" "$CADDY_VERSION_FILE" /etc/caddy/v
    rmdir /etc/caddy 2>/dev/null || true
    rm -rf "${CONFIG_DIR:?}" "${NAIVE_DIR:?}" "${SHARE_DIR:?}"
    rm -f "$SHORTCUT" "$INSTALL_SCRIPT" /root/naiveproxy.sh /etc/profile.d/naiveproxy-go.sh

    green "卸载完成！"
    if [[ -f $BBR_SYSCTL_FILE ]]; then
        blue "BBR 设置已保留，如需还原请删除 $BBR_SYSCTL_FILE 后重启"
    fi
    [[ -d /usr/local/go ]] && blue "在线编译安装的 Go 位于 /usr/local/go，如不再需要可手动删除"
    return 0
}

#===============================================================================
# 查看日志
#===============================================================================
view_log(){
    echo
    yellow "正在展示最近 50 行日志："
    journalctl -u naiveproxy -n 50 --no-pager
    echo
    readp "是否进入实时跟踪日志模式？(y/n，回车跳过，Ctrl+C 退出):" follow
    if [[ $follow == y || $follow == Y ]]; then
        journalctl -u naiveproxy -f
    fi
}

#===============================================================================
# 主菜单
#===============================================================================
main_menu(){
    while true; do
        load_config
        clear
        green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        echo -e "${bblue} ░██     ░██      ░██ ██ ██         ░█${plain}█   ░██     ░██   ░██     ░█${red}█   ░██${plain}  "
        echo -e "${bblue}  ░██   ░██      ░██    ░░██${plain}        ░██  ░██      ░██  ░██${red}      ░██  ░██${plain}   "
        echo -e "${bblue}   ░██ ░██      ░██ ${plain}                ░██ ██        ░██ █${red}█        ░██ ██  ${plain}   "
        echo -e "${bblue}     ░██        ░${plain}██    ░██ ██       ░██ ██        ░█${red}█ ██        ░██ ██  ${plain}  "
        echo -e "${bblue}     ░██ ${plain}        ░██    ░░██        ░██  ░██       ░${red}██ ░██       ░██ ░██ ${plain}  "
        echo -e "${bblue}     ░█${plain}█          ░██ ██ ██         ░██  ░░${red}██     ░██  ░░██     ░██  ░░██ ${plain}  "
        green "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        white "NaiveProxy 多用户/多域名 管理增强版 (修复版)"
        white "快捷命令: na"
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        green " 1. 一键安装 NaiveProxy"
        green " 2. 卸载 NaiveProxy"
        white "----------------------------------------------------------------------------------"
        green " 3. 安装/重构 Caddy2-Naiveproxy"
        green " 4. 安装/更新 systemd 服务"
        white "----------------------------------------------------------------------------------"
        green " 5. 添加用户"
        green " 6. 删除用户"
        green " 7. 用户列表"
        white "----------------------------------------------------------------------------------"
        green " 8. 添加域名"
        green " 9. 删除域名"
        green "10. 域名列表"
        green "11. 申请/配置证书 (带自动续期钩子)"
        white "----------------------------------------------------------------------------------"
        green "12. 生成配置并重启服务"
        green "13. 启动服务"
        green "14. 停止服务"
        green "15. 多端口复用管理 (新增/删除/还原)"
        white "----------------------------------------------------------------------------------"
        green "16. 查看运行状态"
        green "17. 查看节点分享信息 (多用户/多端口/二维码)"
        green "18. 查看服务日志"
        green "19. 更新脚本"
        green "20. 更新内核"
        green "21. 开启 BBR 拥塞控制"
        green " 0. 退出脚本"
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        echo -e "VPS状态: 系统:${blue}$op${plain} 内核:${blue}$kernel_version${plain} 架构:${blue}$cpu${plain} 虚拟化:${blue}$vi${plain} BBR:${blue}$bbr${plain}"
        if systemctl is-active --quiet naiveproxy 2>/dev/null && [[ -f $CADDYFILE ]]; then
            echo -e "NaiveProxy状态: ${green}运行中${plain} (监听端口: ${blue}${PROXY_PORTS[*]}${plain})"
        elif [[ -f $CADDYFILE ]]; then
            echo -e "NaiveProxy状态: ${yellow}未运行${plain}"
        else
            echo -e "NaiveProxy状态: ${red}未安装${plain}"
        fi
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        readp "请输入数字【0-21】:" Input
        case "$Input" in
            1) run_action quick_install;;
            2) run_action uninstall;;
            3) run_action install_caddy;;
            4) run_action install_service;;
            5) run_action add_user;;
            6) run_action del_user;;
            7) run_action list_users;;
            8) run_action add_domain;;
            9) run_action del_domain;;
            10) run_action list_domains;;
            11) run_action apply_cert;;
            12) run_action generate_and_restart;;
            13) run_action start_service;;
            14) run_action stop_service;;
            15) run_action multi_port;;
            16) run_action show_status;;
            17) run_action show_share;;
            18) view_log;;
            19) run_action update_script;;
            20) run_action update_kernel;;
            21) run_action enable_bbr;;
            0) exit 0;;
            *) red "输入错误，请输入 0-21 之间的数字"; pause;;
        esac
    done
}

#===============================================================================
# 程序入口
#===============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    [[ $EUID -ne 0 ]] && yellow "请以root模式运行脚本" && exit 1
    blue "正在初始化面板并检测系统环境，请稍候..."
    get_system_info
    check_deps ask || yellow "依赖未完整安装，部分功能可能受限"
    init_config || { red "初始化配置目录失败"; exit 1; }
    main_menu
fi
