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
pause(){ read -r -p "按回车继续..." _ || true; }

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
[[ -f "${BASH_SOURCE[0]}" ]] && SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
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
FW_PREF_FILE="$CONFIG_DIR/firewall.pref"
ACME_HOOK="$CONFIG_DIR/acme-hook.sh"
CADDYFILE="$CONFIG_DIR/Caddyfile"
BACKUP_CADDYFILE="$CONFIG_DIR/reCaddyfile"
FALLBACK_CERT_DIR="$CONFIG_DIR/certs/_fallback"
FALLBACK_CERT="$FALLBACK_CERT_DIR/cert.crt"
FALLBACK_KEY="$FALLBACK_CERT_DIR/private.key"

SERVICEFILE="/etc/systemd/system/naiveproxy.service"
SERVICE_USER="naiveproxy"
RUN_DIR="/run/naiveproxy"
ADMIN_SOCK="$RUN_DIR/admin.sock"
# 使用独立路径，避免覆盖或误删系统包管理器维护的 /usr/bin/caddy
BINARY="/usr/local/bin/caddy-naive"
LEGACY_BINARY="/usr/bin/caddy"
CADDY_VERSION_FILE="/etc/naiveproxy/caddy.version"
LEGACY_VERSION_FILE="/etc/caddy/version"
NAIVE_DIR="/root/naive"
ACME_HOME="/root/.acme.sh"
ACME_BIN="$ACME_HOME/acme.sh"
ACME_RELOAD_CMD="systemctl try-reload-or-restart naiveproxy"
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

declare -gA USER_PASS USER_EMAIL DOMAIN_BACKEND DOMAIN_CERT DOMAIN_KEY DOMAIN_CERT_SRC
declare -ga PROXY_PORTS

# 系统状态与交互临时变量 (显式初始化以保持 SC2154 静态检查生效)
op="未知"
cpu="amd64"
kernel_version=""
vi="none"
bbr="未知/不支持"
ipv4=""
ipv6=""
wgcfv4=""
wgcfv6=""
AUTO_OPEN_FW=1
NEW_USER=""
NEW_PASS=""
NEW_DOMAIN=""
NEW_BACKEND=""

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
# 域名须包含有效 TLD (字母或合法 punycode)，拒绝 IPv4 与非法连字符 TLD
valid_domain(){
    local d=$1
    [[ ${#d} -le 253 && $d =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}|[Xx][Nn]--[A-Za-z0-9]([A-Za-z0-9-]{0,57}[A-Za-z0-9])?)$ ]]
}
valid_ipv4(){
    local ip=$1 o1 o2 o3 o4
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]}
    (( 10#$o1 <= 255 && 10#$o2 <= 255 && 10#$o3 <= 255 && 10#$o4 <= 255 ))
}
valid_ipv6_literal(){
    local addr=$1
    [[ $addr == \[?*\] ]] || return 1
    addr=${addr#[}
    addr=${addr%]}
    [[ $addr == *:* && $addr =~ ^[0-9A-Fa-f:.]+$ ]]
}
valid_port(){ [[ $1 =~ ^[1-9][0-9]{0,4}$ && $1 -le 65535 ]]; }
valid_email(){ [[ $1 =~ ^[^[:space:]@:|-][^[:space:]@:|]*@[^[:space:]@:|]+\.[^[:space:]@:|]+$ ]]; }

# 去除路径并统一小写；保留 http:// 以支持本地 HTTP 伪装站，默认 https 省略前缀保持向后兼容
normalize_backend(){
    local b=$1 scheme=""
    b="${b#"${b%%[![:space:]]*}"}"
    b="${b%"${b##*[![:space:]]}"}"
    b="${b,,}"
    if [[ $b == http://* ]]; then
        scheme="http://"
        b="${b#http://}"
    elif [[ $b == https://* ]]; then
        b="${b#https://}"
    fi
    b="${b%%/*}"
    b="${b%%\?*}"
    echo "${scheme}${b}"
}

backend_url(){
    local b=$1
    if [[ $b == http://* || $b == https://* ]]; then
        echo "$b"
    else
        echo "https://$b"
    fi
}

backend_has_explicit_port(){
    local b=$1
    b="${b#http://}"
    b="${b#https://}"
    if [[ $b == \[* ]]; then
        [[ $b == *\]:* ]]
    else
        [[ $b == *:* ]]
    fi
}

valid_backend(){
    local b=$1 host port
    b="${b#http://}"
    b="${b#https://}"
    [[ -n $b ]] || return 1
    if [[ $b == \[* ]]; then
        if [[ $b == *\]:* ]]; then
            host="${b%\]:*}]"
            port="${b##*\]:}"
            valid_port "$port" || return 1
        else
            host="$b"
        fi
        valid_ipv6_literal "$host"
        return $?
    fi
    host="${b%%:*}"
    if [[ $b == *:* ]]; then
        port="${b#*:}"
        valid_port "$port" || return 1
    fi
    valid_domain "$host" || valid_ipv4 "$host"
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

mask_secret(){
    local s=$1
    if [[ ${#s} -le 4 ]]; then
        echo "****"
    else
        echo "${s:0:2}****${s: -2}"
    fi
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

# 原子写入：自动确保父目录存在，先写同目录临时文件再 rename，默认权限 600
write_file_atomic(){
    local dest=$1 mode=${2:-600} parent tmp
    parent="${dest%/*}"
    if [[ -n $parent && ! -d $parent ]]; then
        mkdir -p "$parent" || return 1
        if [[ $parent == "$CONFIG_DIR" ]]; then
            chmod 750 "$parent" 2>/dev/null || true
        elif [[ $parent == "$NAIVE_DIR" || $parent == "$CONFIG_DIR"/* ]]; then
            chmod 700 "$parent" 2>/dev/null || true
        fi
    fi
    tmp=$(mktemp "${dest}.XXXXXX") || return 1
    if ! cat > "$tmp"; then rm -f "$tmp"; return 1; fi
    if ! chmod "$mode" "$tmp" || ! mv -f "$tmp" "$dest"; then
        rm -f "$tmp"
        return 1
    fi
    return 0
}

installed_caddy_version(){
    [[ -x $BINARY ]] && "$BINARY" version 2>/dev/null | awk 'NR==1 {print $1}'
}

#===============================================================================
# 全局变量 - 系统检测
#===============================================================================
# shellcheck disable=SC2034 # release 用于记录受支持的发行版类别
get_system_info(){
    local release="" ID="" ID_LIKE="" PRETTY_NAME=""
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
# IPv4/IPv6 地址与 WARP 状态检测 (并行执行，避免单栈串行阻塞)
#===============================================================================
detect_ips_and_warp(){
    local tmpdir
    tmpdir=$(mktemp -d) || return 0
    (curl -s4m3 https://icanhazip.com 2>/dev/null > "$tmpdir/v4" || true) &
    (curl -s6m3 https://icanhazip.com 2>/dev/null > "$tmpdir/v6" || true) &
    (curl -s4m3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="warp"{print $2}' > "$tmpdir/w4" || true) &
    (curl -s6m3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="warp"{print $2}' > "$tmpdir/w6" || true) &
    wait
    ipv4=$(tr -d '[:space:]' < "$tmpdir/v4" 2>/dev/null || true)
    ipv6=$(tr -d '[:space:]' < "$tmpdir/v6" 2>/dev/null || true)
    wgcfv4=$(tr -d '[:space:]' < "$tmpdir/w4" 2>/dev/null || true)
    wgcfv6=$(tr -d '[:space:]' < "$tmpdir/w6" 2>/dev/null || true)
    rm -rf "$tmpdir"
}

warpcheck(){
    local tmpdir
    tmpdir=$(mktemp -d) || return 0
    (curl -s4m3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="warp"{print $2}' > "$tmpdir/w4" || true) &
    (curl -s6m3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="warp"{print $2}' > "$tmpdir/w6" || true) &
    wait
    wgcfv4=$(tr -d '[:space:]' < "$tmpdir/w4" 2>/dev/null || true)
    wgcfv6=$(tr -d '[:space:]' < "$tmpdir/w6" 2>/dev/null || true)
    rm -rf "$tmpdir"
}

has_global_ipv4(){
    ip -4 addr show scope global 2>/dev/null | grep -q 'inet '
}

has_global_ipv6(){
    ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '
}

#===============================================================================
# 纯 IPv6 VPS 的 NAT64/DNS64 支持
#===============================================================================
ensure_nat64(){
    local interactive=${1:-ask} yn=""
    # 必须先确认本机确实具备 IPv6 连通性，避免在纯 IPv4/离线环境下误写 DNS64
    has_global_ipv6 || return 0
    curl -s6m4 -o /dev/null https://icanhazip.com 2>/dev/null || return 0

    warpcheck
    [[ $wgcfv4 =~ on|plus || $wgcfv6 =~ on|plus ]] && return 0
    [[ -n $(curl -s4m3 https://icanhazip.com 2>/dev/null) ]] && return 0
    # GitHub 无 AAAA 记录，可直接判断能否访问仅 IPv4 的站点
    curl -m 4 -s -o /dev/null https://github.com 2>/dev/null && return 0

    yellow "检测到纯 IPv6 VPS 且当前无法访问仅 IPv4 站点 (如 GitHub)。"
    yellow "提示: 启用公共 NAT64/DNS64 (nat64.net) 会使本机所有 IPv4 访问经第三方网关转发，"
    yellow "      可能存在限速、封禁代理流量或隐私风险；生产环境更建议自行配置 Cloudflare WARP。"
    if [[ $interactive == ask && -t 0 ]]; then
        readp "是否配置公共 NAT64/DNS64 以完成下载与访问？(Y/n):" yn
        [[ $yn == n || $yn == N ]] && return 0
    fi

    if systemctl is-active --quiet systemd-resolved 2>/dev/null && [[ -L /etc/resolv.conf ]]; then
        mkdir -p "${RESOLVED_DROPIN%/*}"
        # Domains=~. 确保全局 DNS64 优先级不被接口 DHCP DNS 绕过
        printf '[Resolve]\nDNS=2a00:1098:2b::1 2a00:1098:2c::1\nDomains=~.\n' > "$RESOLVED_DROPIN"
        systemctl restart systemd-resolved 2>/dev/null || true
    elif ! grep -q "$NAT64_MARK" /etc/resolv.conf 2>/dev/null; then
        local tmp
        tmp=$(mktemp) || return 1
        {
            echo "$NAT64_MARK begin"
            echo "nameserver 2a00:1098:2b::1"
            echo "nameserver 2a00:1098:2c::1"
            echo "$NAT64_MARK end"
            cat /etc/resolv.conf 2>/dev/null
        } > "$tmp"
        if ! cat "$tmp" > /etc/resolv.conf 2>/dev/null; then
            yellow "写入 /etc/resolv.conf 失败（可能被设置为只读或 immutable）"
        fi
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
        cat "$tmp" > /etc/resolv.conf 2>/dev/null || true
        rm -f "$tmp"
    fi
}

#===============================================================================
# 防火墙端口管理 (TCP 与 UDP / HTTP3)
# 支持 ufw / firewalld / nftables / iptables+ip6tables，精确记录脚本新增的规则
#===============================================================================
nft_drop_input_chains(){
    command -v nft &>/dev/null || return 0
    nft -a list chains 2>/dev/null | awk '
        /^table / { fam=$2; tbl=$3 }
        /^[[:space:]]*chain / { ch=$2 }
        /hook input/ && /policy drop/ { print fam, tbl, ch }
    '
}

fw_backend(){
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo ufw
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        echo firewalld
    elif [[ -n $(nft_drop_input_chains) ]]; then
        echo nftables
    elif command -v iptables &>/dev/null || command -v ip6tables &>/dev/null; then
        echo iptables
    else
        echo none
    fi
}

fw_rule_exists(){
    local backend=$1 port=$2 proto=$3
    case $backend in
        ufw)
            # 仅匹配针对 Anywhere 的 ALLOW 规则，不误把 DENY/REJECT/限源 IP 当作已放行
            ufw status 2>/dev/null | grep -qE "^${port}/${proto}[[:space:]]+ALLOW[[:space:]]+(IN[[:space:]]+)?Anywhere" ;;
        firewalld)
            firewall-cmd --permanent --query-port="${port}/${proto}" &>/dev/null ;;
        nftables)
            nft list ruleset 2>/dev/null | grep -qE "${proto} dport ${port} accept comment \"naiveproxy\"" ;;
        iptables)
            iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
        ip6tables)
            ip6tables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
        *) return 1 ;;
    esac
}

fw_add(){
    local backend=$1 port=$2 proto=$3 fam tbl ch added=0
    case $backend in
        ufw)
            ufw allow "${port}/${proto}" >/dev/null 2>&1 ;;
        firewalld)
            firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 && \
            firewall-cmd --add-port="${port}/${proto}" >/dev/null 2>&1 ;;
        nftables)
            while read -r fam tbl ch; do
                [[ -n $fam && -n $tbl && -n $ch ]] || continue
                nft insert rule "$fam" "$tbl" "$ch" "$proto" dport "$port" accept comment '"naiveproxy"' >/dev/null 2>&1 && added=1
            done < <(nft_drop_input_chains)
            [[ $added -eq 1 ]] ;;
        iptables)
            iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
        ip6tables)
            ip6tables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null ;;
        *) return 1 ;;
    esac
}

fw_del(){
    local backend=$1 port=$2 proto=$3 fam tbl ch handle
    case $backend in
        ufw)
            ufw delete allow "${port}/${proto}" >/dev/null 2>&1 ;;
        firewalld)
            firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1
            firewall-cmd --remove-port="${port}/${proto}" >/dev/null 2>&1 ;;
        nftables)
            command -v nft &>/dev/null || return 0
            while read -r fam tbl ch handle; do
                [[ -n $handle ]] && nft delete rule "$fam" "$tbl" "$ch" handle "$handle" >/dev/null 2>&1 || true
            done < <(nft -a list ruleset 2>/dev/null | awk -v pr="$proto" -v pt="$port" '
                /^table / { fam=$2; tbl=$3 }
                /^[[:space:]]*chain / { ch=$2 }
                $0 ~ (pr " dport " pt " accept comment \"naiveproxy\"") {
                    for (i=1; i<=NF; i++) if ($i == "handle") print fam, tbl, ch, $(i+1)
                }') ;;
        iptables)
            command -v iptables &>/dev/null && iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true ;;
        ip6tables)
            command -v ip6tables &>/dev/null && ip6tables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true ;;
    esac
}

fw_persist(){
    local backend=$1
    if [[ $backend == nftables ]]; then
        if systemctl is-enabled --quiet nftables 2>/dev/null; then
            yellow "提示: nftables 规则已实时生效，如需重启保留请保存至 /etc/nftables.conf"
        fi
        return 0
    fi
    [[ $backend == iptables || $backend == ip6tables ]] || return 0
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 && return 0
    elif [[ -d /etc/sysconfig ]] && systemctl is-enabled --quiet iptables 2>/dev/null; then
        command -v iptables-save &>/dev/null && iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
        command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
        return 0
    fi
    local v4_drop=0 v6_drop=0
    command -v iptables &>/dev/null && ! iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT ACCEPT' && v4_drop=1
    command -v ip6tables &>/dev/null && ! ip6tables -S INPUT 2>/dev/null | grep -q '^-P INPUT ACCEPT' && v6_drop=1
    if [[ $v4_drop -eq 0 && $v6_drop -eq 0 ]]; then
        return 0
    fi
    yellow "提示: 未检测到 iptables 持久化工具 (如 iptables-persistent)，重启后放行规则会丢失"
}

record_fw_state(){
    local entry=$1 existing=""
    if [[ -f $FW_STATE_FILE ]]; then
        grep -Fqx "$entry" "$FW_STATE_FILE" 2>/dev/null && return 0
        existing=$(cat "$FW_STATE_FILE")
    fi
    {
        [[ -n $existing ]] && printf '%s\n' "$existing"
        printf '%s\n' "$entry"
    } | write_file_atomic "$FW_STATE_FILE" 600
}

open_port(){
    local port=$1 proto_arg=${2:-both} backend proto sub protos=() subs=() persisted=()
    valid_port "$port" || return 0
    backend=$(fw_backend)
    [[ $backend == none ]] && return 0
    [[ $proto_arg == both || $proto_arg == tcp ]] && protos+=(tcp)
    [[ $proto_arg == both || $proto_arg == udp ]] && protos+=(udp)

    if [[ $backend == iptables ]]; then
        command -v iptables &>/dev/null && subs+=(iptables)
        command -v ip6tables &>/dev/null && has_global_ipv6 && subs+=(ip6tables)
    else
        subs=("$backend")
    fi

    for sub in "${subs[@]}"; do
        for proto in "${protos[@]}"; do
            fw_rule_exists "$sub" "$port" "$proto" && continue
            if fw_add "$sub" "$port" "$proto"; then
                record_fw_state "$sub $port $proto" || true
                [[ " ${persisted[*]} " == *" $sub "* ]] || persisted+=("$sub")
            fi
        done
    done
    for sub in "${persisted[@]}"; do
        fw_persist "$sub"
    done
}

# 撤销脚本此前为该端口添加的规则 (用户原有的规则不会动)
close_port(){
    local port=${1:-} b p proto remaining=() changed=()
    [[ -f $FW_STATE_FILE ]] || return 0
    while read -r b p proto; do
        [[ -z $b ]] && continue
        if [[ -z $port || $p == "$port" ]]; then
            fw_del "$b" "$p" "$proto"
            [[ " ${changed[*]} " == *" $b "* ]] || changed+=("$b")
        else
            remaining+=("$b $p $proto")
        fi
    done < "$FW_STATE_FILE"
    if [[ ${#remaining[@]} -gt 0 ]]; then
        printf '%s\n' "${remaining[@]}" | write_file_atomic "$FW_STATE_FILE" 600
    else
        rm -f "$FW_STATE_FILE"
    fi
    for b in "${changed[@]}"; do
        fw_persist "$b"
    done
    return 0
}

save_fw_pref(){
    printf '%s\n' "$AUTO_OPEN_FW" | write_file_atomic "$FW_PREF_FILE" 600 || true
}

load_fw_pref(){
    if [[ -f $FW_PREF_FILE ]]; then
        local v
        v=$(tr -d '[:space:]' < "$FW_PREF_FILE" 2>/dev/null || true)
        [[ $v == "0" || $v == "1" ]] && AUTO_OPEN_FW=$v
    fi
}

open_proxy_ports(){
    local p
    open_port 80 tcp
    for p in "${PROXY_PORTS[@]:-443}"; do
        open_port "$p" both
    done
    blue "执行开放端口 80 (TCP) 与代理端口 ${PROXY_PORTS[*]:-443} (TCP/UDP HTTP/3) 完毕"
    echo "----------------------------------------------------"
}

openyn(){
    local action=""
    while true; do
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        readp "是否自动开放端口（80及代理端口 TCP/UDP）？\n1、是，自动放行 (回车默认)\n2、否，我自己手动\n请选择：" action || return 1
        if [[ -z $action || $action == "1" ]]; then
            AUTO_OPEN_FW=1
            save_fw_pref
            open_proxy_ports
            return 0
        elif [[ $action == "2" ]]; then
            AUTO_OPEN_FW=0
            save_fw_pref
            blue "已设为手动管理防火墙（后续申请证书也不会自动修改防火墙规则）"
            return 0
        else
            red "输入错误，请重新选择"
        fi
    done
}

#===============================================================================
# BBR 拥塞控制与 QUIC UDP 缓冲区优化
#===============================================================================
enable_bbr(){
    green "\n===== 启用 BBR 拥塞控制与 HTTP/3 UDP 缓冲优化 ====="
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) == bbr ]] \
        && [[ -f $BBR_SYSCTL_FILE ]] && grep -q 'net.core.rmem_max' "$BBR_SYSCTL_FILE" 2>/dev/null; then
        green "BBR 与 UDP 缓冲优化已经处于启用状态！"
        return 0
    fi

    modprobe tcp_bbr 2>/dev/null || true
    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        red "当前内核 ($kernel_version) 不支持 BBR (需要 4.9 及以上且包含 tcp_bbr 模块)"
        return 1
    fi

    yellow "正在配置开启 BBR 与 QUIC UDP 缓冲区..."
    # /etc/sysctl.conf 在部分新系统上不再于开机时加载，改用 sysctl.d
    mkdir -p /etc/sysctl.d
    cat > "$BBR_SYSCTL_FILE" <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=7500000
net.core.wmem_max=7500000
EOF
    sysctl -p "$BBR_SYSCTL_FILE" >/dev/null 2>&1 || true
    refresh_bbr_status

    if [[ $bbr == bbr ]]; then
        green "BBR 与 QUIC UDP 缓冲优化启用成功！配置文件: $BBR_SYSCTL_FILE"
    else
        red "配置已写入 $BBR_SYSCTL_FILE，但当前未生效 (容器类虚拟化通常无法修改)"
        return 1
    fi
}

#===============================================================================
# 依赖安装
# 参数: ask = 先询问再安装 (启动时)；auto = 直接安装 (一键安装时)
#===============================================================================
check_deps(){
    local mode=${1:-auto} miss=() opt_miss=() pkgs=() opt_pkgs=() cmd pkg mgr yn=""

    # 必需依赖：含 socat (acme.sh standalone 模式必需) 与 gzip (tar -zxf)
    for cmd in curl tar gzip systemctl ss ip awk grep sed crontab openssl sha256sum base64 socat; do
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    # 可选依赖：RHEL/CentOS/Rocky/AlmaLinux 默认仓库无 qrencode，缺失不应阻断安装
    command -v qrencode &>/dev/null || opt_miss+=(qrencode)

    [[ ${#miss[@]} -eq 0 && ${#opt_miss[@]} -eq 0 ]] && return 0

    if command -v apt-get &>/dev/null; then mgr=apt
    elif command -v dnf &>/dev/null; then mgr=dnf
    elif command -v yum &>/dev/null; then mgr=yum
    else
        if [[ ${#miss[@]} -gt 0 ]]; then
            red "未找到 apt/yum/dnf，无法自动安装依赖: ${miss[*]}"
            return 1
        fi
        return 0
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
    opt_pkgs=("${opt_miss[@]}")

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        if [[ $mode == ask ]]; then
            yellow "缺少必需依赖命令: ${miss[*]}"
            readp "是否立即安装软件包 ${pkgs[*]}？(Y/n):" yn || return 1
            [[ $yn == n || $yn == N ]] && return 1
        else
            yellow "正在安装缺少的必需依赖: ${pkgs[*]}"
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
    fi

    if [[ ${#opt_pkgs[@]} -gt 0 && $mode == auto ]]; then
        yellow "尝试安装可选工具: ${opt_pkgs[*]} (若仓库不含将自动跳过)..."
        case $mgr in
            apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "${opt_pkgs[@]}" >/dev/null 2>&1 || yellow "可选工具 ${opt_pkgs[*]} 安装跳过，不影响核心功能" ;;
            dnf) dnf install -y "${opt_pkgs[@]}" >/dev/null 2>&1 || yellow "可选工具 ${opt_pkgs[*]} 未在默认源中找到 (需 EPEL)，已跳过，不影响核心功能" ;;
            yum) yum install -y "${opt_pkgs[@]}" >/dev/null 2>&1 || yellow "可选工具 ${opt_pkgs[*]} 未在默认源中找到 (需 EPEL)，已跳过，不影响核心功能" ;;
        esac
    fi
    return 0
}

#===============================================================================
# 低权运行用户与目录权限维护
#===============================================================================
ensure_service_user(){
    if ! id -u "$SERVICE_USER" &>/dev/null; then
        if command -v useradd &>/dev/null; then
            useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
                || useradd -r -M -s /sbin/nologin "$SERVICE_USER" 2>/dev/null || return 1
        elif command -v adduser &>/dev/null; then
            adduser --system --no-create-home --group --disabled-login "$SERVICE_USER" 2>/dev/null || return 1
        else
            return 1
        fi
    fi
    return 0
}

ensure_config_dirs(){
    mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/certs" "$NAIVE_DIR" || return 1
    if id -u "$SERVICE_USER" &>/dev/null; then
        chown "root:${SERVICE_USER}" "$CONFIG_DIR" "$CONFIG_DIR/certs" 2>/dev/null || true
        chmod 750 "$CONFIG_DIR" "$CONFIG_DIR/certs" 2>/dev/null || true
    else
        chmod 700 "$CONFIG_DIR" "$CONFIG_DIR/certs" 2>/dev/null || true
    fi
    chmod 700 "$NAIVE_DIR" 2>/dev/null || true
}

sync_runtime_permissions(){
    [[ $EUID -eq 0 ]] || return 0
    id -u "$SERVICE_USER" &>/dev/null || return 0
    [[ -d $CONFIG_DIR ]] && chown "root:${SERVICE_USER}" "$CONFIG_DIR" && chmod 750 "$CONFIG_DIR"
    [[ -d $CONFIG_DIR/certs ]] && chown "root:${SERVICE_USER}" "$CONFIG_DIR/certs" && chmod 750 "$CONFIG_DIR/certs"
    [[ -f $CADDYFILE ]] && chown "root:${SERVICE_USER}" "$CADDYFILE" && chmod 640 "$CADDYFILE"

    local cert_dir
    for cert_dir in "$CONFIG_DIR"/certs/*; do
        [[ -d $cert_dir ]] || continue
        chown "root:${SERVICE_USER}" "$cert_dir" 2>/dev/null || true
        chmod 750 "$cert_dir" 2>/dev/null || true
        [[ -f $cert_dir/cert.crt ]] && chown "root:${SERVICE_USER}" "$cert_dir/cert.crt" && chmod 644 "$cert_dir/cert.crt"
        [[ -f $cert_dir/private.key ]] && chown "root:${SERVICE_USER}" "$cert_dir/private.key" && chmod 640 "$cert_dir/private.key"
    done
    return 0
}

# 旧版将二进制安装在 /usr/bin/caddy；迁移到独立路径 /usr/local/bin/caddy-naive 避免与系统包冲突
migrate_legacy_binary(){
    if [[ ! -x $BINARY && -x $LEGACY_BINARY ]]; then
        if "$LEGACY_BINARY" list-modules 2>/dev/null | grep -q '^http\.handlers\.forward_proxy$'; then
            mkdir -p "${BINARY%/*}"
            if cp -f "$LEGACY_BINARY" "$BINARY" && chmod 755 "$BINARY"; then
                record_caddy_version
                yellow "已将旧版 Caddy 二进制迁移至独立路径: $BINARY"
            fi
        fi
    fi
}

#===============================================================================
# 初始化配置目录与安全权限
#===============================================================================
init_config(){
    ensure_service_user || true
    ensure_config_dirs || return 1

    [[ ! -f $USERS_FILE ]] && touch "$USERS_FILE"
    [[ ! -f $DOMAINS_FILE ]] && touch "$DOMAINS_FILE"
    [[ ! -f $PORTS_FILE ]] && echo "443" > "$PORTS_FILE"
    chmod 600 "$USERS_FILE" "$DOMAINS_FILE" "$PORTS_FILE" 2>/dev/null || true

    migrate_legacy_binary
    load_config
    load_fw_pref
    sync_ports_with_caddyfile
    sync_runtime_permissions
    upgrade_service_file
    fix_acme_cron_and_hooks
    return 0
}

#===============================================================================
# 加载用户、域名与端口配置
#===============================================================================
load_config(){
    local p u e d b c k src line
    PROXY_PORTS=()
    if [[ -f $PORTS_FILE ]]; then
        while IFS= read -r p; do
            p="${p%$'\r'}"
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
            e="${e%$'\r'}"
            p="${p%$'\r'}"
            [[ -n $u && -n $p ]] || continue
            USER_PASS[$u]=$p
            USER_EMAIL[$u]=$e
        done < <(grep -v '^#' "$USERS_FILE" 2>/dev/null)
    fi

    # 新格式以 | 分隔 (域名|后端|证书路径|密钥路径|证书来源)；兼容旧版 4 字段及 : 分隔
    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    DOMAIN_CERT_SRC=()
    if [[ -f $DOMAINS_FILE ]]; then
        while IFS= read -r line; do
            line="${line%$'\r'}"
            [[ -z $line || $line == \#* ]] && continue
            src=""
            if [[ $line == *"|"* ]]; then
                IFS='|' read -r d b c k src <<< "$line"
            else
                IFS=: read -r d b c k <<< "$line"
            fi
            [[ -n $d && -n $b ]] || continue
            DOMAIN_BACKEND[$d]=$b
            DOMAIN_CERT[$d]=$c
            DOMAIN_KEY[$d]=$k
            DOMAIN_CERT_SRC[$d]=$src
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
    } | write_file_atomic "$USERS_FILE" 600
}

save_domains(){
    local d
    {
        echo "# 域名配置 - 格式: 域名|后端|证书路径|密钥路径|证书来源"
        while IFS= read -r d; do
            echo "${d}|${DOMAIN_BACKEND[$d]}|${DOMAIN_CERT[$d]:-}|${DOMAIN_KEY[$d]:-}|${DOMAIN_CERT_SRC[$d]:-}"
        done < <(sorted_domains)
    } | write_file_atomic "$DOMAINS_FILE" 600
}

save_ports(){
    {
        echo "# 端口配置"
        printf '%s\n' "${PROXY_PORTS[@]}"
    } | write_file_atomic "$PORTS_FILE" 600
}

get_proxy_port(){
    local p
    p=$(awk '$1 == "https_port" { print $2; exit }' "$CADDYFILE" 2>/dev/null)
    valid_port "$p" && echo "$p" || echo 443
}

# 现有 Caddyfile 中站点地址使用的代理端口 (每行一个，按出现顺序去重，排除 80)
caddyfile_ports(){
    [[ -f $CADDYFILE ]] || return 0
    awk '/^[^[:space:]#{].*\{[[:space:]]*$/ {
            line = $0; sub(/\{.*/, "", line); n = split(line, a, /[[:space:],]+/)
            for (i = 1; i <= n; i++) if (a[i] ~ /:[0-9]+$/) {
                p = a[i]; sub(/.*:/, "", p)
                if (p != "80" && !(p in seen)) { seen[p] = 1; print p }
            }
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
    local url=$1 out=$2 err=""
    if command -v curl &>/dev/null; then
        if err=$(curl -fsSL --connect-timeout 15 --retry 2 -m 300 "$url" -o "$out" 2>&1); then
            return 0
        fi
    fi
    if command -v wget &>/dev/null; then
        if err=$(wget -q --timeout=30 --tries=2 "$url" -O "$out" 2>&1); then
            return 0
        fi
    fi
    [[ -n $err ]] && yellow "下载详情: ${err%%$'\n'*}"
    return 1
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
    expect=${ASSET_SHA256[$name]:-}
    [[ -n $expect ]] || { red "未知的依赖包: $name"; return 1; }

    for dir in "${ASSET_DIRS[@]}"; do
        if verify_sha256 "$dir/$name" "$expect"; then
            blue "使用本地依赖包: $dir/$name"
            cp -f "$dir/$name" "$out" && return 0
        elif [[ -f $dir/$name ]]; then
            yellow "本地依赖包 $dir/$name 校验失败，已忽略"
        fi
    done

    ensure_nat64 ask
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
    local chcaddy=""
    green "\n===== 安装 Caddy2-Naiveproxy ====="
    yellow "请选择安装方式:"
    yellow "1. 使用预编译版本 (快速，推荐，${BUNDLED_CADDY_VERSION})"
    yellow "2. 在线编译版本 (慢，自动构建最新内核)"
    readp "请选择 [1/2] (默认1):" chcaddy || return 1

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
    mkdir -p "${BINARY%/*}"
    # rename 替换，避免覆盖正在运行的二进制
    mv -f "$tmpdir/caddy" "$BINARY" || { rm -rf "$tmpdir"; return 1; }
    rm -rf "$tmpdir"
    record_caddy_version
    green "Caddy 安装完成: $(installed_caddy_version) ($BINARY)"
}

record_caddy_version(){
    local ver
    ver=$(installed_caddy_version)
    [[ -n $ver ]] && printf '%s\n' "$ver" | write_file_atomic "$CADDY_VERSION_FILE" 644 || true
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
    local base ver="" json="" sha tmpdir file dl_url=""
    for base in https://go.dev/dl https://golang.google.cn/dl; do
        json=$(curl -fsSL --connect-timeout 10 -m 20 "${base}/?mode=json" 2>/dev/null) || continue
        ver=$(echo "$json" | grep -o '"version": *"go[0-9.]*"' | head -n 1 | grep -o 'go[0-9.]*')
        if [[ -n $ver ]]; then
            dl_url="$base"
            break
        fi
    done
    [[ -n $ver ]] || { red "无法获取 Go 最新版本信息"; return 1; }

    file="${ver}.linux-${cpu}.tar.gz"
    sha=$(echo "$json" | tr -d '[:space:]' | grep -o "\"filename\":\"${file}\"[^}]*" | grep -o '"sha256":"[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)
    [[ -n $sha ]] || { red "无法获取 $file 的 SHA256"; return 1; }

    yellow "正在下载官方 Go: $file ..."
    tmpdir=$(mktemp -d) || return 1
    local ok=0 candidate
    for candidate in "${dl_url}/${file}" "https://dl.google.com/go/${file}" "https://golang.google.cn/dl/${file}"; do
        if download "$candidate" "$tmpdir/go.tar.gz" && verify_sha256 "$tmpdir/go.tar.gz" "$sha"; then
            ok=1
            break
        fi
    done
    if [[ $ok -ne 1 ]]; then
        red "Go 下载失败或校验不通过"
        rm -rf "$tmpdir"
        return 1
    fi

    if [[ -d /usr/local/go ]]; then
        yellow "检测到已存在 /usr/local/go，将替换为 $ver"
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
    minor=$(go_minor_version || true)
    if [[ -z $minor || $minor -lt $GO_MIN_MINOR ]]; then
        yellow "未找到 Go 或版本低于 1.${GO_MIN_MINOR}，安装官方 Go..."
        install_go_official || return 1
    fi
    export GOTOOLCHAIN=auto GO111MODULE=on
    if ! curl -fsS --connect-timeout 5 -m 5 -o /dev/null https://proxy.golang.org 2>/dev/null; then
        export GOPROXY=https://goproxy.cn,direct
    fi
    green "Go 环境: $(go version)"
}

install_caddy_build(){
    yellow "开始在线编译..."
    ensure_nat64 ask
    if ! command -v git &>/dev/null; then
        yellow "未检测到 git，部分 Go 模块直连拉取可能需要 git"
    fi

    local total_mem swapfile="/var/naiveproxy-build.swap" swap_created=0 tmpdir="" ret=1
    cleanup_build_resources(){
        [[ -n $tmpdir && -d $tmpdir ]] && rm -rf "$tmpdir"
        if [[ $swap_created -eq 1 ]]; then
            swapoff "$swapfile" 2>/dev/null || true
            rm -f "$swapfile"
            swap_created=0
        fi
    }
    trap cleanup_build_resources RETURN INT TERM

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

    if ensure_go && go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest; then
        local xcaddy_bin
        xcaddy_bin="$(go env GOPATH)/bin/xcaddy"
        tmpdir=$(mktemp -d)
        if "$xcaddy_bin" build --output "$tmpdir/caddy" \
            --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive \
            && "$tmpdir/caddy" list-modules 2>/dev/null | grep -q '^http\.handlers\.forward_proxy$'; then
            chmod 755 "$tmpdir/caddy"
            mkdir -p "${BINARY%/*}"
            mv -f "$tmpdir/caddy" "$BINARY" && ret=0
        fi
    fi

    cleanup_build_resources
    trap - RETURN INT TERM

    if [[ $ret -eq 0 ]]; then
        record_caddy_version
        green "在线编译安装完成: $(installed_caddy_version) ($BINARY)"
    else
        red "编译失败"
        return 1
    fi
}

#===============================================================================
# 安装 systemd 服务 (低权用户 + 沙箱加固 + Type=notify + 私有 Unix Socket 重载)
#===============================================================================
write_service_file(){
    ensure_service_user || { red "创建系统用户 $SERVICE_USER 失败"; return 1; }
    sync_runtime_permissions
    mkdir -p "${SERVICEFILE%/*}" || return 1
    cat > "$SERVICEFILE" <<EOF
[Unit]
Description=NaiveProxy Multi-User Service
Documentation=https://github.com/klzgrad/naiveproxy
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=$SERVICE_USER
Group=$SERVICE_USER
RuntimeDirectory=naiveproxy
RuntimeDirectoryMode=0750
Environment=XDG_CONFIG_HOME=$RUN_DIR/config
Environment=XDG_DATA_HOME=$RUN_DIR/data
ExecStart=$BINARY run --environ --config $CADDYFILE --adapter caddyfile
# --force: 配置未变时也重新加载 (续期后需重新读取证书文件)
ExecReload=$BINARY reload --force --config $CADDYFILE --adapter caddyfile --address unix/$ADMIN_SOCK
TimeoutStopSec=5s
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$RUN_DIR
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

install_service(){
    green "\n===== 安装服务 ====="
    write_service_file || return 1
    systemctl enable naiveproxy >/dev/null 2>&1 || return 1
    if [[ ! -L $SHORTCUT || ! -x $INSTALL_SCRIPT ]]; then
        install_shortcut >/dev/null 2>&1 || true
    fi
    green "服务安装完成"
}

# 旧版服务单元使用 root / /usr/bin/caddy / Type=simple / 无 unix socket 时自动升级
upgrade_service_file(){
    [[ -f $SERVICEFILE ]] || return 0
    if ! grep -q "User=$SERVICE_USER" "$SERVICEFILE" \
        || ! grep -q "Type=notify" "$SERVICEFILE" \
        || ! grep -q -- "--address unix/$ADMIN_SOCK" "$SERVICEFILE" \
        || ! grep -q "ExecStart=$BINARY " "$SERVICEFILE"; then
        write_service_file >/dev/null 2>&1 || true
    fi
}

#===============================================================================
# 端口冲突检测 (TCP 与 UDP；忽略 naiveproxy 自身)
#===============================================================================
check_port(){
    local port=$1 self_pid
    self_pid=$(systemctl show -p MainPID --value naiveproxy 2>/dev/null || true)
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
    NEW_USER=""
    NEW_PASS=""
    readp "请输入用户名（3-32位字母数字下划线，回车随机生成）:" NEW_USER || return 1
    if [[ -z $NEW_USER ]]; then
        NEW_USER=$(gen_random 'a-z0-9' 6)
        blue "随机生成用户名: $NEW_USER"
    fi
    valid_user "$NEW_USER" || { red "用户名不合法，必须由 3-32 位字母、数字或下划线组成"; return 1; }

    readp "请输入密码（5-64位，限字母数字及 . _ ~ -，回车随机生成）:" NEW_PASS || return 1
    if [[ -z $NEW_PASS ]]; then
        NEW_PASS=$(gen_random 'a-zA-Z0-9' 16)
        blue "随机生成密码: $NEW_PASS"
    fi
    valid_pass "$NEW_PASS" || { red "密码不合法（5-64位，仅限字母、数字及 . _ ~ -）"; return 1; }
}

prompt_domain_backend(){
    NEW_DOMAIN=""
    NEW_BACKEND=""
    readp "请输入解析到本 VPS 的域名（如 proxy.example.com）:" NEW_DOMAIN || return 1
    NEW_DOMAIN="${NEW_DOMAIN,,}"
    [[ -z $NEW_DOMAIN ]] && { red "域名不能为空"; return 1; }
    valid_domain "$NEW_DOMAIN" || { red "域名格式错误（请输入有效域名，不支持裸 IP）"; return 1; }

    readp "请输入反代伪装网址（支持 http:// 本地站，回车默认 speed.cloudflare.com）:" NEW_BACKEND || return 1
    [[ -z $NEW_BACKEND ]] && NEW_BACKEND="speed.cloudflare.com"
    NEW_BACKEND=$(normalize_backend "$NEW_BACKEND")
    valid_backend "$NEW_BACKEND" || { red "伪装网址格式错误，应为 [http(s)://]域名或IP[:端口]"; return 1; }
}

#===============================================================================
# 用户管理
#===============================================================================
add_user(){
    local email=""
    echo
    yellow "===== 添加用户 ====="
    prompt_user_pass || return 1
    [[ -n ${USER_PASS[$NEW_USER]:-} ]] && yellow "用户 $NEW_USER 已存在，本次操作将修改其密码"

    readp "请输入邮箱（可选，回车跳过）:" email || return 1
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
    local user="" confirm="" fname
    echo
    yellow "===== 删除用户 ====="
    list_users
    [[ ${#USER_PASS[@]} -eq 0 ]] && return 0

    readp "请输入要删除的用户名:" user || return 1
    [[ -z $user ]] && { red "用户名不能为空"; return 1; }
    [[ -z ${USER_PASS[$user]:-} ]] && { red "用户 $user 不存在"; return 1; }

    readp "确认删除用户 $user ？(输入y确认):" confirm || return 1
    [[ $confirm != y && $confirm != Y ]] && { blue "已取消"; return 0; }

    unset 'USER_PASS[$user]' 'USER_EMAIL[$user]'
    save_users || return 1
    fname="${user//[^A-Za-z0-9_-]/_}"
    rm -f "$NAIVE_DIR/v2rayn_${fname}.json"
    green "用户 $user 已删除"
    yellow "提示: 请执行【12】生成配置并重启以使变更生效！"
}

list_users(){
    local show_plain=${1:-0} u pass_disp
    echo
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        yellow "暂无用户"
        return 0
    fi
    green "─────────── 用户列表 ───────────"
    while IFS= read -r u; do
        if [[ $show_plain == "1" ]]; then
            pass_disp="${USER_PASS[$u]}"
        else
            pass_disp="$(mask_secret "${USER_PASS[$u]}")"
        fi
        blue "用户: $u  密码: $pass_disp  邮箱: ${USER_EMAIL[$u]:-未设置}"
    done < <(sorted_users)
    green "────────────────────────────────"
}

view_users_menu(){
    local yn=""
    list_users 0
    [[ ${#USER_PASS[@]} -eq 0 ]] && return 0
    readp "是否显示明文密码？(y/N):" yn || return 0
    [[ $yn == y || $yn == Y ]] && list_users 1
    return 0
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
    DOMAIN_CERT_SRC[$NEW_DOMAIN]="${DOMAIN_CERT_SRC[$NEW_DOMAIN]:-}"
    save_domains || return 1
    green "域名 $NEW_DOMAIN 添加成功（反代伪装: $(backend_url "$NEW_BACKEND")）"
    yellow "请选择【11】申请或配置该域名的 TLS 证书"
}

del_domain(){
    local domain="" confirm=""
    echo
    yellow "===== 删除域名 ====="
    list_domains
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && return 0

    readp "请输入要删除的域名:" domain || return 1
    domain="${domain,,}"
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]:-} ]] && { red "域名 $domain 不存在"; return 1; }

    readp "确认删除域名 $domain ？(输入y确认):" confirm || return 1
    [[ $confirm != y && $confirm != Y ]] && { blue "已取消"; return 0; }

    cleanup_domain_acme "$domain"
    rm -rf "${CONFIG_DIR:?}/certs/${domain:?}"
    unset 'DOMAIN_BACKEND[$domain]' 'DOMAIN_CERT[$domain]' 'DOMAIN_KEY[$domain]' 'DOMAIN_CERT_SRC[$domain]'
    save_domains || return 1
    green "域名 $domain 及其证书/续期任务已删除"
    yellow "提示: 请执行【12】生成配置并重启以生效！"
}

get_cert_status_desc(){
    local c_file="$1" end_date exp_epoch now_epoch diff_sec days_left
    if [[ -z $c_file || ! -f $c_file ]]; then
        echo -e "${red}未申请${plain}"
        return
    fi
    if [[ ! -s $c_file ]]; then
        echo -e "${red}证书为空/损坏${plain}"
        return
    fi
    end_date=$(openssl x509 -enddate -noout -in "$c_file" 2>/dev/null | cut -d= -f2)
    if [[ -z $end_date ]]; then
        echo -e "${red}证书无效/损坏${plain}"
        return
    fi
    exp_epoch=$(date -d "$end_date" +%s 2>/dev/null || true)
    if [[ -z $exp_epoch ]]; then
        echo -e "${green}已配置${plain}"
        return
    fi
    now_epoch=$(date +%s)
    diff_sec=$(( exp_epoch - now_epoch ))
    if [[ $diff_sec -le 0 ]]; then
        days_left=$(( (-diff_sec + 86399) / 86400 ))
        echo -e "${red}已过期 (失效 ${days_left} 天)${plain}"
    else
        days_left=$(( diff_sec / 86400 ))
        if [[ $days_left -le 30 ]]; then
            echo -e "${yellow}即将到期 (剩余 ${days_left} 天，待自动续期)${plain}"
        else
            echo -e "${green}有效 (剩余 ${days_left} 天)${plain}"
        fi
    fi
}

list_domains(){
    echo
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        yellow "暂无域名"
        return 0
    fi
    green "─────────── 域名列表 ───────────"
    local d src_tag
    while IFS= read -r d; do
        src_tag=""
        [[ ${DOMAIN_CERT_SRC[$d]:-} == "manual" ]] && src_tag=" [手动]"
        [[ ${DOMAIN_CERT_SRC[$d]:-} == "acme" ]] && src_tag=" [ACME]"
        echo -e "  ${blue}域名:${plain} $d  ${blue}反代后端:${plain} $(backend_url "${DOMAIN_BACKEND[$d]}")  ${blue}证书状态:${plain} $(get_cert_status_desc "${DOMAIN_CERT[$d]:-}")${src_tag}"
    done < <(sorted_domains)
    green "────────────────────────────────"
}

#===============================================================================
# acme.sh Standalone 签发/续期钩子
# pre: 识别并停止实际占用 80 端口的 systemd 服务；post: 仅恢复被停止的服务
#===============================================================================
write_acme_hook(){
    mkdir -p "$CONFIG_DIR"
    cat > "$ACME_HOOK" <<'EOF'
#!/bin/sh
# 由 naiveproxy.sh 生成：acme.sh standalone 模式需要临时空出 80 端口
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
STATE=/run/naiveproxy-acme-stopped

pid_to_service() {
    pid=$1
    unit=""
    if command -v ps >/dev/null 2>&1; then
        unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d '[:space:]')
    fi
    if [ -z "$unit" ] && [ -r "/proc/$pid/cgroup" ]; then
        unit=$(sed -n 's|.*/\([^/]*\.service\)$|\1|p' "/proc/$pid/cgroup" 2>/dev/null | head -n 1)
    fi
    case "$unit" in
        *.service) printf '%s\n' "$unit" ;;
    esac
}

case "$1" in
    pre)
        pids=$(ss -Htlnp 'sport = :80' 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
        [ -z "$pids" ] && exit 0
        touch "$STATE"
        for p in $pids; do
            svc=$(pid_to_service "$p")
            [ -z "$svc" ] && continue
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                if systemctl stop "$svc" 2>/dev/null; then
                    grep -Fqx "$svc" "$STATE" 2>/dev/null || printf '%s\n' "$svc" >> "$STATE"
                fi
            fi
        done
        ;;
    post)
        if [ -f "$STATE" ]; then
            while IFS= read -r svc; do
                [ -n "$svc" ] && systemctl start "$svc" 2>/dev/null || true
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
# acme.sh 域名配置读写与托管边界判断
#===============================================================================
acme_domain_conf(){
    local d=$1
    if [[ -f $ACME_HOME/${d}_ecc/$d.conf ]]; then
        echo "$ACME_HOME/${d}_ecc/$d.conf"
    elif [[ -f $ACME_HOME/$d/$d.conf ]]; then
        echo "$ACME_HOME/$d/$d.conf"
    else
        return 1
    fi
}

acme_conf_is_ecc(){
    [[ $1 == *_ecc/* ]]
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
    local conf=$1 key=$2 val=$3 b64=${4:-} tmp
    [[ -n $b64 ]] && val="__ACME_BASE64__START_$(printf '%s' "$val" | base64 -w0)__ACME_BASE64__END_"
    tmp=$(mktemp "${conf}.XXXXXX") || return 1
    if awk -v k="$key" -v line="${key}='${val}'" '
        index($0, k "=") == 1 { if (!done) print line; done = 1; next }
        { print }
        END { if (!done) print line }' "$conf" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$conf"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# 判断某域名在 acme.sh 中的续期任务是否由本脚本托管，避免误删/误改外部服务证书
is_acme_managed_domain(){
    local d=$1 c_path conf real_full
    [[ ${DOMAIN_CERT_SRC[$d]:-} == "manual" ]] && return 1
    c_path=${DOMAIN_CERT[$d]:-}
    [[ -n $c_path ]] || return 1
    conf=$(acme_domain_conf "$d" 2>/dev/null) || return 1
    real_full=$(acme_conf_get "$conf" Le_RealFullChainPath)
    if [[ $real_full == "$c_path" ]]; then
        return 0
    fi
    if [[ ${DOMAIN_CERT_SRC[$d]:-} == "acme" ]]; then
        return 0
    fi
    return 1
}

cleanup_domain_acme(){
    local d=$1 conf
    [[ -x $ACME_BIN ]] || return 0
    valid_domain "$d" || return 0
    is_acme_managed_domain "$d" || return 0
    for conf in "$ACME_HOME/$d/$d.conf" "$ACME_HOME/${d}_ecc/$d.conf"; do
        [[ -f $conf ]] || continue
        local real_full
        real_full=$(acme_conf_get "$conf" Le_RealFullChainPath)
        [[ -z $real_full || $real_full == "${DOMAIN_CERT[$d]:-}" || $real_full == "$CONFIG_DIR/certs/$d/cert.crt" ]] || continue
        if acme_conf_is_ecc "$conf"; then
            "$ACME_BIN" --remove -d "$d" --ecc >/dev/null 2>&1 || true
            rm -rf "${ACME_HOME:?}/${d}_ecc"
        else
            "$ACME_BIN" --remove -d "$d" >/dev/null 2>&1 || true
            rm -rf "${ACME_HOME:?}/$d"
        fi
    done
}

# 判断 acme.sh --standalone 是否需要传 --listen-v6 (兼顾纯 IPv6、WARP-IPv4 及仅 AAAA 域名)
acme_needs_ipv6_listen(){
    local domain=$1
    has_global_ipv6 || return 1
    # 1. 主机无公网 IPv4 接口地址 (纯 IPv6 主机)
    if ! has_global_ipv4; then
        return 0
    fi
    # 2. IPv4 出口由 WARP 接管，公网入站只能走 IPv6
    [[ $wgcfv4 =~ on|plus ]] && return 0
    # 3. 检查域名解析记录 (排除 DNS64 合成的 64:ff9b:: 与 nat64.net 前缀)
    local v4_ips="" v6_ips="" local_v6="" ip6
    v4_ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true)
    v6_ips=$(getent ahostsv6 "$domain" 2>/dev/null | awk '{print $1}' | grep -Ev '^(64:ff9b:|2a00:1098:2[bc]:)' | sort -u || true)
    if [[ -n $v6_ips && -z $v4_ips ]]; then
        return 0
    fi
    # 4. 双栈域名若解析到本机全局 IPv6 且内核允许双栈监听 (bindv6only=0)，用 --listen-v6 同时兼容 v6/v4
    if [[ -n $v6_ips && $(cat /proc/sys/net/ipv6/bindv6only 2>/dev/null || echo 1) == "0" ]]; then
        local_v6=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/ {sub(/\/.*/, "", $2); print $2}')
        for ip6 in $v6_ips; do
            if grep -Fqx "$ip6" <<< "$local_v6"; then
                return 0
            fi
        done
    fi
    return 1
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

    # 仅为明确由本脚本托管的域名补齐/更新续期配置，避免接管外部工具的证书
    local d conf c_path k_path changed v
    for d in "${!DOMAIN_BACKEND[@]}"; do
        [[ ${DOMAIN_CERT_SRC[$d]:-} == "manual" ]] && continue
        c_path=${DOMAIN_CERT[$d]:-}
        k_path=${DOMAIN_KEY[$d]:-}
        [[ -s $c_path && -s $k_path ]] || continue
        conf=$(acme_domain_conf "$d" 2>/dev/null) || continue
        v=$(acme_conf_get "$conf" Le_RealFullChainPath)
        # 仅当 Le_RealFullChainPath 已指向本脚本路径，或域名标记为 acme 且在脚本证书目录时才维护
        if [[ -n $v && $v != "$c_path" ]]; then
            continue
        fi
        if [[ -z $v && ${DOMAIN_CERT_SRC[$d]:-} != "acme" ]]; then
            continue
        fi

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
            if acme_needs_ipv6_listen "$d" && [[ $(acme_conf_get "$conf" Le_Listen_V6) != "1" ]]; then
                acme_conf_set "$conf" Le_Listen_V6 "1" && changed=1
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
    if [[ -n $email && -f $ACME_HOME/account.conf ]]; then
        local cur_email
        cur_email=$(acme_conf_get "$ACME_HOME/account.conf" ACCOUNT_EMAIL)
        if [[ -z $cur_email ]]; then
            "$ACME_BIN" --update-account -m "$email" >/dev/null 2>&1 || true
        fi
    fi
    fix_acme_cron_and_hooks
}

# 返回 0 = 已签发或证书仍有效；通过全局变量 ACME_LAST_ECC 告知调用方是否为 ECC 证书
ACME_LAST_ECC=0
issue_cert_standalone(){
    local domain="$1" email="$2" force=() listen_args=() key_args=(-k ec-256) existing_conf="" yn="" ret

    ensure_acme "$email" || return 1
    if ! command -v socat &>/dev/null && ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
        red "缺少 socat 或 python3，acme.sh standalone 模式无法监听 80 端口，请先安装 socat"
        return 1
    fi

    # 尊重用户在 openyn 中的手动防火墙选择
    if [[ $AUTO_OPEN_FW -eq 1 ]]; then
        open_port 80 tcp
    fi

    ACME_LAST_ECC=1
    if existing_conf=$(acme_domain_conf "$domain" 2>/dev/null); then
        readp "acme.sh 中已有 $domain 的证书，是否强制重新签发？(y/N):" yn || return 1
        if [[ $yn == y || $yn == Y ]]; then
            force=(--force)
        else
            # 沿用现有证书密钥类型，避免已有 ECC 时被 -k 2048 触发重新签发
            if acme_conf_is_ecc "$existing_conf"; then
                key_args=(-k ec-256)
                ACME_LAST_ECC=1
            else
                key_args=(-k 2048)
                ACME_LAST_ECC=0
            fi
        fi
    fi

    if acme_needs_ipv6_listen "$domain"; then
        listen_args=(--listen-v6)
        blue "检测到 IPv6 入站环境，Standalone 模式自动启用 --listen-v6"
    fi

    yellow "使用 Standalone 模式通过 Let's Encrypt 申请证书..."
    "$ACME_BIN" --issue --server letsencrypt -d "$domain" --standalone "${listen_args[@]}" "${key_args[@]}" "${force[@]}" \
        --pre-hook "$ACME_HOOK pre" --post-hook "$ACME_HOOK post"
    ret=$?
    if [[ $ret -eq 2 ]]; then
        blue "证书仍在有效期内，跳过签发，直接安装现有证书"
        return 0
    fi
    return $ret
}

# 校验证书与私钥均为合法 PEM 且公钥匹配
validate_cert_key_pair(){
    local cert_f=$1 key_f=$2 cert_pub key_pub
    openssl x509 -noout -in "$cert_f" 2>/dev/null || { red "$cert_f 不是有效的 PEM 证书"; return 1; }
    openssl pkey -noout -in "$key_f" 2>/dev/null || { red "$key_f 不是有效的 PEM 私钥"; return 1; }
    cert_pub=$(openssl x509 -pubkey -noout -in "$cert_f" 2>/dev/null | sha256sum | awk '{print $1}')
    key_pub=$(openssl pkey -pubout -in "$key_f" 2>/dev/null | sha256sum | awk '{print $1}')
    if [[ -z $cert_pub || $cert_pub != "$key_pub" ]]; then
        red "证书与私钥不匹配，请检查文件路径"
        return 1
    fi
    return 0
}

#===============================================================================
# 申请或配置证书
# 参数: [域名] [norestart]；一键安装时传入域名并由调用方负责生成配置与启动
#===============================================================================
apply_cert(){
    local domain=${1:-} norestart=${2:-} ctype="" email="" user_cert="" user_key=""
    echo
    yellow "===== 申请 / 配置证书 ====="
    if [[ -z $domain ]]; then
        list_domains
        [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { red "请先添加域名"; return 1; }
        readp "请输入要配置证书的域名:" domain || return 1
    fi
    domain="${domain,,}"
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]:-} ]] && { red "域名 $domain 未添加，请先在菜单【8】中添加"; return 1; }
    valid_domain "$domain" || { red "域名 $domain 格式不合法，请删除后重新添加"; return 1; }

    echo
    yellow "请选择证书来源:"
    yellow "1. acme.sh 自动申请并安装 (带自动续期钩子，推荐)"
    yellow "2. 手动指定现有证书路径 (自定义 crt 与 key)"
    readp "请选择 [1/2] (默认1):" ctype || return 1

    ensure_config_dirs || return 1
    local cert_dir="$CONFIG_DIR/certs/$domain"
    local cert_path="$cert_dir/cert.crt"
    local key_path="$cert_dir/private.key"
    local cert_src=""
    mkdir -p "$cert_dir" && chmod 750 "$cert_dir"

    if [[ -z $ctype || $ctype == "1" ]]; then
        local existing_email=""
        [[ -f $ACME_HOME/account.conf ]] && existing_email=$(acme_conf_get "$ACME_HOME/account.conf" ACCOUNT_EMAIL)
        if [[ -n $existing_email ]]; then
            email="$existing_email"
            blue "沿用已注册的 acme.sh 账户邮箱: $email"
        else
            readp "请输入申请通知邮箱（回车默认 admin@$domain）:" email || return 1
            [[ -z $email ]] && email="admin@${domain}"
            valid_email "$email" || { red "邮箱格式错误"; return 1; }
        fi

        green "正在为域名 $domain 申请证书..."
        if ! issue_cert_standalone "$domain" "$email"; then
            red "证书申请失败，请排查："
            yellow "1. 域名 DNS (A/AAAA) 是否已准确解析到本服务器公网 IP"
            yellow "2. 本机及云服务商安全组 80 端口是否完全放行"
            yellow "3. 检查是否达到 Let's Encrypt 频率限制"
            return 1
        fi

        local ecc_args=() conf=""
        if [[ $ACME_LAST_ECC -eq 1 ]]; then
            ecc_args=(--ecc)
            conf="$ACME_HOME/${domain}_ecc/$domain.conf"
        else
            conf="$ACME_HOME/$domain/$domain.conf"
        fi
        # 安装阶段先以 true 占位，避免在 Caddyfile 更新前重启或被旧配置阻断，随后立即写入真实 reloadcmd
        if ! "$ACME_BIN" --install-cert -d "$domain" "${ecc_args[@]}" \
            --key-file "$key_path" \
            --fullchain-file "$cert_path" \
            --reloadcmd "true"; then
            red "acme.sh install-cert 执行失败，证书未安装"
            return 1
        fi
        if [[ -f $conf ]]; then
            acme_conf_set "$conf" Le_ReloadCmd "$ACME_RELOAD_CMD" base64 || true
        fi
        # 若此前存在旧版 RSA 证书目录且本次已强制签发为 ECC，清理旧目录避免重复续期
        if [[ $ACME_LAST_ECC -eq 1 && -f $ACME_HOME/$domain/$domain.conf ]]; then
            local old_real
            old_real=$(acme_conf_get "$ACME_HOME/$domain/$domain.conf" Le_RealFullChainPath)
            if [[ -z $old_real || $old_real == "$cert_path" ]]; then
                "$ACME_BIN" --remove -d "$domain" >/dev/null 2>&1 || true
                rm -rf "${ACME_HOME:?}/$domain"
            fi
        fi
        cert_src="acme"
        green "已注册 acme.sh 自动续期与无感重载钩子"
    elif [[ $ctype == "2" ]]; then
        readp "请输入证书公钥文件路径 (如 /root/cert.crt):" user_cert || return 1
        readp "请输入证书私钥文件路径 (如 /root/private.key):" user_key || return 1
        [[ ! -f $user_cert ]] && { red "证书文件 $user_cert 不存在"; return 1; }
        [[ ! -f $user_key ]] && { red "私钥文件 $user_key 不存在"; return 1; }
        validate_cert_key_pair "$user_cert" "$user_key" || return 1
        # 若此前由 acme.sh 托管，切换为手动证书时清除旧续期任务，防止到期被静默覆盖
        cleanup_domain_acme "$domain"
        write_file_atomic "$cert_path" 644 < "$user_cert" || return 1
        write_file_atomic "$key_path" 600 < "$user_key" || return 1
        cert_src="manual"
        yellow "提示: 手动指定的证书不会自动续期，到期前请重新配置"
    else
        red "输入错误"
        return 1
    fi

    if [[ ! -s $cert_path || ! -s $key_path ]]; then
        red "证书写入失败，证书文件大小异常"
        return 1
    fi
    sync_runtime_permissions

    DOMAIN_CERT[$domain]=$cert_path
    DOMAIN_KEY[$domain]=$key_path
    DOMAIN_CERT_SRC[$domain]=$cert_src
    save_domains || return 1
    green "证书配置成功: $cert_path"

    [[ $norestart == norestart ]] && return 0
    if [[ -f $SERVICEFILE ]]; then
        if generate_caddyfile && reload_or_restart_service; then
            green "新证书已生效"
        else
            red "配置生成或服务重载失败，请检查上方错误信息"
            return 1
        fi
    fi
}

#===============================================================================
# 自签回退证书 (隔离裸 IP / 未知 SNI 扫描，防止暴露真实代理域名证书)
#===============================================================================
ensure_fallback_cert(){
    if [[ -s $FALLBACK_CERT && -s $FALLBACK_KEY ]] \
        && openssl x509 -checkend 2592000 -noout -in "$FALLBACK_CERT" 2>/dev/null; then
        return 0
    fi
    mkdir -p "$FALLBACK_CERT_DIR" || return 1
    local tmp_cert tmp_key
    tmp_cert=$(mktemp "${FALLBACK_CERT}.XXXXXX") || return 1
    tmp_key=$(mktemp "${FALLBACK_KEY}.XXXXXX") || { rm -f "$tmp_cert"; return 1; }
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$tmp_key" -out "$tmp_cert" -days 3650 -nodes -subj "/CN=localhost" >/dev/null 2>&1; then
        chmod 644 "$tmp_cert" && chmod 600 "$tmp_key" \
            && mv -f "$tmp_cert" "$FALLBACK_CERT" && mv -f "$tmp_key" "$FALLBACK_KEY"
        sync_runtime_permissions
        return 0
    fi
    rm -f "$tmp_cert" "$tmp_key"
    return 1
}

#===============================================================================
# 生成 Caddyfile 配置
# 先写临时文件并校验，通过后再替换正式配置；失败时原配置保持不变
#===============================================================================
emit_reverse_proxy_block(){
    local backend=$1 indent=$2 url host_hdr
    url=$(backend_url "$backend")
    if backend_has_explicit_port "$backend"; then
        host_hdr="{upstream_hostport}"
    else
        host_hdr="{upstream_host}"
    fi
    printf '%sreverse_proxy %s {\n' "$indent" "$url"
    printf '%s\theader_up Host %s\n' "$indent" "$host_hdr"
    printf '%s}\n' "$indent"
}

generate_caddyfile(){
    green "\n===== 生成 Caddyfile 配置 ====="
    load_config
    ensure_config_dirs || return 1

    local users=() domains=() u d p i
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

    ensure_fallback_cert || { red "生成默认回退证书失败"; return 1; }

    local tmp catch_all="" sni_list=""
    for p in "${PROXY_PORTS[@]}"; do catch_all+=":${p}, "; done
    for d in "${domains[@]}"; do sni_list+="'${d}', "; done
    sni_list="${sni_list%, }"

    tmp=$(mktemp "${CADDYFILE}.XXXXXX") || return 1
    {
        printf '{\n'
        printf '\tadmin unix/%s\n' "$ADMIN_SOCK"
        printf '\tpersist_config off\n'
        printf '\torder forward_proxy first\n'
        printf '\thttp_port %s\n' "${1:-80}"
        printf '\thttps_port %s\n' "${PROXY_PORTS[0]}"
        printf '\tauto_https off\n'
        printf '}\n\n'

        # 通配端口块统一处理代理 CONNECT：
        # 1) 裸 IP / 未知 SNI 仅看到自签回退证书并直接断开，不暴露真实域名证书
        # 2) 已知 SNI 先经 forward_proxy 鉴权，鉴权失败按实际 SNI 精准回退到各自伪装后端
        printf '%s {\n' "${catch_all%, }"
        printf '\ttls %s %s\n' "$FALLBACK_CERT" "$FALLBACK_KEY"
        printf '\t@known_sni expression {http.request.tls.server_name} in [%s]\n' "$sni_list"
        printf '\thandle @known_sni {\n'
        printf '\t\troute {\n'
        printf '\t\t\tforward_proxy {\n'
        for u in "${users[@]}"; do
            printf '\t\t\t\tbasic_auth %s %s\n' "$u" "${USER_PASS[$u]}"
        done
        printf '\t\t\t\thide_ip\n'
        printf '\t\t\t\thide_via\n'
        printf '\t\t\t\tprobe_resistance\n'
        printf '\t\t\t}\n'
        for (( i = 0; i < ${#domains[@]}; i++ )); do
            d="${domains[$i]}"
            printf "\t\t\t@sni_%d expression {http.request.tls.server_name} == '%s'\n" "$i" "$d"
            printf '\t\t\thandle @sni_%d {\n' "$i"
            emit_reverse_proxy_block "${DOMAIN_BACKEND[$d]}" $'\t\t\t\t'
            printf '\t\t\t}\n'
        done
        printf '\t\t}\n'
        printf '\t}\n'
        printf '\thandle {\n'
        printf '\t\tabort\n'
        printf '\t}\n'
        printf '}\n'

        # 各域名独立站点块提供各自 SNI 证书与正常浏览器访问伪装
        for d in "${domains[@]}"; do
            local headers=""
            for p in "${PROXY_PORTS[@]}"; do headers+="${d}:${p}, "; done
            printf '\n%s {\n' "${headers%, }"
            printf '\ttls %s %s\n' "${DOMAIN_CERT[$d]}" "${DOMAIN_KEY[$d]}"
            emit_reverse_proxy_block "${DOMAIN_BACKEND[$d]}" $'\t'
            printf '}\n'
        done
    } > "$tmp"
    chmod 640 "$tmp"

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
    sync_runtime_permissions
    green "Caddyfile 生成完成并通过语法校验: $CADDYFILE"
}

#===============================================================================
# 服务控制
#===============================================================================
suss_service(){
    if systemctl restart naiveproxy && systemctl is-active --quiet naiveproxy && [[ -f $CADDYFILE ]]; then
        green "NaiveProxy 服务启动成功"
        return 0
    fi
    red "NaiveProxy 服务启动失败"
    journalctl -u naiveproxy -n 20 --no-pager -e
    return 1
}

reload_or_restart_service(){
    green "\n===== 重载/重启服务 ====="
    systemctl daemon-reload
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        if systemctl reload naiveproxy 2>/dev/null && systemctl is-active --quiet naiveproxy; then
            green "NaiveProxy 配置已无感热重载"
            return 0
        fi
        yellow "热重载未成功，回退为重启服务..."
    fi
    suss_service
}

restart_service(){
    green "\n===== 重启服务 ====="
    systemctl daemon-reload
    suss_service
}

generate_and_restart(){
    generate_caddyfile || return 1
    reload_or_restart_service || return 1
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
# 显示分享信息 (支持 HTTP/2 naive+https 与 HTTP/3 naive+quic)
#===============================================================================
cleanup_share_files(){
    rm -f "$NAIVE_DIR"/v2rayn_*.json "$NAIVE_DIR/v2rayn.json" "$NAIVE_DIR/URL.txt"
}

config_has_unapplied_changes(){
    [[ -f $CADDYFILE ]] || return 1
    local f
    for f in "$USERS_FILE" "$DOMAINS_FILE" "$PORTS_FILE"; do
        [[ -f $f && $f -nt $CADDYFILE ]] && return 0
    done
    return 1
}

show_share(){
    if ! systemctl is-active --quiet naiveproxy || [[ ! -f $CADDYFILE ]]; then
        red "NaiveProxy 未正常运行，请先确认服务已启动" && return 1
    fi
    load_config
    mkdir -p "$NAIVE_DIR" && chmod 700 "$NAIVE_DIR"

    if config_has_unapplied_changes; then
        yellow "警告: 检测到用户/域名/端口配置晚于当前 Caddyfile 修改，以下部分变更可能尚未生效，建议先执行【12】！"
    fi

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
    # 无论当前是否还有可用配置，先清理旧凭据文件防止已删除用户残留
    cleanup_share_files
    if [[ ${#domains[@]} -eq 0 || ${#users[@]} -eq 0 ]]; then
        yellow "暂无可用的用户或已配置证书的域名"
        return 0
    fi

    local primary_domain="${domains[0]}"
    local primary_port="${PROXY_PORTS[0]:-443}"
    local url_file="$NAIVE_DIR/URL.txt"
    local urls=()

    echo
    green "V2rayN / NaiveProxy 客户端配置 (已按用户保存至 $NAIVE_DIR/，HTTP/3 可将 https:// 改为 quic://)："
    for u in "${users[@]}"; do
        userinfo="$(urlencode "$u"):$(urlencode "${USER_PASS[$u]}")"
        fname="${u//[^A-Za-z0-9_-]/_}"
        write_file_atomic "$NAIVE_DIR/v2rayn_${fname}.json" 600 <<EOF
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://${userinfo}@${primary_domain}:${primary_port}"
}
EOF
        echo -e "${yellow}--- 用户: $u (配置: $NAIVE_DIR/v2rayn_${fname}.json) ---${plain}"
        cat "$NAIVE_DIR/v2rayn_${fname}.json"
        echo
    done
    # 兼容原版 v2rayn.json (按字典序第一个用户，原子写入保证 600 权限)
    write_file_atomic "$NAIVE_DIR/v2rayn.json" 600 < "$NAIVE_DIR/v2rayn_${users[0]//[^A-Za-z0-9_-]/_}.json"

    green "NaiveProxy 节点分享链接 (HTTP/2 与 HTTP/3 QUIC，已写入 $url_file)："
    for u in "${users[@]}"; do
        userinfo="$(urlencode "$u"):$(urlencode "${USER_PASS[$u]}")"
        for d in "${domains[@]}"; do
            for p in "${PROXY_PORTS[@]}"; do
                url="naive+https://${userinfo}@${d}:${p}?padding=true#NaiveProxy-$(urlencode "$u")-${d}-${p}-H2"
                urls+=("$url")
                yellow "$url"
                url="naive+quic://${userinfo}@${d}:${p}?padding=true#NaiveProxy-$(urlencode "$u")-${d}-${p}-H3"
                urls+=("$url")
                blue "$url"
            done
        done
    done
    printf '%s\n' "${urls[@]}" | write_file_atomic "$url_file" 600

    if [[ ${#users[@]} -lt ${#USER_PASS[@]} ]]; then
        yellow "部分用户因用户名或密码含特殊字符未生成链接，请通过【5】重新设置密码"
    fi

    if command -v qrencode &>/dev/null && [[ ${#urls[@]} -gt 0 ]]; then
        echo
        green "二维码分享 (首个 HTTP/2 节点)："
        qrencode -o - -t ANSIUTF8 "${urls[0]}"
        blue "提示: 全部 H2/H3 节点链接已保存于 $url_file，可直接导入支持 Naive 协议的客户端"
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
    echo -e "服务状态: $service_status  内核版本: ${blue}$(installed_caddy_version || echo 未安装)${plain}  运行用户: ${blue}$SERVICE_USER${plain}"

    echo ""
    echo -e "${bblue}─────────────────── 监听端口 ───────────────────${plain}"
    echo -e "  配置端口: ${green}${PROXY_PORTS[*]}${plain}"
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        local self_pid
        self_pid=$(systemctl show -p MainPID --value naiveproxy 2>/dev/null || true)
        if [[ $self_pid =~ ^[1-9][0-9]*$ ]]; then
            ss -Htulnp 2>/dev/null | awk -v p="pid=${self_pid}," '$0 ~ p {print "  实际监听: " $1 " " $5}' | sort -u
        fi
    fi

    echo ""
    echo -e "${bblue}─────────────────── 用户列表 ───────────────────${plain}"
    local u d
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        echo -e "  ${yellow}暂无用户${plain}"
    else
        while IFS= read -r u; do
            echo -e "  ${green}用户:${plain} $u  ${green}密码:${plain} $(mask_secret "${USER_PASS[$u]}")  ${green}邮箱:${plain} ${USER_EMAIL[$u]:-未设置}"
        done < <(sorted_users)
    fi

    echo ""
    echo -e "${bblue}─────────────────── 域名列表 ───────────────────${plain}"
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        echo -e "  ${yellow}暂无域名${plain}"
    else
        while IFS= read -r d; do
            echo -e "  ${green}域名:${plain} $d  ${green}伪装后端:${plain} $(backend_url "${DOMAIN_BACKEND[$d]}")  ${green}证书状态:${plain} $(get_cert_status_desc "${DOMAIN_CERT[$d]:-}")"
        done < <(sorted_domains)
    fi

    echo ""
    echo -e "${bblue}─────────────────── VPS 状态 ───────────────────${plain}"
    refresh_bbr_status
    echo -e "  ${green}系统:${plain} $op  ${green}内核:${plain} $kernel_version  ${green}架构:${plain} $cpu  ${green}虚拟化:${plain} $vi  ${green}BBR:${plain} $bbr"

    detect_ips_and_warp
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
    if generate_caddyfile && reload_or_restart_service; then
        show_share
        return 0
    fi
    red "端口变更未生效，已恢复为: ${old_ports[*]}"
    PROXY_PORTS=("${old_ports[@]}")
    save_ports
    generate_caddyfile >/dev/null 2>&1 && reload_or_restart_service >/dev/null 2>&1 || true
    return 1
}

multi_port(){
    load_config
    local old_ports=("${PROXY_PORTS[@]}") p choose="" newport="" del_p=""
    green "\n当前 NaiveProxy 代理正在监听的端口："
    blue "${PROXY_PORTS[*]}"

    echo
    readp "1. 添加新端口复用\n2. 删除已添加端口\n3. 恢复仅使用 443 端口\n0. 返回上层\n请选择 [0-3]:" choose || return 1

    if [[ $choose == "0" ]]; then
        return 0
    elif [[ $choose == "1" ]]; then
        readp "请输入要新增的端口 [1-65535]:" newport || return 1
        valid_port "$newport" || { red "端口格式错误，必须为 1-65535 的整数"; return 1; }
        [[ $newport == 80 ]] && { red "80 端口用于证书签发，不能作为代理端口"; return 1; }
        if [[ " ${PROXY_PORTS[*]} " == *" $newport "* ]]; then
            yellow "端口 $newport 已在监听列表中"
            return 0
        fi
        check_port "$newport" || { red "端口 $newport 已被系统其他进程占用"; return 1; }

        PROXY_PORTS+=("$newport")
        [[ $AUTO_OPEN_FW -eq 1 ]] && open_port "$newport" both
        apply_ports_change "${old_ports[@]}" || { [[ $AUTO_OPEN_FW -eq 1 ]] && close_port "$newport"; return 1; }
    elif [[ $choose == "2" ]]; then
        if [[ ${#PROXY_PORTS[@]} -le 1 ]]; then
            red "当前仅有 1 个端口 (${PROXY_PORTS[0]})，无法继续删除"
            return 1
        fi
        readp "请输入要删除的端口号 (${PROXY_PORTS[*]}):" del_p || return 1
        [[ -z $del_p ]] && { blue "已取消"; return 0; }
        [[ " ${PROXY_PORTS[*]} " == *" $del_p "* ]] || { red "未找到端口 $del_p"; return 1; }
        local new_ports=()
        for p in "${PROXY_PORTS[@]}"; do
            [[ $p != "$del_p" ]] && new_ports+=("$p")
        done
        PROXY_PORTS=("${new_ports[@]}")
        apply_ports_change "${old_ports[@]}" && close_port "$del_p"
    elif [[ $choose == "3" ]]; then
        local had_443=0
        if [[ " ${PROXY_PORTS[*]} " == *" 443 "* ]]; then
            had_443=1
        else
            check_port 443 || { red "端口 443 已被系统其他进程占用"; return 1; }
        fi
        PROXY_PORTS=(443)
        [[ $AUTO_OPEN_FW -eq 1 && $had_443 -eq 0 ]] && open_port 443 both
        if ! apply_ports_change "${old_ports[@]}"; then
            [[ $AUTO_OPEN_FW -eq 1 && $had_443 -eq 0 ]] && close_port 443
            return 1
        fi
        for p in "${old_ports[@]}"; do
            [[ $p != 443 ]] && close_port "$p"
        done
        return 0
    else
        red "输入错误，请输入 0-3 之间的数字"
        return 1
    fi
}

#===============================================================================
# 快捷命令与脚本更新
#===============================================================================
validate_script(){
    local f=$1
    [[ -s $f ]] && head -n 1 "$f" | grep -q '^#!/bin/bash' \
        && grep -q 'NaiveProxy' "$f" \
        && grep -q 'ASSET_SHA256' "$f" \
        && bash -n "$f" 2>/dev/null
}

# 安装脚本到 $INSTALL_SCRIPT，并复制当前架构所需的依赖包到 $SHARE_DIR，供 na 运行时使用
install_shortcut(){
    mkdir -p "${INSTALL_SCRIPT%/*}" || return 1
    if [[ -n $SCRIPT_PATH && $SCRIPT_PATH != "$INSTALL_SCRIPT" ]]; then
        cp -f "$SCRIPT_PATH" "$INSTALL_SCRIPT" || return 1
    elif [[ -z $SCRIPT_PATH ]]; then
        # 通过 bash <(curl ...) 执行时始终拉取最新脚本覆盖旧的 $INSTALL_SCRIPT
        local tmp
        tmp=$(mktemp) || return 1
        if ! download "$REPO_URL/naiveproxy.sh" "$tmp" || ! validate_script "$tmp"; then
            rm -f "$tmp"
            [[ -f $INSTALL_SCRIPT ]] || return 1
        else
            mv -f "$tmp" "$INSTALL_SCRIPT" || { rm -f "$tmp"; return 1; }
        fi
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
    ensure_nat64 ask
    yellow "正在从仓库获取最新脚本: $REPO_URL/naiveproxy.sh ..."
    mkdir -p "${INSTALL_SCRIPT%/*}" || return 1
    local tmp new_sha cur_sha="" yn=""
    tmp=$(mktemp "${INSTALL_SCRIPT}.XXXXXX") || return 1
    if ! download "$REPO_URL/naiveproxy.sh" "$tmp"; then
        rm -f "$tmp"
        red "获取脚本更新失败，请检查网络或仓库地址设置"
        return 1
    fi
    if ! validate_script "$tmp"; then
        rm -f "$tmp"
        red "下载的文件语法或结构校验失败，更新终止"
        return 1
    fi
    new_sha=$(sha256sum "$tmp" | awk '{print $1}')
    [[ -f $INSTALL_SCRIPT ]] && cur_sha=$(sha256sum "$INSTALL_SCRIPT" | awk '{print $1}')
    if [[ -n $cur_sha && $cur_sha == "$new_sha" ]]; then
        rm -f "$tmp"
        green "当前 $INSTALL_SCRIPT 已是最新版本 (SHA256: ${new_sha:0:12}...)"
        return 0
    fi
    blue "新版本 SHA256: $new_sha"
    readp "确认更新并覆盖 $INSTALL_SCRIPT ？(Y/n):" yn || { rm -f "$tmp"; return 1; }
    if [[ $yn == n || $yn == N ]]; then
        rm -f "$tmp"
        blue "已取消更新"
        return 0
    fi
    chmod 755 "$tmp"
    # 始终更新安装副本；rename 替换不影响当前正在执行的脚本
    mv -f "$tmp" "$INSTALL_SCRIPT" || { rm -f "$tmp"; return 1; }
    ln -sfn "$INSTALL_SCRIPT" "$SHORTCUT" || return 1
    green "脚本已更新至 $INSTALL_SCRIPT，请重新运行快捷命令 na。"
    if [[ -n $SCRIPT_PATH && $SCRIPT_PATH != "$INSTALL_SCRIPT" && -d $SCRIPT_DIR/.git ]]; then
        yellow "当前运行的 $SCRIPT_PATH 位于 git 克隆目录，未被修改，请使用 git pull 更新"
    fi
    exit 0
}

update_kernel(){
    local cur_ver yn=""
    green "\n===== 更新内核 ====="
    cur_ver=$(installed_caddy_version || true)
    [[ -n $cur_ver ]] && blue "当前已安装内核版本: $cur_ver (脚本内置预编译版本: $BUNDLED_CADDY_VERSION)"
    if [[ $cur_ver == "$BUNDLED_CADDY_VERSION" ]]; then
        yellow "提示: 若希望升级预编译版本，请先执行【19】更新脚本，或在下方选择【2】在线编译最新内核。"
        readp "是否仍继续执行安装/重装？(y/N):" yn || return 1
        [[ $yn == y || $yn == Y ]] || return 0
    fi
    install_caddy || return 1
    if systemctl is-active --quiet naiveproxy; then
        suss_service || return 1
    fi
    green "内核更新成功"
}

#===============================================================================
# 一键安装向导 (配置失败时自动回滚原有配置)
#===============================================================================
quick_install(){
    local rein="" port="" backup_dir=""
    local prev_domains=() prev_ports=() d p

    ensure_config_dirs || return 1
    load_config
    mapfile -t prev_domains < <(sorted_domains)
    prev_ports=("${PROXY_PORTS[@]}")

    if [[ -s $CADDYFILE ]]; then
        yellow "检测到已存在 NaiveProxy 配置，继续安装将重新初始化用户、域名与端口配置。"
        readp "是否继续全新安装？(y/n):" rein || return 1
        [[ $rein != y && $rein != Y ]] && { blue "已取消"; return 0; }
        backup_dir=$(mktemp -d) || return 1
        cp -a "$USERS_FILE" "$DOMAINS_FILE" "$PORTS_FILE" "$backup_dir/" 2>/dev/null || true
    fi

    rollback_quick_install(){
        if [[ -n $backup_dir && -d $backup_dir ]]; then
            cp -a "$backup_dir"/* "$CONFIG_DIR/" 2>/dev/null || true
            chmod 600 "$USERS_FILE" "$DOMAINS_FILE" "$PORTS_FILE" 2>/dev/null || true
            rm -rf "$backup_dir"
            load_config
            yellow "安装未完成，已恢复原有用户/域名/端口配置"
        fi
    }

    ensure_nat64 ask
    check_deps auto || { rollback_quick_install; return 1; }
    install_caddy || { rollback_quick_install; return 1; }
    install_service || { rollback_quick_install; return 1; }

    echo
    yellow "===== 配置首个用户 ====="
    prompt_user_pass || { rollback_quick_install; return 1; }

    echo
    yellow "===== 配置首个域名 ====="
    prompt_domain_backend || { rollback_quick_install; return 1; }

    echo
    yellow "===== 设置监听端口 ====="
    readp "请输入主端口 [1-65535]（回车默认 443）:" port || { rollback_quick_install; return 1; }
    [[ -z $port ]] && port="443"
    valid_port "$port" || { red "端口格式不合法"; rollback_quick_install; return 1; }
    [[ $port == 80 ]] && { red "80 端口用于证书签发，不能作为代理端口"; rollback_quick_install; return 1; }
    check_port "$port" || { red "端口 $port 已被其他进程占用"; rollback_quick_install; return 1; }

    USER_PASS=()
    USER_EMAIL=()
    USER_PASS[$NEW_USER]=$NEW_PASS
    save_users || { rollback_quick_install; return 1; }

    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    DOMAIN_CERT_SRC=()
    DOMAIN_BACKEND[$NEW_DOMAIN]=$NEW_BACKEND
    save_domains || { rollback_quick_install; return 1; }

    PROXY_PORTS=("$port")
    save_ports || { rollback_quick_install; return 1; }

    openyn || { rollback_quick_install; return 1; }
    apply_cert "$NEW_DOMAIN" norestart || { rollback_quick_install; return 1; }
    generate_caddyfile 80 || { rollback_quick_install; return 1; }

    if suss_service; then
        # 全新安装成功后，再清理重装前已被替换掉的旧域名证书续期与旧端口规则
        if [[ -n $backup_dir && -d $backup_dir ]]; then
            for d in "${prev_domains[@]}"; do
                if [[ $d != "$NEW_DOMAIN" ]]; then
                    local old_c="$CONFIG_DIR/certs/$d/cert.crt"
                    DOMAIN_CERT[$d]="$old_c"
                    cleanup_domain_acme "$d"
                    unset 'DOMAIN_CERT[$d]'
                    rm -rf "${CONFIG_DIR:?}/certs/${d:?}"
                fi
            done
            for p in "${prev_ports[@]}"; do
                [[ $p != "$port" ]] && close_port "$p"
            done
            rm -rf "$backup_dir"
        fi
        install_shortcut || yellow "快捷命令 na 安装失败，可手动执行 bash $INSTALL_SCRIPT"
        show_share
    else
        rollback_quick_install
        return 1
    fi
}

#===============================================================================
# 卸载
#===============================================================================
uninstall(){
    local confirm="" rm_acme="" rm_user="" d
    echo
    yellow "===== 卸载 NaiveProxy ====="
    readp "确认完全卸载 NaiveProxy？(输入y确认):" confirm || return 1
    [[ $confirm != y && $confirm != Y ]] && { blue "已取消"; return 0; }

    load_config
    systemctl stop naiveproxy 2>/dev/null || true
    systemctl disable naiveproxy 2>/dev/null || true
    rm -f "$SERVICEFILE"
    systemctl daemon-reload

    # 仅移除经核验由本脚本托管的证书续期任务，不误删外部服务证书
    if [[ -x $ACME_BIN ]]; then
        for d in "${!DOMAIN_BACKEND[@]}"; do
            cleanup_domain_acme "$d"
        done
        readp "是否同时卸载 acme.sh？(本机其他服务使用 acme.sh 管理证书时请选 n) (y/N):" rm_acme || rm_acme="n"
        if [[ $rm_acme == y || $rm_acme == Y ]]; then
            "$ACME_BIN" --uninstall >/dev/null 2>&1 || true
            rm -rf "${ACME_HOME:?}"
        fi
    fi

    close_port
    remove_nat64

    # 仅删除本脚本独立安装的二进制与目录，不触碰系统 /usr/bin/caddy 与用户自定义脚本路径
    rm -f "$BINARY" "$CADDY_VERSION_FILE" "$LEGACY_VERSION_FILE" /etc/caddy/v
    rmdir /etc/caddy 2>/dev/null || true
    rm -rf "${CONFIG_DIR:?}" "${NAIVE_DIR:?}" "${SHARE_DIR:?}" "${RUN_DIR:?}"
    rm -f "$SHORTCUT" "$INSTALL_SCRIPT" /etc/profile.d/naiveproxy-go.sh /run/naiveproxy-acme-stopped
    # 清理旧版以 root 运行 Caddy 时可能遗留的含凭据 autosave.json
    rm -f /root/.config/caddy/autosave.json

    if id -u "$SERVICE_USER" &>/dev/null; then
        readp "是否同时删除专用系统用户 $SERVICE_USER？(Y/n):" rm_user || rm_user="y"
        if [[ $rm_user != n && $rm_user != N ]]; then
            userdel "$SERVICE_USER" 2>/dev/null || true
            groupdel "$SERVICE_USER" 2>/dev/null || true
        fi
    fi

    USER_PASS=()
    USER_EMAIL=()
    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    DOMAIN_CERT_SRC=()
    PROXY_PORTS=(443)

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
    local follow=""
    echo
    yellow "正在展示最近 50 行日志："
    journalctl -u naiveproxy -n 50 --no-pager
    echo
    readp "是否进入实时跟踪日志模式？(y/n，回车跳过，Ctrl+C 返回菜单):" follow || return 0
    if [[ $follow == y || $follow == Y ]]; then
        # 仅中断 journalctl -f，不退出整个管理面板
        trap ':' INT
        journalctl -u naiveproxy -f || true
        trap - INT
    fi
}

#===============================================================================
# 主菜单
#===============================================================================
main_menu(){
    local Input=""
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
        green "12. 生成配置并热重载服务"
        green "13. 启动服务"
        green "14. 停止服务"
        green "15. 多端口复用管理 (新增/删除/还原)"
        white "----------------------------------------------------------------------------------"
        green "16. 查看运行状态"
        green "17. 查看节点分享信息 (H2/H3/多用户/二维码)"
        green "18. 查看服务日志"
        green "19. 更新脚本"
        green "20. 更新内核"
        green "21. 开启 BBR 与 QUIC 拥塞/缓冲优化"
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

        readp "请输入数字【0-21】:" Input || exit 0
        case "$Input" in
            1) run_action quick_install;;
            2) run_action uninstall;;
            3) run_action install_caddy;;
            4) run_action install_service;;
            5) run_action add_user;;
            6) run_action del_user;;
            7) run_action view_users_menu;;
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
