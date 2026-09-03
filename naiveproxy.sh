#!/bin/bash
#===============================================================================
# NaiveProxy 多用户管理增强版 - 完整修复与优化版
# 功能：多用户、多域名、自动化证书申请与续期、多端口复用、HTTP/3 支持、安全加固
#===============================================================================

export LANG=en_US.UTF-8
set -E
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
# 权限检查
#===============================================================================
[[ $EUID -ne 0 ]] && yellow "请以root模式运行脚本" && exit 1

#===============================================================================
# 配置路径定义
#===============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
LOCAL_ASSETS_DIR="$SCRIPT_DIR/assets"
REPO_URL="${REPO_URL:-https://raw.githubusercontent.com/rainsmen/naivesh/main}"

CONFIG_DIR="/etc/naiveproxy"
USERS_FILE="$CONFIG_DIR/users.conf"
DOMAINS_FILE="$CONFIG_DIR/domains.conf"
PORTS_FILE="$CONFIG_DIR/ports.conf"
CADDYFILE="$CONFIG_DIR/Caddyfile"
SERVICEFILE="/etc/systemd/system/naiveproxy.service"
BINARY="/usr/bin/caddy"
NAIVE_DIR="/root/naive"
BACKUP_CADDYFILE="$CONFIG_DIR/reCaddyfile"
ACME_HOME="/root/.acme.sh"
ACME_BIN="$ACME_HOME/acme.sh"

declare -gA USER_PASS USER_EMAIL DOMAIN_BACKEND DOMAIN_CERT DOMAIN_KEY
declare -ga PROXY_PORTS

#===============================================================================
# 全局变量 - 系统检测
#===============================================================================
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
        vsid="${VERSION_ID:-}"
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
    
    # 检测架构
    case "$(uname -m)" in
        x86_64) cpu="amd64" ;;
        aarch64|arm64) cpu="arm64" ;;
        *) red "目前脚本仅支持 x86_64 (amd64) 与 aarch64 (arm64) 架构" && exit 1 ;;
    esac
    
    # 内核版本
    kernel_version=$(uname -r | cut -d "-" -f1)
    
    # 虚拟化检测
    vi=$(systemd-detect-virt 2>/dev/null || true)
    [[ -z $vi ]] && vi="none"
    
    # BBR状态检测
    local cc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ -n $cc ]]; then
        bbr="$cc"
    else
        bbr="未知/不支持"
    fi
    
    # 获取版本信息
    inscore=$(cat /etc/caddy/version 2>/dev/null | head -n 1 || true)
    insV=$(cat /etc/caddy/v 2>/dev/null || true)
    latcore="v2.11.2"
    latestV="本地私有增强版"
}

#===============================================================================
# IPv4/IPv6 地址检测
#===============================================================================
v4v6(){
    v4=$(curl -s4m5 icanhazip.com -k 2>/dev/null || true)
    v6=$(curl -s6m5 icanhazip.com -k 2>/dev/null || true)
}

#===============================================================================
# WARP 状态检测
#===============================================================================
warpcheck(){
    wgcfv6=$(curl -s6m5 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep warp | cut -d= -f2 || true)
    wgcfv4=$(curl -s4m5 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep warp | cut -d= -f2 || true)
}

#===============================================================================
# 纯IPv6 DNS64支持 (安全追加)
#===============================================================================
v6(){
    warpcheck
    if [[ ! $wgcfv4 =~ on|plus && ! $wgcfv6 =~ on|plus ]]; then
        v4=$(curl -s4m5 icanhazip.com -k 2>/dev/null || true)
        if [[ -z $v4 ]]; then
            # 测试外部网络连通性
            if ! curl -m 3 -s https://www.google.com &>/dev/null && ! curl -m 3 -s https://github.com &>/dev/null; then
                yellow "检测到纯 IPv6 VPS 且无法访问外部 IPv4 网络，安全追加 NAT64/DNS64 解析..."
                if ! grep -q "2a00:1098:2b::1" /etc/resolv.conf 2>/dev/null; then
                    echo -e "\n# NaiveProxy NAT64 DNS\nnameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1" >> /etc/resolv.conf
                fi
            fi
        fi
    fi
}

#===============================================================================
# 防火墙端口开放 (支持 TCP 与 UDP / HTTP3)
#===============================================================================
open_port(){
    local port=$1
    local proto=${2:-both} # tcp, udp, both

    [[ -z $port || ! $port =~ ^[0-9]+$ ]] && return 0

    if command -v ufw &>/dev/null; then
        if [[ $proto == "both" || $proto == "tcp" ]]; then
            ufw allow "${port}/tcp" >/dev/null 2>&1 || true
        fi
        if [[ $proto == "both" || $proto == "udp" ]]; then
            ufw allow "${port}/udp" >/dev/null 2>&1 || true
        fi
    fi
    if command -v firewall-cmd &>/dev/null; then
        if [[ $proto == "both" || $proto == "tcp" ]]; then
            firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
        fi
        if [[ $proto == "both" || $proto == "udp" ]]; then
            firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
        fi
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command -v iptables &>/dev/null; then
        if [[ $proto == "both" || $proto == "tcp" ]]; then
            iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
        fi
        if [[ $proto == "both" || $proto == "udp" ]]; then
            iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
        fi
    fi
}

close(){
    open_port 80 tcp
    for p in "${PROXY_PORTS[@]:-443}"; do
        open_port "$p" both
    done
    sleep 1
    blue "执行开放端口 80 (TCP) 与代理端口 ${PROXY_PORTS[*]:-443} (TCP/UDP HTTP/3) 完毕"
    echo "----------------------------------------------------"
}

openyn(){
    red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    readp "是否自动开放端口（80及代理端口 TCP/UDP）？\n1、是，自动放行 (回车默认)\n2、否，我自己手动\n请选择：" action
    if [[ -z $action ]] || [[ "$action" = "1" ]]; then
        close
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
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        green "BBR 已经处于启用状态！"
        return 0
    fi
    
    yellow "正在配置开启 BBR..."
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
    
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        green "BBR 启用成功！"
    else
        yellow "BBR 启用命令已执行，可能需要重启系统生效或当前内核不支持。"
    fi
}

#===============================================================================
# 依赖安装
#===============================================================================
check_deps(){
    local miss=() pkgs=()

    add_pkg(){
        local pkg=$1 existing
        for existing in "${pkgs[@]}"; do
            [[ $existing == "$pkg" ]] && return
        done
        pkgs+=("$pkg")
    }

    for cmd in curl wget tar systemctl ss ip awk grep sed qrencode cron openssl; do
        if [[ $cmd == "cron" ]]; then
            command -v cron &>/dev/null || command -v crond &>/dev/null || miss+=("cron")
        else
            command -v "$cmd" &>/dev/null || miss+=("$cmd")
        fi
    done

    [[ ${#miss[@]} -eq 0 ]] && return 0

    yellow "正在安装缺少的依赖: ${miss[*]}"

    if command -v apt-get &>/dev/null; then
        for cmd in "${miss[@]}"; do
            case "$cmd" in
                ss|ip) add_pkg "iproute2" ;;
                awk) add_pkg "gawk" ;;
                systemctl) add_pkg "systemd" ;;
                cron) add_pkg "cron" ;;
                openssl) add_pkg "openssl" ;;
                *) add_pkg "$cmd" ;;
            esac
        done
        apt-get update -y || return 1
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" || return 1
    elif command -v yum &>/dev/null; then
        for cmd in "${miss[@]}"; do
            case "$cmd" in
                ss|ip) add_pkg "iproute" ;;
                cron) add_pkg "cronie" ;;
                awk) add_pkg "gawk" ;;
                systemctl) add_pkg "systemd" ;;
                openssl) add_pkg "openssl" ;;
                *) add_pkg "$cmd" ;;
            esac
        done
        yum install -y "${pkgs[@]}" || return 1
    elif command -v dnf &>/dev/null; then
        for cmd in "${miss[@]}"; do
            case "$cmd" in
                ss|ip) add_pkg "iproute" ;;
                cron) add_pkg "cronie" ;;
                awk) add_pkg "gawk" ;;
                systemctl) add_pkg "systemd" ;;
                openssl) add_pkg "openssl" ;;
                *) add_pkg "$cmd" ;;
            esac
        done
        dnf install -y "${pkgs[@]}" || return 1
    else
        red "未找到 apt/yum/dnf，无法自动安装依赖: ${miss[*]}"
        return 1
    fi
}

#===============================================================================
# 初始化配置目录与安全权限
#===============================================================================
init_config(){
    mkdir -p "$CONFIG_DIR" "$NAIVE_DIR" /etc/caddy || return 1
    chmod 700 "$CONFIG_DIR" 2>/dev/null || true
    chmod 700 "$NAIVE_DIR" 2>/dev/null || true

    [[ ! -f $USERS_FILE ]] && touch "$USERS_FILE"
    [[ ! -f $DOMAINS_FILE ]] && touch "$DOMAINS_FILE"
    [[ ! -f $PORTS_FILE ]] && echo "443" > "$PORTS_FILE"

    chmod 600 "$USERS_FILE" "$DOMAINS_FILE" "$PORTS_FILE" 2>/dev/null || true
    return 0
}

#===============================================================================
# 加载用户、域名与端口配置
#===============================================================================
load_config(){
    declare -gA USER_PASS USER_EMAIL DOMAIN_BACKEND DOMAIN_CERT DOMAIN_KEY
    declare -ga PROXY_PORTS
    PROXY_PORTS=()

    if [[ -f $PORTS_FILE ]]; then
        while read -r p; do
            [[ -n $p && $p =~ ^[0-9]+$ ]] && PROXY_PORTS+=("$p")
        done < <(grep -v '^#' "$PORTS_FILE" 2>/dev/null)
    fi

    if [[ ${#PROXY_PORTS[@]} -eq 0 ]]; then
        local p
        p=$(get_proxy_port)
        PROXY_PORTS=("${p:-443}")
    fi

    USER_PASS=()
    USER_EMAIL=()
    [[ -f $USERS_FILE ]] && while IFS=: read -r u p e; do
        [[ -n $u && -n $p ]] && USER_PASS[$u]=$p && USER_EMAIL[$u]=$e
    done < <(grep -v '^#' "$USERS_FILE" 2>/dev/null)
    
    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    [[ -f $DOMAINS_FILE ]] && while IFS=: read -r d b c k; do
        [[ -n $d && -n $b ]] && DOMAIN_BACKEND[$d]=$b && DOMAIN_CERT[$d]=$c && DOMAIN_KEY[$d]=$k
    done < <(grep -v '^#' "$DOMAINS_FILE" 2>/dev/null)
    true
}

#===============================================================================
# 保存用户配置
#===============================================================================
save_users(){
    mkdir -p "$CONFIG_DIR"
    {
        echo "# 用户配置 - 格式: 用户名:密码:邮箱"
        for u in "${!USER_PASS[@]}"; do
            echo "${u}:${USER_PASS[$u]}:${USER_EMAIL[$u]:-}"
        done
    } > "$USERS_FILE"
    chmod 600 "$USERS_FILE" 2>/dev/null || true
}

#===============================================================================
# 保存域名配置
#===============================================================================
save_domains(){
    mkdir -p "$CONFIG_DIR"
    {
        echo "# 域名配置 - 格式: 域名:后端:证书路径:密钥路径"
        for d in "${!DOMAIN_BACKEND[@]}"; do
            echo "${d}:${DOMAIN_BACKEND[$d]}:${DOMAIN_CERT[$d]:-}:${DOMAIN_KEY[$d]:-}"
        done
    } > "$DOMAINS_FILE"
    chmod 600 "$DOMAINS_FILE" 2>/dev/null || true
}

#===============================================================================
# 保存端口配置
#===============================================================================
save_ports(){
    mkdir -p "$CONFIG_DIR"
    {
        echo "# 端口配置"
        for p in "${PROXY_PORTS[@]}"; do
            echo "$p"
        done
    } > "$PORTS_FILE"
    chmod 600 "$PORTS_FILE" 2>/dev/null || true
}

#===============================================================================
# 安装 Caddy2-Naiveproxy
#===============================================================================
install_caddy(){
    green "\n===== 安装 Caddy2-Naiveproxy ====="
    yellow "请选择安装方式:"
    yellow "1. 下载预编译版本 (快速，推荐)"
    yellow "2. 在线编译版本 (慢，自动构建最新内核)"
    readp "请选择 [1/2] (默认1):" chcaddy
    
    if [[ -z $chcaddy || $chcaddy == "1" ]]; then
        cd /tmp || return 1
        rm -f caddy2-naive-linux-*.tar.gz caddy.tar.gz caddy
        
        local caddy_pkg="caddy2-naive-linux-${cpu}.tar.gz"
        local local_pkg="$LOCAL_ASSETS_DIR/$caddy_pkg"

        yellow "正在获取 Caddy2-Naiveproxy..."
        if [[ -f "$local_pkg" ]]; then
            blue "检测到本地资产文件，优先使用本地预编译包: $local_pkg"
            cp -f "$local_pkg" /tmp/caddy.tar.gz
        else
            if wget -qN "$REPO_URL/assets/$caddy_pkg" -O /tmp/caddy.tar.gz; then
                :
            elif curl -Ls "$REPO_URL/assets/$caddy_pkg" -o /tmp/caddy.tar.gz; then
                :
            else
                red "下载失败，请检查网络和仓库地址设置: $REPO_URL/assets/$caddy_pkg" && return 1
            fi
        fi
        
        [[ ! -f /tmp/caddy.tar.gz ]] && { red "未找到 Caddy 压缩包"; return 1; }
        tar -zxf /tmp/caddy.tar.gz -C /tmp || { red "解压 Caddy 失败"; return 1; }
        [[ -f /tmp/caddy ]] || { red "压缩包内未找到 caddy 可执行文件"; return 1; }
        mv -f /tmp/caddy "$BINARY" || return 1
        chmod +x "$BINARY" || return 1
        rm -f /tmp/caddy.tar.gz
        
        # 保存版本信息
        mkdir -p /etc/caddy
        echo "$latcore" > /etc/caddy/version 2>/dev/null || true
        
        green "Caddy 安装完成: $($BINARY version 2>&1 | head -1)"
    elif [[ $chcaddy == "2" ]]; then
        yellow "开始在线编译..."
        local total_mem
        total_mem=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}')
        local swap_created=0
        if [[ ${total_mem:-0} -gt 0 && $total_mem -lt 1500 ]]; then
            yellow "当前物理内存仅 ${total_mem}MB，尝试临时配置 2GB Swap 防止编译时 OOM 崩溃..."
            fallocate -l 2G /tmp/swapfile 2>/dev/null || dd if=/dev/zero of=/tmp/swapfile bs=1M count=2048 2>/dev/null || true
            if [[ -f /tmp/swapfile ]]; then
                chmod 600 /tmp/swapfile
                mkswap /tmp/swapfile >/dev/null 2>&1 || true
                swapon /tmp/swapfile >/dev/null 2>&1 && swap_created=1
            fi
        fi

        if ! command -v go &>/dev/null; then
            yellow "安装 Go 环境..."
            if [[ $release = Centos ]]; then
                yum install golang -y 2>/dev/null || dnf install golang -y 2>/dev/null
            elif [[ $release = Debian || $release = Ubuntu ]]; then
                apt-get update -y
                apt-get install -y golang-go 2>/dev/null || {
                    local GO_VER="1.23.6"
                    wget -c "https://golang.google.cn/dl/go${GO_VER}.linux-${cpu}.tar.gz" -O /tmp/go.tar.gz
                    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
                    rm -f /tmp/go.tar.gz
                    export PATH=$PATH:/usr/local/go/bin
                    echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
                }
            fi
        fi
        
        command -v go &>/dev/null || { 
            red "Go 安装失败，无法在线编译"
            [[ $swap_created -eq 1 ]] && swapoff /tmp/swapfile && rm -f /tmp/swapfile
            return 1
        }
        go env -w GO111MODULE=on 2>/dev/null || true
        
        yellow "安装 xcaddy 并构建带 forwardproxy 模块的 Caddy..."
        go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest || {
            red "xcaddy 安装失败"
            [[ $swap_created -eq 1 ]] && swapoff /tmp/swapfile && rm -f /tmp/swapfile
            return 1
        }
        
        local xcaddy_bin
        xcaddy_bin="$(go env GOPATH 2>/dev/null)/bin/xcaddy"
        [[ ! -x $xcaddy_bin ]] && xcaddy_bin="$HOME/go/bin/xcaddy"
        
        "$xcaddy_bin" build --output "$BINARY" --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive
        local build_ret=$?
        
        if [[ $swap_created -eq 1 ]]; then
            swapoff /tmp/swapfile 2>/dev/null || true
            rm -f /tmp/swapfile 2>/dev/null || true
        fi
        
        if [[ $build_ret -eq 0 && -x $BINARY ]]; then
            green "在线编译安装完成: $($BINARY version 2>&1 | head -1)"
        else
            red "编译失败"
            return 1
        fi
    fi
}

#===============================================================================
# 安装 systemd 服务
#===============================================================================
install_service(){
    green "\n===== 安装服务 ====="
    mkdir -p "$(dirname "$SERVICEFILE")" || return 1
    cat > "$SERVICEFILE" <<EOF
[Unit]
Description=NaiveProxy Multi-User Service
Documentation=https://github.com/klzgrad/naiveproxy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BINARY run --config $CADDYFILE --adapter caddyfile
ExecReload=$BINARY reload --config $CADDYFILE --adapter caddyfile
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || return 1
    systemctl enable naiveproxy >/dev/null 2>&1 || return 1
    green "服务安装完成"
}

#===============================================================================
# 端口冲突检测
#===============================================================================
check_port(){
    local port=$1
    if [[ -n $(ss -tunlp 2>/dev/null | grep -w tcp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
        return 1
    fi
    return 0
}

#===============================================================================
# 添加用户
#===============================================================================
add_user(){
    echo
    yellow "===== 添加用户 ====="
    readp "请输入用户名（至少3位，限字母数字下划线，回车随机生成）:" user
    if [[ -z $user ]]; then
        user=$(tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c 6)
        [[ -z $user ]] && user=$(date +%s%N | md5sum | cut -c 1-6)
        blue "随机生成用户名: $user"
    fi
    if [[ ! $user =~ ^[a-zA-Z0-9_]{3,32}$ ]]; then
        red "用户名不合法，必须由 3-32 位字母、数字或下划线组成"
        return 1
    fi
    
    if [[ -n ${USER_PASS[$user]} ]]; then
        yellow "用户 $user 已存在，本次操作将修改其密码"
    fi
    
    readp "请输入密码（至少5位，不可包含冒号或空格，回车随机生成）:" pass
    if [[ -z $pass ]]; then
        pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 12)
        [[ -z $pass ]] && pass=$(date +%s%N | md5sum | cut -c 1-12)
        blue "随机生成密码: $pass"
    fi
    if [[ ! $pass =~ ^[a-zA-Z0-9_@#!.-]{5,64}$ ]]; then
        red "密码不合法（至少5位字符，且不能包含冒号或空格）"
        return 1
    fi
    
    readp "请输入邮箱（可选，回车跳过）:" email
    
    USER_PASS[$user]=$pass
    [[ -n $email ]] && USER_EMAIL[$user]=$email
    
    save_users
    green "用户 $user 保存成功"
    yellow "提示: 增删用户后请执行【12】生成配置并重启以生效！"
}

#===============================================================================
# 删除用户
#===============================================================================
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
    
    unset USER_PASS["$user"]
    unset USER_EMAIL["$user"]
    save_users
    green "用户 $user 已删除"
    yellow "提示: 请执行【12】生成配置并重启以使变更生效！"
}

#===============================================================================
# 用户列表
#===============================================================================
list_users(){
    echo
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        yellow "暂无用户"
        return 0
    fi
    green "─────────── 用户列表 ───────────"
    for u in "${!USER_PASS[@]}"; do
        blue "用户: $u  密码: ${USER_PASS[$u]}  邮箱: ${USER_EMAIL[$u]:-未设置}"
    done
    green "────────────────────────────────"
}

#===============================================================================
# 添加域名
#===============================================================================
add_domain(){
    echo
    yellow "===== 添加域名 ====="
    readp "请输入域名（如 proxy.example.com）:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    
    # 域名格式验证
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
        red "域名格式错误"
        return 1
    fi
    
    readp "请输入反代伪装网址（回车默认 speed.cloudflare.com）:" backend
    [[ -z $backend ]] && backend="speed.cloudflare.com"
    backend="${backend#https://}"
    backend="${backend#http://}"
    backend="${backend%%/*}"
    
    DOMAIN_BACKEND[$domain]=$backend
    DOMAIN_CERT[$domain]="${DOMAIN_CERT[$domain]:-}"
    DOMAIN_KEY[$domain]="${DOMAIN_KEY[$domain]:-}"
    
    save_domains
    green "域名 $domain 添加成功（反代伪装: https://$backend）"
    yellow "请选择【11】申请或配置该域名的 TLS 证书"
}

#===============================================================================
# 删除域名
#===============================================================================
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
    
    unset DOMAIN_BACKEND["$domain"]
    unset DOMAIN_CERT["$domain"]
    unset DOMAIN_KEY["$domain"]
    save_domains
    green "域名 $domain 已删除"
    yellow "提示: 请执行【12】生成配置并重启以生效！"
}

#===============================================================================
# 域名列表
#===============================================================================
list_domains(){
    echo
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        yellow "暂无域名"
        return 0
    fi
    green "─────────── 域名列表 ───────────"
    for d in "${!DOMAIN_BACKEND[@]}"; do
        local cert_st="未申请"
        [[ -n ${DOMAIN_CERT[$d]} && -f ${DOMAIN_CERT[$d]} ]] && cert_st="已配置"
        blue "域名: $d  反代后端: ${DOMAIN_BACKEND[$d]}  证书状态: $cert_st"
    done
    green "────────────────────────────────"
}

#===============================================================================
# acme.sh 安装与安全签发
#===============================================================================
validate_acme_installer(){
    local file="$1"
    if ! grep -q 'PROJECT_NAME="acme.sh"' "$file" 2>/dev/null; then
        red "下载的 acme.sh 校验未通过，已终止执行"
        return 1
    fi
}

install_shortcut(){
    local target="/usr/local/bin/naiveproxy.sh"
    local source_path="${BASH_SOURCE[0]}"

    if [[ -f "$source_path" && "$source_path" != "$target" && "$source_path" != "/dev/fd/"* ]]; then
        cp -f "$source_path" "$target" || return 1
    elif [[ ! -f "$target" ]]; then
        wget -qN "$REPO_URL/naiveproxy.sh" -O "$target" || return 1
    fi

    chmod +x "$target" || return 1
    ln -sf "$target" /usr/bin/na || return 1
}

ensure_acme(){
    local email="$1"
    local installer="/tmp/acme_install.sh"

    if [[ -f "$ACME_BIN" ]]; then
        validate_acme_installer "$ACME_BIN" || return 1
        [[ -x "$ACME_BIN" ]] || chmod +x "$ACME_BIN" || return 1
    else
        yellow "正在安装官方 acme.sh 证书工具..."
        local local_acme="$LOCAL_ASSETS_DIR/acme.sh"
        if [[ -f "$local_acme" ]]; then
            blue "检测到本地 acme.sh 资产，优先使用本地包"
            cp -f "$local_acme" "$installer"
        else
            wget -qN "$REPO_URL/assets/acme.sh" -O "$installer" || curl -Ls "$REPO_URL/assets/acme.sh" -o "$installer" || { red "acme.sh 下载失败"; return 1; }
        fi
        
        validate_acme_installer "$installer" || { rm -f "$installer"; return 1; }
        chmod +x "$installer" || { rm -f "$installer"; return 1; }
        (cd /tmp && "$installer" --install -m "$email" --home "$ACME_HOME" --no-profile) || { rm -f "$installer"; return 1; }
        rm -f "$installer"
    fi

    [[ -x "$ACME_BIN" ]] || { red "acme.sh 安装失败: $ACME_BIN 不存在或不可执行"; return 1; }
    "$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
}

stop_web_services_for_acme(){
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    systemctl stop naiveproxy 2>/dev/null || true
}

issue_cert_standalone(){
    local domain="$1"
    local email="$2"

    ensure_acme "$email" || return 1
    stop_web_services_for_acme
    open_port 80 tcp
    
    yellow "使用 Standalone 模式通过 Let's Encrypt 申请证书..."
    "$ACME_BIN" --issue --server letsencrypt -d "$domain" --standalone -k 2048 --force \
        --pre-hook "systemctl stop naiveproxy nginx apache2 caddy 2>/dev/null || true" \
        --post-hook "systemctl start naiveproxy 2>/dev/null || true"
}

#===============================================================================
# 申请或配置证书
#===============================================================================
apply_cert(){
    echo
    yellow "===== 申请 / 配置证书 ====="
    list_domains
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { red "请先添加域名"; return 1; }
    
    readp "请输入要配置证书的域名:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]} ]] && { red "域名 $domain 未添加，请先在菜单【8】中添加"; return 1; }
    
    echo
    yellow "请选择证书来源:"
    yellow "1. acme.sh 自动申请并安装 (带自动续期钩子，推荐)"
    yellow "2. 手动指定现有证书路径 (自定义 crt 与 key)"
    readp "请选择 [1/2] (默认1):" ctype
    
    local cert_dir="$CONFIG_DIR/certs/$domain"
    mkdir -p "$cert_dir"
    local cert_path="$cert_dir/cert.crt"
    local key_path="$cert_dir/private.key"

    local was_running=0
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        was_running=1
    fi
    
    if [[ -z $ctype || $ctype == "1" ]]; then
        readp "请输入申请通知邮箱（回车默认 admin@$domain）:" email
        [[ -z $email ]] && email="admin@${domain}"
        
        green "正在为域名 $domain 申请证书..."
        if ! issue_cert_standalone "$domain" "$email"; then
            red "证书申请命令失败，请排查："
            yellow "1. 域名 DNS 是否已准确解析到本服务器公网 IP"
            yellow "2. 本机及云服务商安全组 80 端口是否完全放行"
            yellow "3. 检查是否达到 Let's Encrypt 频率限制"
            [[ $was_running -eq 1 ]] && systemctl start naiveproxy 2>/dev/null || true
            return 1
        fi
        
        # 使用官方 install-cert 安装证书并注册 reloadcmd，实现 100% 自动无感续期
        "$ACME_BIN" --install-cert -d "$domain" \
            --key-file "$key_path" \
            --fullchain-file "$cert_path" \
            --reloadcmd "systemctl reload naiveproxy 2>/dev/null || systemctl restart naiveproxy 2>/dev/null || true" >/dev/null 2>&1 || {
                cp -f "$ACME_HOME/$domain/fullchain.cer" "$cert_path" 2>/dev/null || cp -f "$ACME_HOME/${domain}_ecc/fullchain.cer" "$cert_path" 2>/dev/null || true
                cp -f "$ACME_HOME/$domain/$domain.key" "$key_path" 2>/dev/null || cp -f "$ACME_HOME/${domain}_ecc/$domain.key" "$key_path" 2>/dev/null || true
            }
    else
        readp "请输入证书公钥文件路径 (如 /root/cert.crt):" user_cert
        readp "请输入证书私钥文件路径 (如 /root/private.key):" user_key
        [[ ! -f $user_cert ]] && { red "证书文件 $user_cert 不存在"; return 1; }
        [[ ! -f $user_key ]] && { red "私钥文件 $user_key 不存在"; return 1; }
        cp -f "$user_cert" "$cert_path" || return 1
        cp -f "$user_key" "$key_path" || return 1
    fi
    
    chmod 600 "$key_path" 2>/dev/null || true
    chmod 644 "$cert_path" 2>/dev/null || true
    
    if [[ -s $cert_path && -s $key_path ]]; then
        DOMAIN_CERT[$domain]=$cert_path
        DOMAIN_KEY[$domain]=$key_path
        save_domains
        green "证书配置成功: $cert_path"
        if [[ $was_running -eq 1 ]]; then
            generate_caddyfile >/dev/null 2>&1 || true
            systemctl start naiveproxy 2>/dev/null || true
        fi
    else
        red "证书写入失败，证书文件大小异常"
        [[ $was_running -eq 1 ]] && systemctl start naiveproxy 2>/dev/null || true
        return 1
    fi
}

#===============================================================================
# 生成 Caddyfile 配置 (修复多域名与多端口语法)
#===============================================================================
generate_caddyfile(){
    green "\n===== 生成 Caddyfile 配置 ====="
    
    load_config
    [[ ${#USER_PASS[@]} -eq 0 ]] && { red "请先添加至少一个用户"; return 1; }
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { red "请先添加至少一个域名"; return 1; }
    
    if [[ -n $1 ]]; then
        PROXY_PORTS=("$1")
        save_ports
    elif [[ ${#PROXY_PORTS[@]} -eq 0 ]]; then
        PROXY_PORTS=(443)
        save_ports
    fi
    
    local primary_port="${PROXY_PORTS[0]}"
    local http_port=${2:-80}
    
    > "$CADDYFILE"
    
    cat >> "$CADDYFILE" <<EOF
{
    order forward_proxy before reverse_proxy
    http_port $http_port
    https_port $primary_port
    auto_https off
}

EOF
    
    local domain_count=0
    for domain in "${!DOMAIN_BACKEND[@]}"; do
        local cert="${DOMAIN_CERT[$domain]}"
        local key="${DOMAIN_KEY[$domain]}"
        
        if [[ -n $cert && -n $key && -s $cert && -s $key ]]; then
            local site_headers=""
            for p in "${PROXY_PORTS[@]}"; do
                site_headers+="${domain}:${p}, "
            done
            site_headers="${site_headers%, }"
            
            cat >> "$CADDYFILE" <<EOF
$site_headers {
    tls $cert $key
    forward_proxy {
EOF
            for user in "${!USER_PASS[@]}"; do
                echo "        basic_auth ${user} ${USER_PASS[$user]}" >> "$CADDYFILE"
            done
            
            cat >> "$CADDYFILE" <<EOF
        hide_ip
        hide_via
        probe_resistance
    }
    reverse_proxy https://${DOMAIN_BACKEND[$domain]} {
        header_up Host {upstream_hostport}
    }
}

EOF
            ((domain_count++))
        else
            yellow "跳过域名 $domain (证书未正确配置)"
        fi
    done
    
    [[ $domain_count -eq 0 ]] && { red "无可用已配置证书的域名，无法生成配置"; return 1; }
    
    chmod 600 "$CADDYFILE" 2>/dev/null || true
    
    # 语法预校验
    if [[ -x $BINARY ]]; then
        if ! "$BINARY" validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1; then
            red "错误: Caddyfile 语法校验失败！"
            "$BINARY" validate --config "$CADDYFILE" --adapter caddyfile
            return 1
        fi
    fi
    
    cp -f "$CADDYFILE" "$BACKUP_CADDYFILE"
    chmod 600 "$BACKUP_CADDYFILE" 2>/dev/null || true
    green "Caddyfile 生成完成并通过语法校验: $CADDYFILE"
}

#===============================================================================
# 服务启动验证
#===============================================================================
suss_service(){
    systemctl restart naiveproxy
    sleep 2
    if systemctl is-active --quiet naiveproxy && [[ -f $CADDYFILE ]]; then
        green "NaiveProxy 服务启动成功"
        return 0
    else
        red "NaiveProxy 服务启动失败"
        journalctl -u naiveproxy -n 20 --no-pager -e
        return 1
    fi
}

#===============================================================================
# 重启服务
#===============================================================================
restart_service(){
    green "\n===== 重启服务 ====="
    systemctl daemon-reload
    suss_service || return 1
}

generate_and_restart(){
    generate_caddyfile || return 1
    restart_service || return 1
    show_share || return 1
}

#===============================================================================
# 启动服务
#===============================================================================
start_service(){
    green "启动服务..."
    if systemctl start naiveproxy; then
        green "服务已启动"
    else
        install_service
        systemctl start naiveproxy || { red "启动失败"; return 1; }
    fi
}

#===============================================================================
# 停止服务
#===============================================================================
stop_service(){
    green "停止服务..."
    systemctl stop naiveproxy && green "服务已停止" || red "停止失败"
}

#===============================================================================
# 获取当前代理端口
#===============================================================================
get_proxy_port(){
    local p
    p=$(awk '$1 == "https_port" { print $2; exit }' "$CADDYFILE" 2>/dev/null)
    if [[ -z $p ]]; then
        p=$(awk -F '[: ,{]+' '/^[[:space:]]*[a-zA-Z0-9.-]+:[0-9]+/ { for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/ && $i > 0 && $i <= 65535) { print $i; exit } }' "$CADDYFILE" 2>/dev/null)
    fi
    echo "${p:-443}"
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
    
    local valid_domains=()
    for d in "${!DOMAIN_BACKEND[@]}"; do
        [[ -n ${DOMAIN_CERT[$d]} && -f ${DOMAIN_CERT[$d]} ]] && valid_domains+=("$d")
    done
    
    if [[ ${#valid_domains[@]} -eq 0 ]]; then
        yellow "暂无可用的已配置证书的域名，请先添加域名并申请证书"
        return 0
    fi
    
    local primary_domain="${valid_domains[0]}"
    local primary_port="${PROXY_PORTS[0]:-443}"
    
    mkdir -p "$NAIVE_DIR"
    > "$NAIVE_DIR/URL.txt"
    
    echo
    green "V2rayN 客户端配置 (已按用户分别保存至 $NAIVE_DIR/)："
    for user in "${!USER_PASS[@]}"; do
        local user_json="$NAIVE_DIR/v2rayn_${user}.json"
        cat > "$user_json" <<EOF
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://${user}:${USER_PASS[$user]}@${primary_domain}:${primary_port}"
}
EOF
        echo -e "${yellow}--- 用户: $user (配置: $user_json) ---${plain}"
        cat "$user_json"
        echo
    done
    
    # 兼容原版 v2rayn.json
    local first_u="${!USER_PASS[@]}"
    first_u="${first_u%% *}"
    if [[ -n $first_u && -f "$NAIVE_DIR/v2rayn_${first_u}.json" ]]; then
        cp -f "$NAIVE_DIR/v2rayn_${first_u}.json" "$NAIVE_DIR/v2rayn.json"
    fi
    
    green "NaiveProxy 节点分享链接 (已追加写入 $NAIVE_DIR/URL.txt)："
    for user in "${!USER_PASS[@]}"; do
        for domain in "${valid_domains[@]}"; do
            for p in "${PROXY_PORTS[@]}"; do
                local url="naive+https://${user}:${USER_PASS[$user]}@${domain}:${p}?padding=true#NaiveProxy-${user}-${p}"
                echo "$url" >> "$NAIVE_DIR/URL.txt"
                yellow "$url"
            done
        done
    done
    
    if command -v qrencode &>/dev/null && [[ -s $NAIVE_DIR/URL.txt ]]; then
        echo
        green "二维码分享 (首个可用节点)："
        local first_url
        first_url=$(head -n 1 "$NAIVE_DIR/URL.txt")
        qrencode -o - -t ANSIUTF8 "$first_url"
        blue "提示: 全部节点链接已保存于 $NAIVE_DIR/URL.txt，可直接导入支持 Naive 协议的客户端"
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
    echo -e "服务状态: $service_status"
    
    echo ""
    echo -e "${bblue}─────────────────── 监听端口 ───────────────────${plain}"
    echo -e "  配置端口: ${green}${PROXY_PORTS[*]}${plain}"
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        ss -tunlp 2>/dev/null | grep caddy | awk '{print "  实际监听: " $5}' | sort -u
    fi
    
    echo ""
    echo -e "${bblue}─────────────────── 用户列表 ───────────────────${plain}"
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        echo -e "  ${yellow}暂无用户${plain}"
    else
        for u in "${!USER_PASS[@]}"; do
            echo -e "  ${green}用户:${plain} $u  ${green}密码:${plain} ${USER_PASS[$u]}  ${green}邮箱:${plain} ${USER_EMAIL[$u]:-未设置}"
        done
    fi
    
    echo ""
    echo -e "${bblue}─────────────────── 域名列表 ───────────────────${plain}"
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        echo -e "  ${yellow}暂无域名${plain}"
    else
        for d in "${!DOMAIN_BACKEND[@]}"; do
            local cert_st="${red}未申请${plain}"
            [[ -n ${DOMAIN_CERT[$d]} && -f ${DOMAIN_CERT[$d]} ]] && cert_st="${green}已配置${plain}"
            echo -e "  ${green}域名:${plain} $d  ${green}伪装后端:${plain} ${DOMAIN_BACKEND[$d]}  ${green}证书:${plain} $cert_st"
        done
    fi
    
    # VPS 状态信息
    echo ""
    echo -e "${bblue}─────────────────── VPS 状态 ───────────────────${plain}"
    echo -e "  ${green}系统:${plain} $op  ${green}内核:${plain} $kernel_version  ${green}架构:${plain} $cpu  ${green}虚拟化:${plain} $vi  ${green}BBR:${plain} $bbr"
    
    v4v6
    warpcheck
    local w4="" w6=""
    [[ "$v6" == "2a09"* ]] && w6="【WARP】"
    [[ "$v4" == "104.28"* ]] && w4="【WARP】"
    
    if [[ -z $v4 ]]; then
        echo -e "  ${green}IPv4:${plain} 无  ${green}IPv6:${plain} ${v6:-无} $w6"
    elif [[ -n $v4 && -n $v6 ]]; then
        echo -e "  ${green}IPv4:${plain} $v4 $w4  ${green}IPv6:${plain} $v6 $w6"
    else
        echo -e "  ${green}IPv4:${plain} $v4 $w4  ${green}IPv6:${plain} 无"
    fi
    
    red "======================================================================================"
}

#===============================================================================
# 多端口复用 (完全重构，语法安全可靠)
#===============================================================================
multi_port(){
    load_config
    green "\n当前 NaiveProxy 代理正在监听的端口："
    blue "${PROXY_PORTS[*]}"
    
    echo
    readp "1. 添加新端口复用\n2. 删除已添加端口\n3. 恢复仅使用 443 端口\n0. 返回上层\n请选择 [0-3]:" choose
    
    if [[ $choose == "1" ]]; then
        readp "请输入要新增的端口 [1-65535]:" newport
        [[ -z $newport ]] && { red "端口不能为空"; return 1; }
        if [[ ! $newport =~ ^[0-9]+$ || $newport -lt 1 || $newport -gt 65535 ]]; then
            red "端口格式错误，必须为 1-65535 的整数"
            return 1
        fi
        for p in "${PROXY_PORTS[@]}"; do
            if [[ $p == "$newport" ]]; then
                yellow "端口 $newport 已在监听列表中"
                return 0
            fi
        done
        check_port "$newport" || { red "端口 $newport 已被系统其他进程占用"; return 1; }
        
        PROXY_PORTS+=("$newport")
        save_ports
        open_port "$newport" both
        generate_caddyfile || return 1
        restart_service && show_share
    elif [[ $choose == "2" ]]; then
        if [[ ${#PROXY_PORTS[@]} -le 1 ]]; then
            red "当前仅有 1 个端口 (${PROXY_PORTS[0]})，无法继续删除"
            return 1
        fi
        echo "当前配置的端口:"
        local idx=1
        for p in "${PROXY_PORTS[@]}"; do
            echo "  $idx) $p"
            ((idx++))
        done
        readp "请输入要删除的端口号:" del_p
        [[ -z $del_p ]] && { blue "已取消"; return 0; }
        local new_ports=()
        local found=0
        for p in "${PROXY_PORTS[@]}"; do
            if [[ $p == "$del_p" ]]; then
                found=1
            else
                new_ports+=("$p")
            fi
        done
        if [[ $found -eq 0 ]]; then
            red "未找到端口 $del_p"
            return 1
        fi
        PROXY_PORTS=("${new_ports[@]}")
        save_ports
        generate_caddyfile || return 1
        restart_service && show_share
    elif [[ $choose == "3" ]]; then
        PROXY_PORTS=(443)
        save_ports
        open_port 443 both
        generate_caddyfile 443 || return 1
        restart_service && show_share
    fi
}

#===============================================================================
# 更新脚本
#===============================================================================
update_script(){
    green "\n===== 更新脚本 ====="
    yellow "正在从仓库获取最新脚本: $REPO_URL/naiveproxy.sh ..."
    local tmp_file="/tmp/naiveproxy_new.sh"
    if wget -qN "$REPO_URL/naiveproxy.sh" -O "$tmp_file" || curl -Ls "$REPO_URL/naiveproxy.sh" -o "$tmp_file"; then
        if [[ -s "$tmp_file" ]] && grep -q "NaiveProxy" "$tmp_file"; then
            local dest="${BASH_SOURCE[0]}"
            [[ -z $dest || "$dest" == "/dev/fd/"* ]] && dest="/usr/local/bin/naiveproxy.sh"
            mv -f "$tmp_file" "$dest"
            chmod +x "$dest"
            ln -sf "$dest" /usr/bin/na 2>/dev/null || true
            green "脚本更新成功！请重新运行快捷命令 na。"
            exit 0
        else
            red "下载的文件校验失败，更新终止"
            rm -f "$tmp_file"
            return 1
        fi
    else
        red "获取脚本更新失败，请检查网络或仓库地址设置"
        return 1
    fi
}

#===============================================================================
# 更新内核
#===============================================================================
update_kernel(){
    green "\n===== 更新内核 ====="
    install_caddy || return 1
    systemctl restart naiveproxy || return 1
    green "内核更新成功"
}

#===============================================================================
# 一键安装向导
#===============================================================================
quick_install(){
    if [[ -f $CADDYFILE && -s $CADDYFILE ]]; then
        yellow "检测到已存在 NaiveProxy 配置，继续安装将重新初始化配置。"
        readp "是否继续全新安装？(y/n):" rein
        [[ $rein != y && $rein != Y ]] && { blue "已取消"; return 0; }
    fi
    
    # 检查依赖
    check_deps || return 1
    
    # IPv6 支持
    v6
    
    # 安装 Caddy
    install_caddy || return 1
    
    # 安装服务
    install_service || return 1
    
    # 添加用户
    echo
    yellow "===== 配置首个用户 ====="
    readp "请输入用户名（至少3位，限字母数字下划线，回车随机生成）:" user
    if [[ -z $user ]]; then
        user=$(tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c 6)
        [[ -z $user ]] && user=$(date +%s%N | md5sum | cut -c 1-6)
        blue "随机生成用户名: $user"
    fi
    [[ ${#user} -lt 3 ]] && { red "用户名至少3位字符"; return 1; }
    
    readp "请输入密码（至少5位，不可包含冒号或空格，回车随机生成）:" pass
    if [[ -z $pass ]]; then
        pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 12)
        [[ -z $pass ]] && pass=$(date +%s%N | md5sum | cut -c 1-12)
        blue "随机生成密码: $pass"
    fi
    [[ ${#pass} -lt 5 ]] && { red "密码至少5位字符"; return 1; }
    
    USER_PASS=()
    USER_PASS[$user]=$pass
    save_users
    
    # 添加域名
    echo
    yellow "===== 配置首个域名 ====="
    readp "请输入解析到本 VPS 的域名:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    
    readp "请输入反代伪装网址（回车默认 speed.cloudflare.com）:" backend
    [[ -z $backend ]] && backend="speed.cloudflare.com"
    backend="${backend#https://}"
    backend="${backend#http://}"
    backend="${backend%%/*}"
    
    DOMAIN_BACKEND=()
    DOMAIN_CERT=()
    DOMAIN_KEY=()
    DOMAIN_BACKEND[$domain]=$backend
    save_domains
    
    # 设置端口
    echo
    yellow "===== 设置监听端口 ====="
    readp "请输入主端口 [1-65535]（回车默认 443）:" port
    [[ -z $port ]] && port="443"
    if [[ ! $port =~ ^[0-9]+$ || $port -lt 1 || $port -gt 65535 ]]; then
        red "端口格式不合法"
        return 1
    fi
    check_port "$port" || { red "端口 $port 已被占用"; return 1; }
    
    PROXY_PORTS=("$port")
    save_ports
    
    # 防火墙
    openyn
    
    # 申请证书
    apply_cert || return 1
    
    # 生成配置
    generate_caddyfile "$port" 80 || return 1
    
    # 启动服务
    if suss_service; then
        # 安装快捷命令
        install_shortcut || yellow "快捷命令 na 安装失败，可手动执行 bash /usr/local/bin/naiveproxy.sh"
        
        # 保存版本
        echo "$latestV" > /etc/caddy/v 2>/dev/null || true
        echo "$latcore" > /etc/caddy/version 2>/dev/null || true
        
        show_share
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
    rm -f "$BINARY"
    rm -rf "$CONFIG_DIR"
    rm -rf "$NAIVE_DIR"
    rm -f /usr/bin/na
    rm -f /usr/local/bin/naiveproxy.sh
    rm -f /root/naiveproxy.sh
    
    green "卸载完成！"
}

#===============================================================================
# 查看日志
#===============================================================================
view_log(){
    echo
    yellow "正在展示最近 50 行日志（按 Ctrl+C 可退出）："
    journalctl -u naiveproxy -n 50 --no-pager -e
    echo
    readp "是否进入实时跟踪日志模式？(y/n，回车跳过):" follow
    if [[ $follow == y || $follow == Y ]]; then
        journalctl -u naiveproxy -f
    fi
}

#===============================================================================
# 主菜单
#===============================================================================
main_menu(){
    clear
    blue "正在初始化面板并检测系统环境，请稍候..."
    get_system_info
    init_config
    load_config
    
    while true; do
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
        
        # VPS 状态
        echo -e "VPS状态: 系统:${blue}$op${plain} 内核:${blue}$kernel_version${plain} 架构:${blue}$cpu${plain} 虚拟化:${blue}$vi${plain} BBR:${blue}$bbr${plain}"
        
        # 服务状态
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
    check_deps || yellow "依赖安装未完成，部分功能可能受限"
    init_config || { red "初始化配置目录失败"; exit 1; }
    main_menu
fi
