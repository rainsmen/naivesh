#!/bin/bash
#===============================================================================
# NaiveProxy 多用户管理增强版 - 修复优化版
# 功能：多用户、多域名、自动证书申请、用户管理、系统适配
# 修复：语法错误、功能缺失、设计问题
#===============================================================================

export LANG=en_US.UTF-8
set -e
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
readp(){ read -p "$(yellow "$1")" $2;}

#===============================================================================
# 权限检查
#===============================================================================
[[ $EUID -ne 0 ]] && yellow "请以root模式运行脚本" && exit 1

#===============================================================================
# 配置路径定义
#===============================================================================
REPO_URL="https://raw.githubusercontent.com/rainsmen/naivesh/main"
CONFIG_DIR="/etc/naiveproxy"
USERS_FILE="$CONFIG_DIR/users.conf"
DOMAINS_FILE="$CONFIG_DIR/domains.conf"
CADDYFILE="$CONFIG_DIR/Caddyfile"
SERVICEFILE="/etc/systemd/system/naiveproxy.service"
BINARY="/usr/bin/caddy"
NAIVE_DIR="/root/naive"
BACKUP_CADDYFILE="$CONFIG_DIR/reCaddyfile"

#===============================================================================
# 全局变量 - 系统检测
#===============================================================================
get_system_info(){
    # 检测系统类型
    if [[ -f /etc/redhat-release ]]; then
        release="Centos"
    elif cat /etc/issue 2>/dev/null | grep -q -E -i "debian"; then
        release="Debian"
    elif cat /etc/issue 2>/dev/null | grep -q -E -i "ubuntu"; then
        release="Ubuntu"
    elif cat /etc/issue 2>/dev/null | grep -q -E -i "centos|red hat|redhat"; then
        release="Centos"
    elif cat /proc/version 2>/dev/null | grep -q -E -i "debian"; then
        release="Debian"
    elif cat /proc/version 2>/dev/null | grep -q -E -i "ubuntu"; then
        release="Ubuntu"
    elif cat /proc/version 2>/dev/null | grep -q -E -i "centos|red hat|redhat"; then
        release="Centos"
    else
        red "脚本不支持当前的系统，请选择使用Ubuntu,Debian,Centos系统。" && exit 1
    fi
    
    # 系统版本
    vsid=$(grep -i version_id /etc/os-release 2>/dev/null | cut -d \" -f2 | cut -d . -f1)
    op=$(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep -i pretty_name | cut -d \" -f2)
    
    # 检测架构
    if [[ $(uname -m) = x86_64 ]]; then
        cpu=amd64
    elif [[ $(uname -m) = aarch64 ]]; then
        cpu=arm64
    else
        red "目前脚本不支持 $(uname -m) 架构" && exit 1
    fi
    
    # 内核版本
    kernel_version=$(uname -r | cut -d "-" -f1)
    
    # 虚拟化检测
    vi=$(systemd-detect-virt 2>/dev/null)
    
    # BBR状态检测
    if [[ -n $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F ' ' '{print $3}') ]]; then
        bbr=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk -F ' ' '{print $3}')
    elif [[ -n $(ping 10.0.0.2 -c 2 2>/dev/null | grep ttl) ]]; then
        bbr="Openvz版bbr-plus"
    else
        bbr="Openvz/Lxc"
    fi
    
    # 获取版本信息
    inscore=$(cat /etc/caddy/version 2>/dev/null | head -n 1)
    insV=$(cat /etc/caddy/v 2>/dev/null)
    latcore=$(curl -m 3 -Ls https://data.jsdelivr.com/v1/package/gh/klzgrad/naiveproxy 2>/dev/null | sed -n 4p | tr -d ',"' | awk '{print $1}')
    latestV="本地私有版"
}

#===============================================================================
# IPv4/IPv6 地址检测
#===============================================================================
v4v6(){
    v4=$(curl -s4m5 icanhazip.com -k 2>/dev/null)
    v6=$(curl -s6m5 icanhazip.com -k 2>/dev/null)
}

#===============================================================================
# WARP 状态检测
#===============================================================================
warpcheck(){
    wgcfv6=$(curl -s6m5 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep warp | cut -d= -f2)
    wgcfv4=$(curl -s4m5 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep warp | cut -d= -f2)
}

#===============================================================================
# 纯IPv6 DNS64支持
#===============================================================================
v6(){
    warpcheck
    if [[ ! $wgcfv4 =~ on|plus && ! $wgcfv6 =~ on|plus ]]; then
        v4=$(curl -s4m5 icanhazip.com -k 2>/dev/null)
        if [[ -z $v4 ]]; then
            yellow "检测到 纯IPV6 VPS，添加DNS64"
            echo -e "nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1\nnameserver 2a01:4f8:c2c:123f::1" > /etc/resolv.conf
        fi
    fi
}

#===============================================================================
# 防火墙端口开放
#===============================================================================
close(){
    if command -v ufw &>/dev/null; then
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
    fi
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    if command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1
    fi
    sleep 1
    blue "执行开放端口 80 和 443 完毕，如需其他端口请在提供商面板单独开放"
    echo "----------------------------------------------------"
}

openyn(){
    red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    readp "是否开放端口，关闭防火墙？\n1、是，执行 (回车默认)\n2、否，我自己手动\n请选择：" action
    if [[ -z $action ]] || [[ "$action" = "1" ]]; then
        close
    elif [[ "$action" = "2" ]]; then
        echo
    else
        red "输入错误,请重新选择" && openyn
    fi
}

#===============================================================================
# OpenVZ TUN 支持
#===============================================================================
tun_support(){
    if [[ $vi = openvz ]]; then
        TUN=$(cat /dev/net/tun 2>&1)
        if [[ ! $TUN =~ 'in bad state' ]] && [[ ! $TUN =~ '处于错误状态' ]] && [[ ! $TUN =~ 'Die Dateizugriffsnummer ist in schlechter Verfassung' ]]; then
            red "检测到未开启TUN，现尝试添加TUN支持" && sleep 4
            cd /dev && mkdir net 2>/dev/null && mknod net/tun c 10 200 && chmod 0666 net/tun
            TUN=$(cat /dev/net/tun 2>&1)
            if [[ ! $TUN =~ 'in bad state' ]] && [[ ! $TUN =~ '处于错误状态' ]] && [[ ! $TUN =~ 'Die Dateizugriffsnummer ist in schlechter Verfassung' ]]; then
                green "添加TUN支持失败，建议与VPS厂商沟通或后台设置开启" && exit 1
            else
                echo '#!/bin/bash' > /root/tun.sh && echo 'cd /dev && mkdir net 2>/dev/null && mknod net/tun c 10 200 && chmod 0666 net/tun' >> /root/tun.sh && chmod +x /root/tun.sh
                grep -qE "^ *@reboot root bash /root/tun.sh >/dev/null 2>&1" /etc/crontab || echo "@reboot root bash /root/tun.sh >/dev/null 2>&1" >> /etc/crontab
                green "TUN守护功能已启动"
            fi
        fi
    fi
}

#===============================================================================
# 依赖安装
#===============================================================================
check_deps(){
    local miss=()
    for cmd in curl wget tar systemctl ss ip awk grep sed jq qrencode cron; do
        command -v $cmd &>/dev/null || miss+=($cmd)
    done
    [[ ${#miss[@]} -gt 0 ]] && {
        yellow "正在安装缺少的依赖: ${miss[*]}"
        if [ -x "$(command -v apt-get)" ]; then
            apt-get update -y && apt-get install -y ${miss[*]}
        elif [ -x "$(command -v yum)" ]; then
            yum update -y && yum install -y ${miss[*]}
            [[ " ${miss[*]} " =~ " cron " ]] && yum install -y cronie
        elif [ -x "$(command -v dnf)" ]; then
            dnf update -y && dnf install -y ${miss[*]}
            [[ " ${miss[*]} " =~ " cron " ]] && dnf install -y cronie
        fi
    }
}

#===============================================================================
# 初始化配置目录
#===============================================================================
init_config(){
    [[ ! -d $CONFIG_DIR ]] && mkdir -p $CONFIG_DIR
    [[ ! -f $USERS_FILE ]] && touch $USERS_FILE
    [[ ! -f $DOMAINS_FILE ]] && touch $DOMAINS_FILE
    [[ ! -d $NAIVE_DIR ]] && mkdir -p $NAIVE_DIR
}

#===============================================================================
# 加载用户和域名配置
#===============================================================================
load_config(){
    declare -gA USER_PASS USER_EMAIL DOMAIN_BACKEND DOMAIN_CERT DOMAIN_KEY
    [[ -f $USERS_FILE ]] && while IFS=: read -r u p e; do
        [[ -n $u && -n $p ]] && USER_PASS[$u]=$p && USER_EMAIL[$u]=$e
    done < <(grep -v '^#' $USERS_FILE 2>/dev/null)
    
    [[ -f $DOMAINS_FILE ]] && while IFS=: read -r d b c k; do
        [[ -n $d && -n $b ]] && DOMAIN_BACKEND[$d]=$b && DOMAIN_CERT[$d]=$c && DOMAIN_KEY[$d]=$k
    done < <(grep -v '^#' $DOMAINS_FILE 2>/dev/null)
}

#===============================================================================
# 保存用户配置
#===============================================================================
save_users(){
    {
        echo "# 用户配置 - 格式: 用户名:密码:邮箱"
        for u in "${!USER_PASS[@]}"; do
            echo "${u}:${USER_PASS[$u]}:${USER_EMAIL[$u]:-}"
        done
    } > $USERS_FILE
}

#===============================================================================
# 保存域名配置
#===============================================================================
save_domains(){
    {
        echo "# 域名配置 - 格式: 域名:后端:证书路径:密钥路径"
        for d in "${!DOMAIN_BACKEND[@]}"; do
            echo "${d}:${DOMAIN_BACKEND[$d]}:${DOMAIN_CERT[$d]:-}:${DOMAIN_KEY[$d]:-}"
        done
    } > $DOMAINS_FILE
}

#===============================================================================
# 安装 Caddy2-Naiveproxy
#===============================================================================
install_caddy(){
    green "\n===== 安装 Caddy2-Naiveproxy ====="
    yellow "请选择安装方式:"
    yellow "1. 下载预编译版本 (快速，推荐)"
    yellow "2. 在线编译版本 (慢，可能失败)"
    readp "请选择 [1/2]:" chcaddy
    
    if [[ -z $chcaddy || $chcaddy == "1" ]]; then
        cd /tmp
        rm -f caddy2-naive-linux-*.tar.gz caddy.tar.gz
        
        # 多下载源尝试
        yellow "正在下载 Caddy2-Naiveproxy..."
        if wget -qN "$REPO_URL/assets/caddy2-naive-linux-${cpu}.tar.gz" -O caddy.tar.gz; then
            :
        else
            red "下载失败，请检查网络和仓库地址设置" && return 1
        fi
        
        [[ ! -f caddy.tar.gz ]] && { red "下载失败"; return 1; }
        tar -zxf caddy.tar.gz
        mv caddy $BINARY
        chmod +x $BINARY
        rm -f caddy.tar.gz
        
        # 保存版本信息
        echo "$latcore" > /etc/caddy/version 2>/dev/null || true
        
        green "Caddy 安装完成: $($BINARY version 2>&1 | head -1)"
    elif [[ $chcaddy == "2" ]]; then
        yellow "开始在线编译..."
        go env -w GO111MODULE=on
        if ! command -v go &>/dev/null; then
            yellow "安装 Go 环境..."
            if [[ $release = Centos ]]; then
                rpm --import https://mirror.go-repo.io/centos/RPM-GPG-KEY-GO-REPO
                curl -s https://mirror.go-repo.io/centos/go-repo.repo | tee /etc/yum.repos.d/go-repo.repo
                yum install golang -y
            elif [[ $release = Debian ]]; then
                apt install software-properties-common -y
                apt update
                GO_VER=$(curl -Ls https://golang.google.cn/dl/ 2>/dev/null | grep -oE "go[0-9.]+\.linux-${cpu}\.tar\.gz" | head -n 1 | cut -c3-8)
                wget -c "https://golang.google.cn/dl/${GO_VER}.linux-${cpu}.tar.gz"
                rm -rf /usr/local/go && tar -C /usr/local -xzf "${GO_VER}.linux-${cpu}.tar.gz"
                echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
                source /etc/profile
            else
                apt install software-properties-common -y
                add-apt-repository ppa:longsleep/golang-backports -y
                apt update
                apt install golang-go -y
            fi
        fi
        
        go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
        ~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive
        [[ -f /root/caddy ]] && mv /root/caddy $BINARY && chmod +x $BINARY || { red "编译失败"; return 1; }
        green "在线编译安装完成"
    fi
}

#===============================================================================
# 安装 systemd 服务
#===============================================================================
install_service(){
    green "\n===== 安装服务 ====="
    cat > $SERVICEFILE <<EOF
[Unit]
Description=NaiveProxy Multi-User Service
Documentation=https://github.com/klzgrad/naiveproxy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BINARY run --config $CADDYFILE
ExecReload=$BINARY reload --config $CADDYFILE
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity
PrivateTmp=false
NoNewPrivileges=yes
ProtectHome=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable naiveproxy >/dev/null 2>&1
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
    readp "请输入用户名（至少3位字符，回车随机生成）:" user
    if [[ -z $user ]]; then
        user=$(date +%s%N | md5sum | cut -c 1-5)
        blue "随机生成用户名: $user"
    fi
    [[ ${#user} -lt 3 ]] && { red "用户名至少3位字符"; return 1; }
    
    readp "请输入密码（至少5位字符，回车随机生成）:" pass
    if [[ -z $pass ]]; then
        pass=$(date +%s%N | md5sum | cut -c 1-8)
        blue "随机生成密码: $pass"
    fi
    [[ ${#pass} -lt 5 ]] && { red "密码至少5位字符"; return 1; }
    
    readp "请输入邮箱（可选，回车跳过）:" email
    
    USER_PASS[$user]=$pass
    [[ -n $email ]] && USER_EMAIL[$user]=$email
    
    save_users
    green "用户 $user 添加成功"
}

#===============================================================================
# 删除用户
#===============================================================================
del_user(){
    echo
    yellow "===== 删除用户 ====="
    list_users
    [[ ${#USER_PASS[@]} -eq 0 ]] && { green "暂无用户"; return; }
    
    readp "请输入要删除的用户名:" user
    [[ -z $user ]] && { red "用户名不能为空"; return 1; }
    [[ -z ${USER_PASS[$user]} ]] && { red "用户 $user 不存在"; return 1; }
    
    readp "确认删除用户 $user ？(输入y确认):" confirm
    [[ $confirm != y ]] && { blue "已取消"; return; }
    
    unset USER_PASS[$user]
    unset USER_EMAIL[$user]
    save_users
    green "用户 $user 已删除"
}

#===============================================================================
# 用户列表
#===============================================================================
list_users(){
    echo
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        yellow "暂无用户"
        return
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
    readp "请输入域名（如 example.com）:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    
    # 改进的域名验证
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
        red "域名格式错误"
        return 1
    fi
    
    readp "请输入后端伪装网址（如 www.example.com，回车默认 ygkkk.blogspot.com）:" backend
    [[ -z $backend ]] && backend="ygkkk.blogspot.com"
    
    DOMAIN_BACKEND[$domain]=$backend
    DOMAIN_CERT[$domain]=""
    DOMAIN_KEY[$domain]=""
    
    save_domains
    green "域名 $domain 添加成功"
    yellow "请选择【9】申请证书"
}

#===============================================================================
# 删除域名
#===============================================================================
del_domain(){
    echo
    yellow "===== 删除域名 ====="
    list_domains
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { green "暂无域名"; return; }
    
    readp "请输入要删除的域名:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]} ]] && { red "域名 $domain 不存在"; return 1; }
    
    readp "确认删除域名 $domain ？(输入y确认):" confirm
    [[ $confirm != y ]] && { blue "已取消"; return; }
    
    unset DOMAIN_BACKEND[$domain]
    unset DOMAIN_CERT[$domain]
    unset DOMAIN_KEY[$domain]
    save_domains
    green "域名 $domain 已删除"
}

#===============================================================================
# 域名列表
#===============================================================================
list_domains(){
    echo
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        yellow "暂无域名"
        return
    fi
    green "─────────── 域名列表 ───────────"
    for d in "${!DOMAIN_BACKEND[@]}"; do
        local cert_st="未申请"
        [[ -n ${DOMAIN_CERT[$d]} && -f ${DOMAIN_CERT[$d]} ]] && cert_st="已配置"
        blue "域名: $d  后端: ${DOMAIN_BACKEND[$d]}  证书: $cert_st"
    done
    green "────────────────────────────────"
}

#===============================================================================
# 申请证书
#===============================================================================
apply_cert(){
    echo
    yellow "===== 申请证书 ====="
    list_domains
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { red "请先添加域名"; return 1; }
    
    readp "请输入要申请证书的域名:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    [[ -z ${DOMAIN_BACKEND[$domain]} ]] && { red "域名 $domain 未添加"; return 1; }
    
    readp "请输入邮箱（用于证书通知，回车默认 admin@域名）:" email
    [[ -z $email ]] && email="admin@${domain}"
    
    green "正在申请 $domain 的证书..."
    
    local cert_dir="$CONFIG_DIR/certs/$domain"
    mkdir -p $cert_dir
    mkdir -p "$CONFIG_DIR/www"
    
    if ! command -v acme.sh &>/dev/null; then
        yellow "安装 acme.sh..."
        wget -qN "$REPO_URL/assets/acme.sh" -O /tmp/acme.sh
        chmod +x /tmp/acme.sh
        /tmp/acme.sh --install -m $email
        rm -f /tmp/acme.sh
    fi
    
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    systemctl stop naiveproxy 2>/dev/null || true

    ~/.acme.sh/acme.sh --issue -d $domain --standalone -k 2048 --force
    
    local cert_path="$cert_dir/cert.crt"
    local key_path="$cert_dir/private.key"
    
    if [[ -f ~/.acme.sh/$domain/fullchain.cer && -f ~/.acme.sh/$domain/$domain.key ]]; then
        cp ~/.acme.sh/$domain/fullchain.cer $cert_path
        cp ~/.acme.sh/$domain/$domain.key $key_path
        DOMAIN_CERT[$domain]=$cert_path
        DOMAIN_KEY[$domain]=$key_path
        save_domains
        green "证书申请成功: $cert_path"
    else
        red "证书申请失败，请检查:"
        yellow "1. 域名 DNS 是否已解析到本服务器"
        yellow "2. 域名是否可正常访问"
        return 1
    fi
}

#===============================================================================
# 生成 Caddyfile 配置
#===============================================================================
generate_caddyfile(){
    green "\n===== 生成配置 ====="
    
    [[ ${#USER_PASS[@]} -eq 0 ]] && { red "请先添加用户"; return 1; }
    [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]] && { red "请先添加域名"; return 1; }
    
    local port=${1:-443}
    local http_port=${2:-80}
    
    > $CADDYFILE
    
    cat >> $CADDYFILE <<EOF
{
    http_port $http_port
    https_port $port
    auto_https off
}

EOF
    
    local domain_count=0
    for domain in "${!DOMAIN_BACKEND[@]}"; do
        local cert="${DOMAIN_CERT[$domain]}"
        local key="${DOMAIN_KEY[$domain]}"
        
        if [[ -n $cert && -n $key && -f $cert && -f $key ]]; then
            cat >> $CADDYFILE <<EOF
$domain:$port {
    tls $cert $key
    route {
        forward_proxy {
EOF
            for user in "${!USER_PASS[@]}"; do
                echo "            basic_auth ${user} ${USER_PASS[$user]}" >> $CADDYFILE
            done
            
            cat >> $CADDYFILE <<EOF
            hide_ip
            hide_via
            probe_resistance
        }
        reverse_proxy https://${DOMAIN_BACKEND[$domain]} {
            header_up Host {upstream_hostport}
            header_up X-Forwarded-Host {host}
        }
    }
}
EOF
            ((domain_count++))
        else
            yellow "跳过 $domain (证书未配置)"
        fi
    done
    
    [[ $domain_count -eq 0 ]] && { red "无可用域名配置"; return 1; }
    
    green "Caddyfile 生成完成: $CADDYFILE"
    
    cp -f $CADDYFILE "$BACKUP_CADDYFILE"
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
        journalctl -u naiveproxy -n 20 --no-pager
        return 1
    fi
}

#===============================================================================
# 重启服务
#===============================================================================
restart_service(){
    green "\n===== 重启服务 ====="
    systemctl daemon-reload
    
    if suss_service; then
        :
    else
        return 1
    fi
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
# 显示分享信息
#===============================================================================
show_share(){
    if ! systemctl is-active --quiet naiveproxy || [[ ! -f $CADDYFILE ]]; then
        red "NaiveProxy 未正常运行" && return 1
    fi
    
    echo
    red "======================================================================================"
    green "                         NaiveProxy 分享信息"
    red "======================================================================================"
    
    echo
    green "当前监听端口："
    blue "$(cat $CADDYFILE 2>/dev/null | awk '{print $1}' | grep ':' | tr -d ',:')"
    
    echo
    green "V2rayN 配置文件 (保存到 $NAIVE_DIR/v2rayn.json)："
    
    # 使用第一个域名和用户生成配置
    local first_domain=""
    for d in "${!DOMAIN_BACKEND[@]}"; do
        [[ -n ${DOMAIN_CERT[$d]} && -f ${DOMAIN_CERT[$d]} ]] && first_domain=$d && break
    done
    
    if [[ -n $first_domain ]]; then
        local first_user=""
        for u in "${!USER_PASS[@]}"; do
            first_user=$u
            break
        done
        
        local port="443"
        cat > $NAIVE_DIR/v2rayn.json <<EOF
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://${first_user}:${USER_PASS[$first_user]}@${first_domain}:${port}"
}
EOF
        yellow "$(cat $NAIVE_DIR/v2rayn.json)"
        
        echo
        green "分享链接："
        for user in "${!USER_PASS[@]}"; do
            for domain in "${!DOMAIN_BACKEND[@]}"; do
                [[ -n ${DOMAIN_CERT[$domain]} && -f ${DOMAIN_CERT[$domain]} ]] || continue
                local url="naive+https://${user}:${USER_PASS[$user]}@${domain}:${port}?padding=true#NaiveProxy-${user}"
                echo "$url" > $NAIVE_DIR/URL.txt
                yellow "$url"
            done
        done
        
        echo
        green "二维码分享链接 (Nekobox)："
        qrencode -o - -t ANSIUTF8 "$(cat $NAIVE_DIR/URL.txt 2>/dev/null)"
    fi
    
    red "======================================================================================"
}

#===============================================================================
# 显示状态
#===============================================================================
show_status(){
    echo
    red "======================================================================================"
    green "                         NaiveProxy 多用户管理状态"
    red "======================================================================================"
    
    local service_status="${red}未安装${plain}"
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        service_status="${green}运行中${plain}"
    elif [[ -f $SERVICEFILE ]]; then
        service_status="${yellow}已安装${plain}"
    fi
    echo -e "服务状态: $service_status"
    
    echo ""
    echo -e "${bblue}─────────────────── 用户列表 ───────────────────${plain}"
    if [[ ${#USER_PASS[@]} -eq 0 ]]; then
        echo -e "${yellow}暂无用户${plain}"
    else
        for u in "${!USER_PASS[@]}"; do
            echo -e "  ${green}用户:${plain} $u  ${green}密码:${plain} ${USER_PASS[$u]}  ${green}邮箱:${plain} ${USER_EMAIL[$u]:-未设置}"
        done
    fi
    echo -e "${bblue}────────────────────────────────────────────${plain}"
    
    echo ""
    echo -e "${bblue}─────────────────── 域名列表 ───────────────────${plain}"
    if [[ ${#DOMAIN_BACKEND[@]} -eq 0 ]]; then
        echo -e "${yellow}暂无域名${plain}"
    else
        for d in "${!DOMAIN_BACKEND[@]}"; do
            local cert_st="${red}未申请${plain}"
            [[ -n ${DOMAIN_CERT[$d]} && -f ${DOMAIN_CERT[$d]} ]] && cert_st="${green}已配置${plain}"
            echo -e "  ${green}域名:${plain} $d  ${green}后端:${plain} ${DOMAIN_BACKEND[$d]}  ${green}证书:${plain} $cert_st"
        done
    fi
    echo -e "${bblue}────────────────────────────────────────────${plain}"
    
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
    echo -e "${bblue}────────────────────────────────────────────${plain}"
    
    if systemctl is-active --quiet naiveproxy 2>/dev/null; then
        echo ""
        echo -e "${bblue}─────────────────── 端口监听 ───────────────────${plain}"
        ss -tlnp 2>/dev/null | grep caddy | awk '{print $4}' | while read addr; do
            echo -e "  ${green}$addr${plain}"
        done
        echo -e "${bblue}────────────────────────────────────────────${plain}"
    fi
    
    # 版本信息
    if [[ -f /etc/caddy/v ]]; then
        echo ""
        echo -e "${bblue}─────────────────── 版本信息 ───────────────────${plain}"
        if [[ "$insV" = "$latestV" ]]; then
            echo -e "  ${green}脚本版本:${plain} ${insV} (最新)"
        else
            echo -e "  ${green}脚本版本:${plain} ${insV}"
            echo -e "  ${yellow}最新版本:${plain} ${latestV} (可更新)"
        fi
        if [[ -n $inscore && -n $latcore ]]; then
            if [[ "$inscore" = "$latcore" ]]; then
                echo -e "  ${green}内核版本:${plain} ${inscore} (最新)"
            else
                echo -e "  ${green}内核版本:${plain} ${inscore}"
                echo -e "  ${yellow}最新内核:${plain} ${latcore} (可更新)"
            fi
        fi
        echo -e "${bblue}────────────────────────────────────────────${plain}"
    fi
    
    red "======================================================================================"
}

#===============================================================================
# 多端口复用
#===============================================================================
multi_port(){
    local current_ports=$(cat $CADDYFILE 2>/dev/null | awk '{print $1}' | grep ':' | tr -d ',:')
    green "\n当前 NaiveProxy 代理正在使用的端口："
    blue "$current_ports"
    
    echo
    readp "1. 添加多端口复用\n2. 恢复仅一个主端口\n0. 返回上层\n请选择：" choose
    
    if [[ $choose == "1" ]]; then
        readp "请输入新端口 [1-65535]:" newport
        [[ -z $newport ]] && { red "端口不能为空"; return 1; }
        check_port $newport || { red "端口 $newport 已被占用"; return 1; }
        
        local old_port=$(cat $CADDYFILE 2>/dev/null | sed -n '4p' | awk '{print $1}' | tr -d ',:')
        sed -i "s/$old_port/$newport/g" $BACKUP_CADDYFILE
        cat $BACKUP_CADDYFILE 2>/dev/null | tail -15 >> $CADDYFILE
        suss_service && show_share
    elif [[ $choose == "2" ]]; then
        sed -i '19,$d' $CADDYFILE 2>/dev/null
        suss_service && show_share
    fi
}

#===============================================================================
# 更新脚本
#===============================================================================
update_script(){
    green "\n===== 更新脚本 ====="
    yellow "自定义 GitHub 仓库版不支持一键覆盖更新，请手动拉取代码或配置自动同步。"
    sleep 2
}

#===============================================================================
# 更新内核
#===============================================================================
update_kernel(){
    green "\n===== 更新内核 ====="
    install_caddy
    systemctl restart naiveproxy
    green "内核更新成功"
}

#===============================================================================
# 一键安装
#===============================================================================
quick_install(){
    if [[ -f $CADDYFILE ]]; then
        red "已安装 NaiveProxy，请先卸载或使用其他功能" && return 1
    fi
    
    # 检查依赖
    check_deps
    
    # IPv6 支持
    v6
    
    # TUN 支持
    tun_support
    
    # 防火墙
    openyn
    
    # 安装 Caddy
    install_caddy || return 1
    
    # 安装服务
    install_service
    
    # 添加用户
    echo
    yellow "===== 配置用户 ====="
    readp "请输入用户名（至少3位字符，回车随机生成）:" user
    if [[ -z $user ]]; then
        user=$(date +%s%N | md5sum | cut -c 1-5)
        blue "随机生成用户名: $user"
    fi
    [[ ${#user} -lt 3 ]] && { red "用户名至少3位字符"; return 1; }
    
    readp "请输入密码（至少5位字符，回车随机生成）:" pass
    if [[ -z $pass ]]; then
        pass=$(date +%s%N | md5sum | cut -c 1-8)
        blue "随机生成密码: $pass"
    fi
    [[ ${#pass} -lt 5 ]] && { red "密码至少5位字符"; return 1; }
    
    USER_PASS[$user]=$pass
    save_users
    
    # 添加域名
    echo
    yellow "===== 配置域名 ====="
    readp "请输入域名:" domain
    [[ -z $domain ]] && { red "域名不能为空"; return 1; }
    
    readp "请输入后端伪装网址（回车默认 ygkkk.blogspot.com）:" backend
    [[ -z $backend ]] && backend="ygkkk.blogspot.com"
    
    DOMAIN_BACKEND[$domain]=""
    save_domains
    
    # 申请证书
    echo
    yellow "===== 申请证书 ====="
    readp "请选择证书申请方式:\n1. acme 自动申请（回车默认）\n2. 自定义证书路径\n请选择:" certtype
    
    if [[ -z $certtype || $certtype == "1" ]]; then
        readp "请输入邮箱（回车默认 admin@域名）:" email
        [[ -z $email ]] && email="admin@${domain}"
        
        green "正在申请 $domain 的证书..."
        
        local cert_dir="$CONFIG_DIR/certs/$domain"
        mkdir -p $cert_dir
        mkdir -p "$CONFIG_DIR/www"
        
        if ! command -v acme.sh &>/dev/null; then
            yellow "安装 acme.sh..."
            wget -qN "$REPO_URL/assets/acme.sh" -O /tmp/acme.sh
            chmod +x /tmp/acme.sh
            /tmp/acme.sh --install -m $email
            rm -f /tmp/acme.sh
        fi
        
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        systemctl stop httpd 2>/dev/null || true
        systemctl stop caddy 2>/dev/null || true
        systemctl stop naiveproxy 2>/dev/null || true

        ~/.acme.sh/acme.sh --issue -d $domain --standalone -k 2048 --force
        
        if [[ -f ~/.acme.sh/$domain/fullchain.cer && -f ~/.acme.sh/$domain/$domain.key ]]; then
            cp ~/.acme.sh/$domain/fullchain.cer "$cert_dir/cert.crt"
            cp ~/.acme.sh/$domain/$domain.key "$cert_dir/private.key"
            DOMAIN_CERT[$domain]="$cert_dir/cert.crt"
            DOMAIN_KEY[$domain]="$cert_dir/private.key"
            DOMAIN_BACKEND[$domain]=$backend
            save_domains
            green "证书申请成功"
        else
            red "证书申请失败"
            return 1
        fi
    else
        readp "请输入公钥文件 crt 路径:" certpath
        readp "请输入密钥文件 key 路径:" keypath
        DOMAIN_CERT[$domain]=$certpath
        DOMAIN_KEY[$domain]=$keypath
        DOMAIN_BACKEND[$domain]=$backend
        save_domains
    fi
    
    # 设置端口
    echo
    yellow "===== 设置端口 ====="
    readp "请输入端口 [1-65535]（回车随机 2000-65535）:" port
    if [[ -z $port ]]; then
        port=$(shuf -i 2000-65535 -n 1)
        while ! check_port $port; do
            port=$(shuf -i 2000-65535 -n 1)
        done
    fi
    check_port $port || { red "端口 $port 已被占用"; return 1; }
    blue "已确认端口: $port"
    
    # 生成配置
    generate_caddyfile $port 80 || return 1
    
    # 启动服务
    if suss_service; then
        # 安装快捷命令
        ln -sf $0 /usr/bin/na 2>/dev/null
        
        # 保存版本
        echo "$latestV" > /etc/caddy/v 2>/dev/null
        echo "$latcore" > /etc/caddy/version 2>/dev/null
        
        # 生成分享链接
        local url="naive+https://${user}:${USER_PASS[$user]}@${domain}:${port}?padding=true#NaiveProxy-${user}"
        echo $url > $NAIVE_DIR/URL.txt
        
        show_share
    fi
}

#===============================================================================
# 卸载
#===============================================================================
uninstall(){
    echo
    yellow "===== 卸载 NaiveProxy ====="
    readp "确认卸载？(输入y确认):" confirm
    [[ $confirm != y ]] && { blue "已取消"; return; }
    
    systemctl stop naiveproxy 2>/dev/null || true
    systemctl disable naiveproxy 2>/dev/null || true
    rm -f $SERVICEFILE
    rm -f $BINARY
    rm -rf $CONFIG_DIR
    rm -rf $NAIVE_DIR
    rm -f /usr/bin/na
    rm -f /root/nayg_update
    
    green "卸载完成"
}

#===============================================================================
# 查看日志
#===============================================================================
view_log(){
    echo
    yellow "退出日志查看请按 Ctrl+c"
    journalctl -u naiveproxy --no-pager -f
}

#===============================================================================
# 主菜单
#===============================================================================
main_menu(){
    clear
    blue "正在初始化面板并检测系统环境，请稍候..."
    get_system_info
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
        white "NaiveProxy 多用户管理增强版 (修复版)"
        white "快捷命令: na"
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        green " 1. 一键安装 NaiveProxy"
        green " 2. 卸载 NaiveProxy"
        white "----------------------------------------------------------------------------------"
        green " 3. 安装 Caddy2-Naiveproxy"
        green " 4. 安装/更新服务"
        white "----------------------------------------------------------------------------------"
        green " 5. 添加用户"
        green " 6. 删除用户"
        green " 7. 用户列表"
        white "----------------------------------------------------------------------------------"
        green " 8. 添加域名"
        green " 9. 删除域名"
        green "10. 域名列表"
        green "11. 申请证书"
        white "----------------------------------------------------------------------------------"
        green "12. 生成配置并重启"
        green "13. 启动服务"
        green "14. 停止服务"
        green "15. 多端口复用"
        white "----------------------------------------------------------------------------------"
        green "16. 查看状态"
        green "17. 查看分享信息"
        green "18. 查看日志"
        green "19. 更新脚本"
        green "20. 更新内核"
        green " 0. 退出脚本"
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        # 显示版本和状态
        if [[ -f /etc/caddy/v ]]; then
            if [[ "$insV" = "$latestV" ]]; then
                echo -e "当前脚本版本: ${bblue}${insV}${plain} (最新)"
            else
                echo -e "当前脚本版本: ${bblue}${insV}${plain}"
                [[ -n $latestV ]] && echo -e "检测到最新版本: ${yellow}${latestV}${plain} (可选择19更新)"
            fi
        else
            echo -e "当前脚本版本: ${bblue}${latestV}${plain}"
        fi
        
        if [[ -n $inscore && -n $latcore ]]; then
            if [[ "$inscore" = "$latcore" ]]; then
                echo -e "当前内核版本: ${bblue}${inscore}${plain} (最新)"
            else
                echo -e "当前内核版本: ${bblue}${inscore}${plain}"
                echo -e "检测到最新内核: ${yellow}${latcore}${plain} (可选择20更新)"
            fi
        fi
        
        # VPS 状态
        echo -e "VPS状态: 系统:${blue}$op${plain} 内核:${blue}$kernel_version${plain} 架构:${blue}$cpu${plain} 虚拟化:${blue}$vi${plain}"
        
        # 服务状态
        if systemctl is-active --quiet naiveproxy 2>/dev/null && [[ -f $CADDYFILE ]]; then
            echo -e "NaiveProxy状态: ${green}运行中${plain}"
        elif [[ -f $CADDYFILE ]]; then
            echo -e "NaiveProxy状态: ${yellow}未启动${plain}"
        else
            echo -e "NaiveProxy状态: ${red}未安装${plain}"
        fi
        
        red "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        readp "请输入数字【0-20】:" Input
        
        case "$Input" in
            1) quick_install;;
            2) uninstall;;
            3) install_caddy;;
            4) install_service;;
            5) add_user;;
            6) del_user;;
            7) list_users; read -p "按回车继续...";;
            8) add_domain;;
            9) del_domain;;
            10) list_domains; read -p "按回车继续...";;
            11) apply_cert;;
            12) generate_caddyfile && restart_service && show_share;;
            13) start_service;;
            14) stop_service;;
            15) multi_port;;
            16) show_status; read -p "按回车继续...";;
            17) show_share; read -p "按回车继续...";;
            18) view_log;;
            19) update_script;;
            20) update_kernel;;
            0) exit 0;;
            *) red "输入错误";;
        esac
    done
}

#===============================================================================
# 程序入口
#===============================================================================
check_deps
init_config
main_menu