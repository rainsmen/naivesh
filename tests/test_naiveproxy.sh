#!/bin/bash
#===============================================================================
# NaiveProxy 脚本自动化测试套件 (无需 root，不修改宿主机状态)
# 覆盖：输入校验、配置解析、原子写入、ACME 配置读写、嵌入钩子语法、
#       多域名/多端口 Caddyfile 生成 + caddy validate/fmt + 实时 SNI/探测/重载验证
#===============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR_TEST="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
    if [[ -n ${CADDY_PID:-} ]]; then kill "$CADDY_PID" 2>/dev/null || true; wait "$CADDY_PID" 2>/dev/null || true; fi
    if [[ -n ${HTTP_PID:-} ]]; then kill "$HTTP_PID" 2>/dev/null || true; wait "$HTTP_PID" 2>/dev/null || true; fi
    rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

assert_ok() {
    local desc=$1
    shift
    if "$@"; then
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $desc" >&2
        FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    local desc=$1
    shift
    if ! "$@"; then
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $desc (expected failure, got success)" >&2
        FAIL=$((FAIL + 1))
    fi
}

assert_eq() {
    local desc=$1 expect=$2 actual=$3
    if [[ $expect == "$actual" ]]; then
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $desc: expected '$expect', got '$actual'" >&2
        FAIL=$((FAIL + 1))
    fi
}

# shellcheck source=../naiveproxy.sh
source "$REPO_ROOT/naiveproxy.sh"

# 1. 输入校验测试
assert_ok   "valid_user normal" valid_user "alice_01"
assert_fail "valid_user short"  valid_user "ab"
assert_fail "valid_user colon"  valid_user "a:b"

assert_ok   "valid_pass normal" valid_pass "Abc_123.~-"
assert_fail "valid_pass space"  valid_pass "bad pass"
assert_fail "valid_pass short"  valid_pass "1234"

assert_ok   "valid_domain standard" valid_domain "proxy.example.com"
assert_ok   "valid_domain punycode" valid_domain "sub.xn--fiqs8s"
assert_fail "valid_domain rejects IPv4" valid_domain "1.2.3.44"
assert_fail "valid_domain rejects numeric TLD" valid_domain "a.12"
assert_fail "valid_domain rejects hyphen TLD" valid_domain "a.-b"

assert_ok   "valid_ipv4 valid"   valid_ipv4 "127.0.0.1"
assert_ok   "valid_ipv4 max"     valid_ipv4 "255.255.255.0"
assert_fail "valid_ipv4 >255"    valid_ipv4 "999.999.999.999"

assert_ok   "valid_ipv6_literal" valid_ipv6_literal "[::1]"
assert_fail "valid_ipv6 bare"    valid_ipv6_literal "::1"

assert_ok   "valid_port 443"   valid_port "443"
assert_fail "valid_port 0443"  valid_port "0443"
assert_fail "valid_port 65536" valid_port "65536"

assert_ok   "valid_email normal"       valid_email "admin@example.com"
assert_fail "valid_email leading dash" valid_email "-admin@example.com"
assert_fail "valid_email pipe"         valid_email "a|b@example.com"

assert_eq "normalize_backend uppercase HTTPS" "example.com" "$(normalize_backend "HTTPS://Example.COM/path?a=1")"
assert_eq "normalize_backend preserves http"  "http://127.0.0.1:8080" "$(normalize_backend "HTTP://127.0.0.1:8080/index")"
assert_eq "normalize_backend bare domain"     "speed.cloudflare.com" "$(normalize_backend "  Speed.Cloudflare.Com  ")"
assert_eq "backend_url https default"         "https://speed.cloudflare.com" "$(backend_url "speed.cloudflare.com")"
assert_eq "backend_url http preserved"        "http://127.0.0.1:8080" "$(backend_url "http://127.0.0.1:8080")"

assert_ok   "valid_backend domain"        valid_backend "speed.cloudflare.com"
assert_ok   "valid_backend http ipv4"     valid_backend "http://127.0.0.1:8080"
assert_ok   "valid_backend ipv6 port"     valid_backend "[::1]:8080"
assert_fail "valid_backend invalid ipv4"  valid_backend "999.999.999.999"
assert_fail "valid_backend broken scheme" valid_backend "https:"

assert_eq "urlencode space" "a%20b" "$(urlencode "a b")"
assert_eq "mask_secret long" "ab****ef" "$(mask_secret "abcdef")"
assert_eq "mask_secret short" "****" "$(mask_secret "abc")"

# 2. write_file_atomic 自动建父目录 (修复卸载后重装崩溃)
MISSING_DEST="$TMPDIR_TEST/deleted_dir/sub/users.conf"
write_missing_dest_test() {
    echo "ok" | write_file_atomic "$MISSING_DEST" 600
}
assert_ok "write_file_atomic creates missing parent dir" write_missing_dest_test
assert_eq "write_file_atomic content" "ok" "$(cat "$MISSING_DEST")"
assert_eq "write_file_atomic mode 600" "600" "$(stat -c '%a' "$MISSING_DEST")"

# 3. 配置保存/加载 (含旧版 : 格式与新版 5 字段 | 格式)
CONFIG_DIR="$TMPDIR_TEST/etc_naiveproxy"
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
NAIVE_DIR="$TMPDIR_TEST/root_naive"
ACME_HOME="$TMPDIR_TEST/acme_home"
ACME_BIN="$ACME_HOME/acme.sh"
RUN_DIR="$TMPDIR_TEST/run_naiveproxy"
ADMIN_SOCK="$RUN_DIR/admin.sock"
mkdir -p "$CONFIG_DIR/certs" "$NAIVE_DIR" "$ACME_HOME" "$RUN_DIR"

cat > "$DOMAINS_FILE" <<'EOF'
# legacy + new
legacy.example.com:example.org:/tmp/c.crt:/tmp/k.key
new.example.com|http://127.0.0.1:8080|/tmp/c2.crt|/tmp/k2.key|manual
EOF
load_config
assert_eq "load legacy domain backend" "example.org" "${DOMAIN_BACKEND["legacy.example.com"]:-}"
assert_eq "load new http backend"      "http://127.0.0.1:8080" "${DOMAIN_BACKEND["new.example.com"]:-}"
assert_eq "load cert source manual"    "manual" "${DOMAIN_CERT_SRC["new.example.com"]:-}"

# 4. caddyfile_ports 排除 80 端口
cat > "$CADDYFILE" <<'EOF'
:80 {
	respond "ok"
}
:443, :8443 {
	respond "ok"
}
a.example.com:443, a.example.com:8443 {
	respond "ok"
}
EOF
assert_eq "caddyfile_ports ignores 80" $'443\n8443' "$(caddyfile_ports)"

# 5. acme_conf_get / acme_conf_set 与托管边界
mkdir -p "$ACME_HOME/a.example.com_ecc"
CONF_A="$ACME_HOME/a.example.com_ecc/a.example.com.conf"
printf "Le_Domain='a.example.com'\nLe_Webroot='no'\nLe_RealFullChainPath='%s'\n" "$CONFIG_DIR/certs/a.example.com/cert.crt" > "$CONF_A"
assert_ok "acme_conf_set base64" acme_conf_set "$CONF_A" Le_ReloadCmd "$ACME_RELOAD_CMD" base64
assert_eq "acme_conf_get base64" "$ACME_RELOAD_CMD" "$(acme_conf_get "$CONF_A" Le_ReloadCmd)"
assert_ok "acme_conf_is_ecc" acme_conf_is_ecc "$CONF_A"

DOMAIN_CERT["a.example.com"]="$CONFIG_DIR/certs/a.example.com/cert.crt"
DOMAIN_CERT_SRC["a.example.com"]="acme"
assert_ok "is_acme_managed_domain true for acme" is_acme_managed_domain "a.example.com"
DOMAIN_CERT_SRC["a.example.com"]="manual"
assert_fail "is_acme_managed_domain false for manual" is_acme_managed_domain "a.example.com"

# 6. 证书状态与公私钥匹配校验
mkdir -p "$CONFIG_DIR/certs/a.example.com" "$CONFIG_DIR/certs/b.example.com"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CONFIG_DIR/certs/a.example.com/private.key" \
    -out "$CONFIG_DIR/certs/a.example.com/cert.crt" \
    -days 60 -nodes -subj "/CN=a.example.com" -addext "subjectAltName=DNS:a.example.com" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CONFIG_DIR/certs/b.example.com/private.key" \
    -out "$CONFIG_DIR/certs/b.example.com/cert.crt" \
    -days 60 -nodes -subj "/CN=b.example.com" -addext "subjectAltName=DNS:b.example.com" >/dev/null 2>&1

assert_ok   "validate_cert_key_pair matching" validate_cert_key_pair "$CONFIG_DIR/certs/a.example.com/cert.crt" "$CONFIG_DIR/certs/a.example.com/private.key"
assert_fail "validate_cert_key_pair mismatched" validate_cert_key_pair "$CONFIG_DIR/certs/a.example.com/cert.crt" "$CONFIG_DIR/certs/b.example.com/private.key"

echo "not-a-cert" > "$TMPDIR_TEST/bad.crt"
assert_ok "get_cert_status_desc corrupt cert reports invalid" grep -q "无效/损坏" <<< "$(get_cert_status_desc "$TMPDIR_TEST/bad.crt")"

# 7. 嵌入式 acme-hook.sh 语法检查 (及 shellcheck -s sh)
write_acme_hook
assert_ok "acme-hook.sh sh -n" sh -n "$ACME_HOOK"
if command -v shellcheck &>/dev/null; then
    assert_ok "acme-hook.sh shellcheck -s sh" shellcheck -s sh "$ACME_HOOK"
fi

# 8. Caddyfile 生成 + caddy validate + caddy fmt + 实时多域名 SNI / 探测 / 热重载测试
CADDY_TAR=""
if [[ -f $REPO_ROOT/assets/caddy2-naive-linux-amd64.tar.gz && $(uname -m) == x86_64 ]]; then
    CADDY_TAR="$REPO_ROOT/assets/caddy2-naive-linux-amd64.tar.gz"
elif [[ -f $REPO_ROOT/assets/caddy2-naive-linux-arm64.tar.gz && $(uname -m) =~ ^(aarch64|arm64)$ ]]; then
    CADDY_TAR="$REPO_ROOT/assets/caddy2-naive-linux-arm64.tar.gz"
fi

check_caddy_fmt_clean() {
    local out
    out=$("$BINARY" validate --config "$CADDYFILE" --adapter caddyfile 2>&1)
    ! grep -q "Caddyfile input is not formatted" <<< "$out"
}

if [[ -n $CADDY_TAR ]]; then
    tar -zxf "$CADDY_TAR" -C "$TMPDIR_TEST" caddy
    BINARY="$TMPDIR_TEST/caddy"
    chmod 755 "$BINARY"

    # 启动两个本地 HTTP 后端模拟不同域名的独立伪装站
    mkdir -p "$TMPDIR_TEST/site_a" "$TMPDIR_TEST/site_b"
    echo "CAMOUFLAGE_SITE_A" > "$TMPDIR_TEST/site_a/index.html"
    echo "CAMOUFLAGE_SITE_B" > "$TMPDIR_TEST/site_b/index.html"
    python3 -m http.server 18091 --bind 127.0.0.1 -d "$TMPDIR_TEST/site_a" >/dev/null 2>&1 &
    HTTP_PID=$!
    python3 -m http.server 18092 --bind 127.0.0.1 -d "$TMPDIR_TEST/site_b" >/dev/null 2>&1 &
    HTTP_PID2=$!

    USER_PASS=(["alice"]="Pass_12345")
    USER_EMAIL=(["alice"]="alice@example.com")
    save_users

    DOMAIN_BACKEND=(["a.example.com"]="http://127.0.0.1:18091" ["b.example.com"]="http://127.0.0.1:18092")
    DOMAIN_CERT=(["a.example.com"]="$CONFIG_DIR/certs/a.example.com/cert.crt" ["b.example.com"]="$CONFIG_DIR/certs/b.example.com/cert.crt")
    DOMAIN_KEY=(["a.example.com"]="$CONFIG_DIR/certs/a.example.com/private.key" ["b.example.com"]="$CONFIG_DIR/certs/b.example.com/private.key")
    DOMAIN_CERT_SRC=(["a.example.com"]="acme" ["b.example.com"]="manual")
    save_domains

    PROXY_PORTS=(19445 19446)
    save_ports

    assert_ok "generate_caddyfile multi-domain multi-port" generate_caddyfile 80
    assert_ok "caddy fmt has zero formatting warnings" check_caddy_fmt_clean

    # 实时启动 Caddy 校验 SNI 证书隔离、多域名探测伪装一致、裸 IP 阻断及 Unix Socket 热重载
    "$BINARY" run --config "$CADDYFILE" --adapter caddyfile >"$TMPDIR_TEST/caddy.log" 2>&1 &
    CADDY_PID=$!
    sleep 1

    sni_a_subj=$(openssl s_client -connect 127.0.0.1:19445 -servername a.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject || true)
    sni_b_subj=$(openssl s_client -connect 127.0.0.1:19445 -servername b.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject || true)
    bare_subj=$(openssl s_client -connect 127.0.0.1:19445 -noservername </dev/null 2>/dev/null | openssl x509 -noout -subject || true)
    assert_ok "TLS SNI a.example.com serves a cert" grep -q "a.example.com" <<< "$sni_a_subj"
    assert_ok "TLS SNI b.example.com serves b cert" grep -q "b.example.com" <<< "$sni_b_subj"
    assert_ok "Bare IP serves localhost fallback cert (no domain leak)" grep -q "localhost" <<< "$bare_subj"

    body_a=$(curl -sk --resolve a.example.com:19445:127.0.0.1 https://a.example.com:19445/ || true)
    body_b=$(curl -sk --resolve b.example.com:19445:127.0.0.1 https://b.example.com:19445/ || true)
    probe_a=$(curl -sk --proxy-insecure --resolve a.example.com:19445:127.0.0.1 -x https://bad:bad@a.example.com:19445 http://example.org/ || true)
    probe_b=$(curl -sk --proxy-insecure --resolve b.example.com:19445:127.0.0.1 -x https://bad:bad@b.example.com:19445 http://example.org/ || true)
    assert_eq "GET a.example.com returns site A" "CAMOUFLAGE_SITE_A" "$body_a"
    assert_eq "GET b.example.com returns site B" "CAMOUFLAGE_SITE_B" "$body_b"
    assert_eq "Invalid-auth CONNECT probe on a returns site A" "CAMOUFLAGE_SITE_A" "$probe_a"
    assert_eq "Invalid-auth CONNECT probe on b returns site B" "CAMOUFLAGE_SITE_B" "$probe_b"
    assert_fail "Bare IP GET is aborted" curl -sk --max-time 3 https://127.0.0.1:19445/

    # 校验合法凭据经 b.example.com 建立 HTTP/2 CONNECT 隧道 (200)
    connect_out=$(curl -svk --proxy-http2 --proxytunnel --proxy-insecure --max-time 3 \
        --resolve b.example.com:19446:127.0.0.1 \
        -x https://alice:Pass_12345@b.example.com:19446 \
        http://127.0.0.1:18091/ 2>&1 || true)
    assert_ok "Valid HTTP/2 CONNECT tunnel via b.example.com on secondary port" grep -q "CONNECT tunnel established, response 200" <<< "$connect_out"

    # 校验 Unix Socket 零中断热重载
    assert_ok "Caddy reload via private unix socket" "$BINARY" reload --force --config "$CADDYFILE" --adapter caddyfile --address "unix/$ADMIN_SOCK" >/dev/null 2>&1

    kill "$HTTP_PID2" 2>/dev/null || true
    wait "$HTTP_PID2" 2>/dev/null || true
else
    echo "[SKIP] 未找到本机架构的预编译 Caddy 压缩包，跳过实时 Caddy 测试"
fi

echo "测试完成: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
