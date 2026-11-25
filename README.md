# NaiveProxy 多用户/多域名 管理面板 (全功能修复优化版)

这是一个经过全面深度重构与安全加固的 NaiveProxy 管理脚本。支持多用户、多域名、自动化证书申请与无感续期（含纯 IPv6 主机）、多端口复用、HTTP/3 (QUIC) 协议加速以及快捷分享。

## 依赖包 (固定版本 + SHA256 校验)
脚本使用以下固定版本的依赖包：
- `acme.sh`：随仓库存放在 `assets` 目录
- `caddy2-naive-linux-amd64.tar.gz` / `caddy2-naive-linux-arm64.tar.gz` (预编译 Caddy v2 + forwardproxy)：发布在 [GitHub Releases](https://github.com/rainsmen/naivesh/releases/tag/caddy-v2.11.2)，不放入 git 仓库

脚本按以下顺序查找依赖包：脚本目录下的 `assets/`、`/usr/local/share/naiveproxy/assets/`，都没有时再下载（acme.sh 来自仓库，caddy 来自 Releases）。下载成功后会缓存到 `/usr/local/share/naiveproxy/assets`，之后通过快捷命令 `na` 运行时直接使用缓存。离线环境可先把对应的 tar.gz 放进 `assets/` 目录。

所有依赖包（本地或下载）都会按脚本内置的 SHA256 校验，校验值与 `assets/SHA256SUMS` 一致，不匹配时拒绝使用。组件版本、许可证与构建方式见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 许可证
本项目以 [GPL-3.0](LICENSE) 许可证发布。

---

## 核心修复与优化特性

1. **多域名精准 SNI 伪装与裸 IP 证书隔离**：重构 Caddyfile 路由结构——通配端口块使用本地自签回退证书隔离裸 IP/未知 SNI 扫描并直接断开，已知 SNI 先经 `forward_proxy` 鉴权，失败后按实际 SNI 精准回退到对应域名的反代伪装站（支持 `https://` 与本地 `http://` 伪装后端）。
2. **独立二进制路径与系统安全加固**：二进制安装至 `/usr/local/bin/caddy-naive`（自动兼容迁移旧版 `/usr/bin/caddy`，避免与系统包管理器冲突）；systemd 以专用低权用户 `naiveproxy` + `Type=notify` + 沙箱隔离运行；Caddy Admin API 收口为私有 Unix Socket (`/run/naiveproxy/admin.sock`) 并关闭 `persist_config`，杜绝 `127.0.0.1:2019` 端口冲突与凭据落盘泄露。
3. **纯 IPv6 与 ACME.sh 全生命周期自愈**：自动检测纯 IPv6 / 仅 AAAA / WARP-IPv4 环境并启用 `--listen-v6`；默认签发 ECDSA (`ec-256`) 证书，通过私有 Unix Socket 执行无感热重载 (`systemctl try-reload-or-restart`)；记录证书来源（ACME/手动），删域名/换手动证书/卸载时精确清理，不误删外部服务证书；手动证书导入前校验证书与私钥匹配性。
4. **全栈防火墙支持与规则记账**：支持 `ufw`、`firewalld`、`nftables` 及独立记账的 `iptables`/`ip6tables`，同步放行 TCP 与 UDP（HTTP/3），尊重用户手动防火墙偏好，删除端口或卸载时只撤销本脚本添加的规则。
5. **HTTP/2 与 HTTP/3 (QUIC) 双协议分享**：支持同时导出所有用户的客户端配置（`v2rayn_<user>.json`）以及包含域名的 `naive+https://`（H2）与 `naive+quic://`（H3）分享链接；状态与用户列表默认密码脱敏，防止截图泄密。
6. **内核 BBR 与 QUIC UDP 缓冲优化**：菜单选项【21】一键开启 BBR + FQ 并调优 UDP 收发缓冲区（`rmem_max`/`wmem_max`），配置写入 `/etc/sysctl.d/99-naiveproxy-bbr.conf`。
7. **自动化测试与可复现构建**：内置 `tests/test_naiveproxy.sh`（覆盖输入校验、配置解析、嵌入式钩子语法、多域名 `caddy validate` 与实时 SNI/探测/热重载测试），并在 CI 中开启全量 ShellCheck（含 `SC2154`）。

---

## 部署与使用指南

### 方式一：Git 克隆本地运行 (推荐，免改仓库地址)
```bash
git clone https://github.com/rainsmen/naivesh.git /root/naiveproxy
cd /root/naiveproxy
bash naiveproxy.sh
```
*本地克隆运行会直接使用仓库内的 acme.sh，caddy 预编译包首次安装时从 Releases 下载并校验。*

### 方式二：远程一键执行
若您已将本仓库 Fork 或 Push 到自己的 GitHub 仓库，可在 VPS 上直接通过 `curl` 运行：
```bash
bash <(curl -Ls https://raw.githubusercontent.com/rainsmen/naivesh/main/naiveproxy.sh)
```
*(如使用个人仓库，可修改 `naiveproxy.sh` 开头的 `REPO_URL`，或通过环境变量传递：`REPO_URL="https://raw.githubusercontent.com/用户名/仓库名/分支" bash <(curl ...)`。caddy 下载地址可用 `RELEASE_URL` 覆盖。若替换了依赖包，需同步更新脚本内的 `ASSET_SHA256` 与 `assets/SHA256SUMS`，否则校验不通过。)*

---

## 脚本菜单功能导览

运行脚本后（或安装后直接使用快捷命令 `na`），输入对应数字即可执行管理操作：

- **1 一键安装 NaiveProxy**: 全自动安装 Caddy、配置首个用户/域名/端口、申请证书并启动服务（失败时自动回滚原有配置）。
- **2 卸载 NaiveProxy**: 移除独立 Caddy 二进制、配置、systemd 服务、本脚本托管的证书续期任务、脚本添加的防火墙规则与 NAT64 DNS 设置；可选是否同时卸载 acme.sh 与专用系统用户 `naiveproxy`。BBR 设置会保留。
- **5-7 用户管理**: 动态添加、删除用户，查看脱敏/明文用户清单。
- **8-10 域名管理**: 动态添加、删除域名（同步清理证书与续期任务），配置 HTTPS 或本地 HTTP 反代伪装站点。
- **11 申请/配置证书**: 支持 acme.sh 自动申请（支持纯 IPv6）与手动证书导入（校验公私钥匹配），自动挂载无感续期重载钩子。
- **12 生成配置并热重载服务**: 每次增删用户、域名、证书后执行，校验新配置并无感热重载生效。
- **15 多端口复用管理**: 动态增加/删除监听端口（如 443、8443 等），失败自动回滚。
- **17 查看节点分享信息**: 批量查看所有用户的 H2/H3 节点链接、二维码与 V2rayN 客户端配置。
- **18 查看服务日志**: 查看最近 50 行运行日志，支持实时日志追踪（`Ctrl+C` 返回菜单）。
- **21 开启 BBR 与 QUIC 拥塞/缓冲优化**: 一键开启 BBR + FQ 并调优 HTTP/3 UDP 缓冲区。
