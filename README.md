# NaiveProxy 多用户/多域名 管理面板 (全功能修复优化版)

这是一个经过全面深度重构与 Bug 修复的 NaiveProxy 管理脚本。支持多用户、多域名、自动化证书申请与续期、多端口复用、HTTP/3 (QUIC) 协议加速以及快捷分享。

## 本地化依赖 (免除外部依赖源失效的烦恼)
该仓库不仅包含了安装主脚本 `naiveproxy.sh`，还自带了所有的核心依赖包（存放在 `assets` 目录），包括：
- `caddy2-naive-linux-amd64.tar.gz` (预编译 Caddy v2 + forwardproxy)
- `caddy2-naive-linux-arm64.tar.gz`
- `acme.sh`

若将本仓库克隆至本地运行，脚本将**优先使用本地 assets 资产**，无需额外联网下载依赖；若上传至 GitHub，也可随时一键远程拉取。安装完成后，当前架构所需的依赖包会复制到 `/usr/local/share/naiveproxy/assets`，之后通过快捷命令 `na` 运行时同样使用本地包。

所有依赖包（本地或远程下载）都会按脚本内置的 SHA256 校验，校验值与 `assets/SHA256SUMS` 一致，不匹配时拒绝使用。组件版本、许可证与构建方式见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

---

## 核心修复与优化特性

1. **多域名 Caddyfile 独立 SNI 绑定修复**：重写了配置生成器，彻底修复多域名下因端口泛绑定冲突导致的 `ambiguous site definition: :443` 崩溃问题。
2. **端口解析与分享配置修复**：修复了原版正则无法匹配自定义端口导致分享链接与 V2rayN 配置强制退化为 443 端口的 Bug。
3. **ACME.sh 证书自动化续期与历史任务自愈**：接入官方 `--install-cert`，续期后自动重启服务加载新证书；Standalone 签发时只临时停止实际占用 80 端口的服务，完成后只恢复这些服务；启动时自动修复历史错误 Crontab 语法与旧版续期配置（本地操作，不联网）；内置证书到期倒计时检测与可视化状态展示。
4. **多端口复用功能安全重构**：重构多端口复用逻辑，彻底废弃不安全的 `sed` 盲改行号方式，优雅支持单个域名同时监听多端口。
5. **HTTP/3 (QUIC / UDP) 协议放行**：自动识别当前生效的防火墙（ufw / firewalld / iptables+ip6tables），同步放行 TCP 与 UDP 端口；记录脚本新增的规则，删除端口或卸载时只撤销这些规则。
6. **多用户客户端配置独立导出**：修复原版 `URL.txt` 循环覆盖 Bug，支持同时保存所有用户独立客户端配置（`v2rayn_<user>.json`）与节点二维码。
7. **系统安全权限加固**：敏感配置文件（`users.conf`、`Caddyfile`、私钥、分享链接）严格限制为 `600` 权限；用户名限字母数字下划线，密码限字母数字及 `. _ ~ -`，分享链接无需转义；配置先写临时文件并通过 `caddy validate` 校验后再替换，失败时原配置保持不变。
8. **内核 BBR 拥塞控制支持**：菜单选项【21】一键开启 BBR + FQ，配置写入 `/etc/sysctl.d/99-naiveproxy-bbr.conf`，重启后仍生效。

---

## 部署与使用指南

### 方式一：Git 克隆本地运行 (推荐，免改仓库地址)
```bash
git clone https://github.com/rainsmen/naivesh.git /root/naiveproxy
cd /root/naiveproxy
bash naiveproxy.sh
```
*本地克隆运行会自动识别并使用本地 `assets` 资产，无需任何额外配置。*

### 方式二：远程一键执行
若您已将本仓库 Fork 或 Push 到自己的 GitHub 仓库，可在 VPS 上直接通过 `curl` 运行：
```bash
bash <(curl -Ls https://raw.githubusercontent.com/rainsmen/naivesh/main/naiveproxy.sh)
```
*(如使用个人仓库，可修改 `naiveproxy.sh` 开头的 `REPO_URL`，或通过环境变量传递：`REPO_URL="https://raw.githubusercontent.com/用户名/仓库名/分支" bash <(curl ...)`。若替换了 `assets` 中的文件，需同步更新脚本内的 `ASSET_SHA256` 与 `assets/SHA256SUMS`，否则校验不通过。)*

---

## 脚本菜单功能导览

运行脚本后（或安装后直接使用快捷命令 `na`），输入对应数字即可执行管理操作：

- **1 一键安装 NaiveProxy**: 全自动安装 Caddy、配置首个用户/域名/端口、申请证书并启动服务。
- **2 卸载 NaiveProxy**: 移除 Caddy 二进制、配置、systemd 服务、本脚本申请的证书续期任务、脚本添加的防火墙规则与 NAT64 DNS 设置；可选是否同时卸载 acme.sh。BBR 设置会保留。
- **5-7 用户管理**: 动态添加、删除用户，查看用户清单。
- **8-10 域名管理**: 动态添加、删除域名，配置反代伪装站点。
- **11 申请/配置证书**: 支持 acme.sh 自动申请与自定义证书路径，自动挂载无感续期钩子。
- **12 生成配置并重启**: 每次增删用户、域名、证书后执行，重构配置并平滑重启生效。
- **15 多端口复用管理**: 动态增加/删除监听端口（如 443、8443 等），无需重建节点。
- **17 查看节点分享信息**: 批量查看所有用户节点链接、二维码与 V2rayN 客户端配置。
- **18 查看服务日志**: 查看最近 50 行运行日志，并支持按需开启实时日志追踪。
- **21 开启 BBR 拥塞控制**: 一键开启系统 BBR 算法，优化高丢包网络连接质量。
