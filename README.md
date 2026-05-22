# NaiveProxy 多用户/多域名 管理面板 (私有化定制版)

这是一个经过全面优化和 Bug 修复的 NaiveProxy 管理脚本。支持多用户、多域名、自动化证书申请以及快捷分享。

## 本地化依赖 (免除外部图床/源失效的烦恼)
该仓库不仅包含了安装主脚本 `naiveproxy.sh`，还自带了所有的核心依赖包（存放在 `assets` 目录），包括：
- `caddy2-naive-linux-amd64.tar.gz`
- `caddy2-naive-linux-arm64.tar.gz`
- `acme.sh`

将它们一同上传至您的私有或公开 GitHub 仓库后，即可确保随时可用，不受任何外部环境挂掉的影响。

## 修复的关键特性
1. **多域名 Caddyfile 绑定修复**：重写了配置生成器，不会再因为多域名泛绑定相同的端口导致服务瘫痪。
2. **ACME.sh 证书申请修复**：采用安全的 Standalone 模式，即使未配置服务器也能100%申请下证书。
3. **更安全的防火墙策略**：移除了粗暴清除系统防火墙的做法，改为安全的按需端口放行。

---

## 部署与使用指南

### 第一步：修改仓库地址并上传
1. 打开根目录下的 `naiveproxy.sh`。
2. 找到第 37 行：
   ```bash
   REPO_URL="https://raw.githubusercontent.com/rainsmen/naivesh/main"
   ```
3. 将 `rainsmen/naivesh/main` 替换为您真实的 GitHub 仓库名和分支。
4. 将本目录下的所有文件（包括 `assets` 文件夹及其内部依赖）Push 到您的 GitHub 仓库中。

### 第二步：在您的 VPS 上一键执行
通过 SSH 登录您的 VPS（推荐 Debian 11/12 或 Ubuntu 22.04），执行以下命令拉取并运行脚本：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/rainsmen/naivesh/main/naiveproxy.sh)
```
*(注意替换上述链接为您自己仓库的真实 Raw 地址)*

### 第三步：脚本菜单选项
运行脚本后，按数字键即可使用以下核心功能：
- **1 一键安装 NaiveProxy**: 适合初次安装，按提示操作即可完成安装、域名绑定、用户建立和一键分享。
- **5-11 用户和域名管理**: 可动态增加、删除用户和域名。
- **12 生成配置并重启**: 每次增删用户、域名、证书后，必须执行此步骤才能使新配置生效！
- **17 查看分享信息**: 一键生成各用户的客户端 V2rayN 配置文件内容及二维码分享链接。
