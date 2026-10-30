# 第三方组件说明

本项目分发以下第三方软件，各自遵循其原始许可证：`acme.sh` 位于仓库 `assets/` 目录，预编译 caddy 发布在 GitHub Releases (`caddy-v2.11.2`)。SHA256 见 `assets/SHA256SUMS`。

| 文件 | 组件 | 版本 | 许可证 | 来源 |
|---|---|---|---|---|
| `acme.sh` | acme.sh | 3.1.4 | GPL-3.0 | https://github.com/acmesh-official/acme.sh |
| `caddy2-naive-linux-amd64.tar.gz` / `caddy2-naive-linux-arm64.tar.gz` | Caddy | v2.11.2 | Apache-2.0 | https://github.com/caddyserver/caddy |
| 同上 (编译进 caddy) | forwardproxy (naive 分支) | klzgrad/forwardproxy@naive | Apache-2.0 | https://github.com/klzgrad/forwardproxy |

预编译 caddy 由 xcaddy 构建 (Go 1.25.8)，等价于：

```bash
xcaddy build v2.11.2 --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive
```

可用 `caddy build-info` 查看二进制内记录的构建信息。
