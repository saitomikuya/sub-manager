# SubManager

一个轻量的自托管订阅服务。通过中文 Web 后台维护多条订阅，把节点原始内容动态编码为标准 Base64，并记录每条订阅的拉取次数、IP、时间、客户端和 User-Agent。

## 功能

- `/admin` 管理后台，无用户名，初始密码为 `password`
- 首次登录强制修改密码，新密码最少 4 位
- 自动生成或手动设置订阅路径
- 为每条订阅生成兼容 `sub://` 规则的可扫描二维码
- 新增、编辑、删除、启用和停用订阅
- 批量把任意多条订阅更新为相同节点内容
- 标准 Base64 订阅输出，适用于主流代理客户端
- 拉取次数、最后拉取时间和最后拉取 IP
- 访问日志分页、IP 搜索、客户端筛选和清理
- HTTP 和 HTTPS 环境均可一键复制订阅地址
- 可配置日志保留天数及可信反向代理网段，安全记录真实客户端 IP
- SQLite 持久化、CSRF 防护、登录限速和安全 Cookie

> Base64 是编码，不是加密。订阅地址和节点内容都应视为敏感信息，公网部署请使用 HTTPS，并使用不容易猜到的随机路径。

## Docker Compose 部署

```bash
docker compose up -d --build
```

也可以直接使用 Docker Hub 已构建镜像，一条命令启动：

```bash
docker run -d --name sub-manager --restart unless-stopped -p 8080:8080 -e TZ=Asia/Shanghai -v sub-manager-data:/data saitomikuya/sub-manager:latest
```

打开：

- 管理后台：`http://服务器地址:8080/admin`
- 初始密码：`password`

首次登录会强制进入修改密码页面。数据保存在 Docker 命名卷 `sub-manager-data` 的 `/data/app.db` 中，重新构建容器不会丢失。

新增订阅后，例如路径设置为 `/ss`，在客户端中填写：

```text
http://服务器地址:8080/ss
```

## 配置项

可在 `docker-compose.yml` 中设置：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `ADDR` | `:8080` | 服务监听地址 |
| `DATA_DIR` | `/data` | SQLite 数据目录 |
| `DATABASE_PATH` | 空 | 自定义数据库完整路径，设置后优先于 `DATA_DIR` |
| `BASE_URL` | 自动识别 | 后台显示和复制订阅地址时使用的外部基础 URL |
| `COOKIE_SECURE` | `auto` | `true`、`false` 或 `auto`；HTTPS 公网部署建议设为 `true` |
| `TRUSTED_PROXIES` | 空 | 逗号分隔的可信代理 IP/CIDR；默认不信任任何代理 |
| `TZ` | `Asia/Shanghai` | 页面时间显示时区 |

使用反向代理时，建议将 `BASE_URL` 设置为外部地址，例如：

```yaml
environment:
  BASE_URL: https://sub.example.com
  COOKIE_SECURE: "true"
  TRUSTED_PROXIES: 172.17.0.1/32
```

`TRUSTED_PROXIES` 支持单个 IPv4、IPv6 和 CIDR，例如：

```dotenv
TRUSTED_PROXIES=172.17.0.1/32,10.0.0.0/8,2001:db8::1/128
```

配置会在启动时校验；无效 IP/CIDR 会使程序明确报错退出。登录后台后，也可以在“系统设置 → 可信代理 IP / CIDR”中配置，支持逗号或换行分隔，保存后立即生效。页面配置保存在数据库中，并与环境变量合并；两处均为空时不信任任何代理。

应用先检查 TCP `RemoteAddr`。只有直接连接方命中可信范围时，才会从右向左检查 `X-Forwarded-For`，跳过可信代理并取第一个不受信任的有效地址；没有 `X-Forwarded-For` 时才会接受单一、有效的 `X-Real-IP`。代理头缺失或畸形时回退到 `RemoteAddr`。

> **安全警告：** 启用可信代理后，不要让不可信公网客户端绕过 Caddy 直接访问应用端口。否则当其连接地址落入可信范围时，可能伪造 IP 请求头。不要信任全部私网，只配置真正连接到应用的代理 IP 或最小网段。

## Caddy HTTPS 示例

```caddyfile
sub.example.com {
    reverse_proxy 172.17.0.1:8081
}
```

上述现有拓扑需要设置 `TRUSTED_PROXIES=172.17.0.1/32`，并通过防火墙确保宿主机 8081 不可被公网直接访问。

更推荐让 Caddy 和 SubManager 使用同一个自定义 Docker 网络，Caddy 直接访问 `sub-manager:8080`，SubManager 不配置 `ports` 公网映射。下面是可直接调整的 Compose 示例：

```yaml
services:
  sub-manager:
    image: saitomikuya/sub-manager:1.0.1
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      BASE_URL: https://sub.example.com
      COOKIE_SECURE: "true"
      TRUSTED_PROXIES: 172.30.0.2/32
    volumes:
      - sub-manager-data:/data
    networks:
      proxy:
        ipv4_address: 172.30.0.3

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
    networks:
      proxy:
        ipv4_address: 172.30.0.2

networks:
  proxy:
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  sub-manager-data:
  caddy-data:
```

对应的 `Caddyfile`：

```caddyfile
sub.example.com {
    reverse_proxy sub-manager:8080
}
```

## 日志与隐私

每次成功拉取（HTTP 200）会记录：

- 时间
- 客户端 IP
- 根据 User-Agent 判断的客户端名称
- 完整 User-Agent（最长保存 1024 字节）
- 请求方法和状态码

系统默认保留 90 天访问日志，每天自动清理。后台可设置为 `0` 永久保留。清理访问日志不会清零订阅的累计拉取次数。

客户端名称依赖 User-Agent，只能作为辅助判断；客户端不发送或伪装 User-Agent 时会显示为“未知客户端”或识别为其他客户端。

## 备份与恢复

停止服务后，把整个数据卷打包到当前目录：

```bash
docker compose stop
docker run --rm \
  -v sub-manager-data:/data:ro \
  -v "$PWD":/backup \
  alpine:3.21 tar czf /backup/sub-manager-data-backup.tar.gz -C /data .
docker compose start
```

恢复时停止服务，把备份完整解压回 `sub-manager-data` 数据卷。始终备份整个卷，避免遗漏 SQLite 的 WAL 文件。执行 `docker compose down -v` 会删除数据卷，请勿在没有备份时使用 `-v`。

## 本地开发

需要 Go 1.23 或更高版本：

```bash
mkdir -p ./data
DATA_DIR=./data go run ./cmd/server
```

运行测试和构建：

```bash
go test ./...
go build ./cmd/server
```

## 自动发布镜像

GitHub Actions 支持手动触发构建并发布以下平台：

- `linux/amd64`
- `linux/arm64`

GitHub 仓库需要配置两个 Actions Secrets：

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

配置完成后，在 GitHub 仓库的 **Actions → Build and publish Docker image → Run workflow** 中手动发布。
