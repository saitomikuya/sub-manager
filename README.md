# SubManager

一个轻量的自托管订阅服务。通过中文 Web 后台维护文本订阅和文件订阅，记录每条订阅的拉取次数、IP、时间、客户端和 User-Agent，并对上传文件进行内容去重和独立统计。

## 功能

- `/admin` 管理后台，无用户名，初始密码为 `password`
- 首次登录强制修改密码，新密码最少 4 位
- 自动生成或手动设置订阅路径
- 为文本订阅生成兼容 `sub://` 规则的可扫描二维码
- 新增、编辑、删除、启用和停用订阅
- 批量把任意多条订阅更新为相同节点内容
- 标准 Base64 订阅输出，适用于主流代理客户端
- 上传原始文件并通过独立订阅路径下载
- 基于 MD5 检查及 SHA-256 校验的文件去重，同一文件可关联多条订阅
- 文件管理、关联订阅、替换、解除关联、查看、下载和文件维度统计
- 文件详情页一键替换文件，同步更新所有关联订阅
- 文件订阅列表显示本次更新后的拉取次数，替换为不同内容后重新计数
- 拉取次数、最后拉取时间和最后拉取 IP
- 访问日志分页、IP 搜索、客户端筛选和清理
- HTTP 和 HTTPS 环境均可一键复制订阅地址
- 可配置日志保留天数及可信反向代理网段，安全记录真实客户端 IP
- SQLite 持久化、CSRF 防护、登录限速和安全 Cookie

> Base64 是编码，不是加密。订阅地址和节点内容都应视为敏感信息，公网部署请使用 HTTPS，并使用不容易猜到的随机路径。

## 文件订阅快速上手

管理后台现在分为“文本订阅”“文件订阅”和“文件管理”三个入口：

1. 进入“文件订阅”，选择“新增文件订阅”，填写名称和随机访问路径后上传文件。
2. 文件订阅地址会直接返回原始文件；它不会进行 Base64 编码，也不会生成二维码。
3. 在订阅编辑页可以查看、下载、替换或解除当前文件关联；解除关联会自动停用订阅，但不会删除原始文件。
4. 进入“文件管理”可以查看所有去重后的原始文件，并直接基于已有文件创建新的关联订阅，无需重复上传。
5. 当同一文件关联多个订阅时，进入该文件的详情页，展开“更新替换文件”，上传新文件并点击“替换并更新所有关联订阅”。所有当前关联订阅会一起切换到新文件，下载文件名同步更新，各条订阅的名称、地址和启停状态保留；操作完成后进入新文件的详情页。

相同内容的文件只保存一份，但可以对应多条独立访问路径。例如同一份配置文件关联 `/team-a` 和 `/team-b` 后，两条链接分别统计拉取次数，文件管理同时展示该原始文件跨链接的汇总下载次数。

统计分为以下维度：

| 维度 | 含义 |
|---|---|
| 更新后拉取 | 文件订阅自最近一次替换为不同内容后的拉取次数，文件订阅列表显示此值 |
| 订阅累计拉取 | 某条访问路径的全部历史拉取次数，替换文件后继续累计 |
| 文件累计下载 | 某个原始文件通过所有订阅路径产生的累计下载次数 |
| 该文件下载 | 某个原始文件通过某条关联订阅产生的累计下载次数 |

单条订阅编辑页替换文件和文件详情页统一替换都会重置受影响订阅的“更新后拉取”，历史累计次数和访问日志保留。上传与当前文件相同的内容不会重置计数；换回以前用过的文件内容也会从零重新计数。新文件如果已存在，系统会去重复用，已关联新文件的其他订阅及其计数保留。

升级到 1.2.0 时，系统用每条订阅当前关联文件已有的下载次数初始化“更新后拉取”。旧版本没有记录每次关联切换的独立计数，初始化值可能包含以前使用同一文件时的下载；升级后的每次内容替换会准确重新计数，重启和清理日志不会重置计数。

后台查看、后台下载和 HEAD 请求不会增加公开下载统计。文件订阅采用原始文件响应，并带有安全的文件名、内容类型、长度和 ETag 响应头。

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

首次登录会强制进入修改密码页面。数据库保存在 Docker 命名卷 `sub-manager-data` 的 `/data/app.db` 中；Docker Compose 默认把上传文件映射到当前目录的 `./files`。

首次使用 Docker Compose 时，请确保文件目录允许容器内 UID `10001` 写入：

```bash
mkdir -p ./files
sudo chown -R 10001:10001 ./files
```

可以通过 `FILES_PATH` 改为其他宿主机目录：

```bash
FILES_PATH=/srv/sub-manager/files docker compose up -d --build
```

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
| `FILES_DIR` | `/data/files` | 上传文件在容器内的存储目录 |
| `MAX_UPLOAD_SIZE_MB` | `100` | 单个上传文件大小上限，范围 1 到 10240 MiB |
| `BASE_URL` | 自动识别 | 后台显示和复制订阅地址时使用的外部基础 URL |
| `COOKIE_SECURE` | `auto` | `true`、`false` 或 `auto`；HTTPS 公网部署建议设为 `true` |
| `TRUSTED_PROXIES` | 空 | 可选的可信代理 IP/CIDR；留空时默认信任所有直接来源 |
| `TZ` | `Asia/Shanghai` | 页面时间显示时区 |

使用反向代理时，建议将 `BASE_URL` 设置为外部地址，例如：

```yaml
environment:
  BASE_URL: https://sub.example.com
  COOKIE_SECURE: "true"
```

无需设置 `TRUSTED_PROXIES` 即可读取 Caddy 传来的真实 IP。若要把信任范围收紧为指定代理，它支持单个 IPv4、IPv6 和 CIDR，例如：

```dotenv
TRUSTED_PROXIES=172.17.0.1/32,10.0.0.0/8,2001:db8::1/128
```

配置会在启动时校验；无效 IP/CIDR 会使程序明确报错退出。登录后台后，也可以在“系统设置 → 可信代理 IP / CIDR”中配置，支持逗号或换行分隔，保存后立即生效。环境变量和页面配置均为空时默认信任所有直接来源；页面填写范围后，只信任所填范围；显式环境变量会与页面配置合并。

应用先解析 TCP `RemoteAddr`。默认模式会接受所有直接连接方的代理头；配置了范围后，只有直接连接方命中可信范围才读取代理头。`X-Forwarded-For` 会从右向左检查，跳过显式配置的可信代理并取第一个不受信任的有效地址；没有 `X-Forwarded-For` 时才接受单一、有效的 `X-Real-IP`。代理头缺失或畸形时回退到 `RemoteAddr`。

> **安全警告：** 默认信任所有来源意味着任何能直连应用端口的客户端都可以伪造 IP 请求头。必须让 Caddy 覆盖 `X-Forwarded-For` 和 `X-Real-IP`，并避免应用端口被公网绕过 Caddy 直接访问。安全要求更高时，请在后台或环境变量中只填写真正的代理地址。

## Caddy HTTPS 示例

```caddyfile
sub.example.com {
    reverse_proxy 172.17.0.1:8081
}
```

上述现有拓扑无需设置 `TRUSTED_PROXIES`；仍应通过防火墙确保宿主机 8081 不可被公网直接访问。若希望收紧范围，可选配 `TRUSTED_PROXIES=172.17.0.1/32`。

更推荐让 Caddy 和 SubManager 使用同一个自定义 Docker 网络，Caddy 直接访问 `sub-manager:8080`，SubManager 不配置 `ports` 公网映射。下面是可直接调整的 Compose 示例：

```yaml
services:
  sub-manager:
    image: saitomikuya/sub-manager:1.2.0
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      BASE_URL: https://sub.example.com
      COOKIE_SECURE: "true"
      TRUSTED_PROXIES: 172.30.0.2/32
      FILES_DIR: /data/files
      MAX_UPLOAD_SIZE_MB: "100"
    volumes:
      - sub-manager-data:/data
      - ./files:/data/files
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

文件订阅列表展示最近一次文件内容更新后的拉取次数。文件详情页还保留订阅链接累计拉取次数、原始文件跨链接累计下载次数，以及文件通过当前关联订阅产生的累计下载次数。后台查看和下载文件不会进入公开订阅统计；HEAD 请求也不计数。

## 文件存储与去重

文件订阅公开地址直接返回原始文件，不进行 Base64 编码。文本订阅保持原有 Base64 输出不变。

上传过程会同时计算 MD5 和 SHA-256。系统先使用 MD5 检查候选文件，再通过 SHA-256 和文件大小确认内容一致；相同内容只在磁盘保存一份，但可以创建任意多条独立订阅链接。从“文件管理”中可以直接选择已有文件创建新的关联订阅。

解除文件与订阅的关联会自动停用该订阅，但不会删除原始文件。只有不再关联任何订阅的文件才能从文件管理中彻底删除。

文件详情页的统一替换在同一个数据库事务中更新全部当前关联订阅。替换完成后原文件保留为未关联文件，历史日志和统计仍可查询；可从文件管理中手动删除不再需要的原文件。没有关联订阅的文件需要先创建关联订阅才能使用统一替换。

客户端名称依赖 User-Agent，只能作为辅助判断；客户端不发送或伪装 User-Agent 时会显示为“未知客户端”或识别为其他客户端。

## 备份与恢复

停止服务后，分别备份数据库卷和宿主机文件目录：

```bash
docker compose stop
docker run --rm \
  -v sub-manager-data:/data:ro \
  -v "$PWD":/backup \
  alpine:3.21 tar czf /backup/sub-manager-database-backup.tar.gz -C /data .
tar czf sub-manager-files-backup.tar.gz -C ./files .
docker compose start
```

恢复时停止服务，把数据库备份完整解压回 `sub-manager-data` 数据卷，并把文件备份恢复到 `FILES_PATH` 对应目录。数据库和文件目录必须来自同一次停机备份，避免关联记录与物理文件不一致。执行 `docker compose down -v` 会删除数据库卷，请勿在没有备份时使用 `-v`。

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
- `DOCKERHUB_TOKEN_RELEASE`

配置完成后，在 GitHub 仓库的 **Actions → Build and publish Docker image → Run workflow** 中手动发布。工作流会运行测试，推送版本号、提交 SHA 和 `latest` 标签，并验证多架构清单与容器健康状态。
