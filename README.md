# auth-center

一个面向自托管场景的多身份提供商认证中心。项目将 GitHub、Google 等第三方登录统一封装，并提供 OIDC/OAuth 风格接口，方便 Web 应用、反向代理和内部服务复用统一登录能力。

> 当前项目处于 beta candidate 阶段，适合受控环境试用和二次开发。正式暴露到公网前，仍需完成密钥轮换、完整安全审计和生产级运维验证。

项目当前没有发布稳定版本，也没有兼容旧版 `r9s-access` 的 `/v1/*` 接口。API 和配置格式可能在 `v0.x` 阶段发生变化。

## 特性

- GitHub OAuth 登录
- Google 登录
- 可扩展的 `IdentityProvider` 接口
- Authorization Code + PKCE 登录流程
- 一次性 authorization code 和过期控制
- OIDC Discovery、UserInfo、Token Introspection 和 JWKS 端点
- Redis 生产存储与内存开发存储
- 严格的客户端 redirect URI 白名单
- 健康检查、就绪检查和 Prometheus metrics
- Docker / Docker Compose 本地运行方式
- Go 模块化代码结构，便于替换存储和身份提供商
- 统一用户模型，支持 GitHub / Google verified email 账号关联

## 架构概览

```text
浏览器 / 业务应用
        │
        │ OIDC Authorization Code + PKCE
        ▼
   auth-center ─────── GitHub / Google
        │
        ├── /oauth/authorize
        ├── /oauth/token
        ├── /userinfo
        ├── /oauth/introspect
        └── /.well-known/openid-configuration
        │
        └── Redis（生产）或内存存储（开发）
```

核心目录：

```text
config/       YAML 配置加载和校验
provider/     GitHub、Google 及身份提供商抽象
server/       HTTP/OIDC 端点
store/        Redis 与内存存储实现
identity/     用户和 provider identity 持久化、账号关联
policy/       授权策略基础类型
cmd/authd/    服务启动入口
```

## 快速开始

### 环境要求

- Go 1.25+
- Docker（可选）
- Redis（生产环境推荐；本地可使用内存存储）

### 1. 获取代码并准备配置

```bash
git clone https://github.com/edgefn/auth-center.git
cd auth-center
cp config.example.yaml config.local.yaml
```

编辑 `config.local.yaml`，将 `${GITHUB_CLIENT_ID}`、`${GITHUB_CLIENT_SECRET}`、`${GOOGLE_CLIENT_ID}` 和 `${GOOGLE_CLIENT_SECRET}` 替换为真实值。当前配置文件按 YAML 直接读取，示例中的 `${...}` 只是占位符，不会自动展开环境变量。

### 2. 配置 OAuth 应用

GitHub OAuth App 的回调地址：

```text
http://localhost:8080/oauth/callback/github
```

Google OAuth Client 的回调地址：

```text
http://localhost:8080/oauth/callback/google
```

生产环境必须使用 HTTPS，并将 `issuer`、回调地址和客户端 redirect URI 替换为正式域名。

生产环境建议预先生成并安全保存 signing key：

```bash
openssl genrsa 2048 > signing-key.pem
openssl rsa -in signing-key.pem -traditional -outform DER | base64 -w0
```

### 3. 启动服务

```bash
go run ./cmd/authd config.local.yaml
```

验证服务：

```bash
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

### Docker Compose

```bash
docker compose up --build
```

Compose 示例会启动认证服务和 Redis。生产部署时请使用密钥管理系统注入凭据，不要把真实 secret 提交到 Git。

### systemd / Kubernetes

仓库提供基础模板：

- `deploy/systemd/auth-center.service`
- `deploy/kubernetes/deployment.yaml`
- `deploy/kubernetes/config-secret.example.yaml`

Kubernetes 部署至少需要配置多副本共享 Redis，并通过 Secret 注入持久化 `signing_key`。systemd 部署应使用专用非 root 用户和宿主机反向代理提供 TLS。

## 接入示例

业务应用首先从 Discovery 文档读取端点，然后将用户导向授权地址。示例（省略 URL 编码）：

```text
https://auth.example.com/oauth/authorize?
  client_id=docs&
  redirect_uri=https%3A%2F%2Fdocs.example.com%2Foauth%2Fcallback&
  response_type=code&
  scope=openid%20profile%20email&
  state=<random-state>&
  nonce=<random-nonce>&
  code_challenge=<pkce-challenge>&
  code_challenge_method=S256&
  provider=github
```

登录完成后，业务应用会在注册的 `redirect_uri` 收到 `code` 和原始 `state`：

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=docs' \
  --data-urlencode 'client_secret=replace-me' \
  --data-urlencode 'redirect_uri=https://docs.example.com/oauth/callback' \
  --data-urlencode 'code=<authorization-code>' \
  --data-urlencode 'code_verifier=<pkce-verifier>'
```

然后使用返回的 Bearer token 请求 `/userinfo`，或将 token 提交到 `/oauth/introspect`。如果返回了 `refresh_token`，客户端可以使用 `grant_type=refresh_token` 换取新 token；每个 refresh token 只允许使用一次，刷新后会返回新的 refresh token。

机密客户端推荐使用 HTTP Basic 认证：

```bash
curl -u docs:replace-me -X POST https://auth.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'refresh_token=<refresh-token>'
```

生产客户端必须自行保存并验证 `state`，并在回调时确认它与发起请求时完全一致。

## 配置说明

最小配置示例：

```yaml
issuer: https://auth.example.com
addr: :8080
cookie_secure: true
redis_addr: 127.0.0.1:6379

providers:
  - name: github
    type: github
    client_id: replace-me
    client_secret: replace-me
  - name: google
    type: google
    client_id: replace-me
    client_secret: replace-me

clients:
  - id: docs
    secret: replace-me
    redirect_uris:
      - https://docs.example.com/oauth/callback
    scopes:
      - openid
      - profile
      - email
    require_pkce: true
    policy: workspace

policies:
  workspace:
    allowed_providers: [github, google]
    email_domains: [example.com]
    github_organization: example-org
    github_team: platform
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `issuer` | 认证中心对外发布的规范化 URL，不要以 `/` 结尾 |
| `addr` | HTTP 监听地址，默认 `:8080` |
| `cookie_secure` | 是否为 Cookie 设置 `Secure` 属性；HTTPS 生产环境应开启 |
| `redis_addr` | Redis 地址；设置为 `memory` 使用内存存储 |
| `providers` | 第三方身份提供商列表，`type` 当前支持 `github`、`google` |
| `clients` | 允许接入的业务应用及精确 redirect URI 白名单 |
| `require_pkce` | 是否强制客户端提供 PKCE 参数，推荐开启 |
| `policy` | 可选的授权策略名称，绑定到 `policies` 中的规则 |

当前策略支持按 provider、邮箱域以及 GitHub organization/team 限制登录。例如上面的 `workspace` 策略只允许 GitHub/Google，要求用户邮箱域为 `example.com`，并要求 GitHub 用户属于 `example-org/platform`。策略在第三方登录回调阶段执行，拒绝的用户不会获得 authorization code。GitHub organization/team 校验需要 OAuth scope `read:org`。

登录成功后，系统会按 `provider + subject` 查找 provider identity。若找不到但 provider 返回了 verified email，则会尝试关联到相同 verified email 的现有用户；否则创建新的统一用户。OIDC `sub` 使用统一用户 ID，provider 原始 subject 仅作为内部 identity 记录。

`signing_key` 可填写 base64 编码的 PKCS#1 RSA 私钥；也可以通过 `signing_keys` 配置 key ring，列表第一把作为 active key，其余旧 key 继续通过 JWKS 发布用于验签。未配置时服务会临时生成密钥，重启后旧 ID Token 将无法验证，因此生产环境必须持久化该字段。`encryption_key` 仍在完善中。

## OIDC 端点

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | OIDC Provider 元数据 |
| `GET` | `/oauth/authorize` | 启动第三方登录和授权码流程 |
| `GET` | `/oauth/callback/{provider}` | 接收 GitHub / Google 回调 |
| `POST` | `/oauth/token` | 使用 authorization code 换取 token |
| `GET` | `/userinfo` | 获取当前 Bearer token 对应的用户资料 |
| `POST` | `/oauth/introspect` | 检查 token 是否有效 |
| `POST` | `/oauth/revoke` | 撤销 access token 或 refresh token |
| `POST` | `/oauth/session/revoke-all` | 撤销当前用户的全部会话 |
| `GET` | `/oauth/jwks` | 发布签名密钥元数据 |
| `GET` | `/oauth/logout` | 注销并跳转到指定地址 |
| `GET` | `/healthz` | 存活检查 |
| `GET` | `/readyz` | 存储就绪检查 |
| `GET` | `/metrics` | Prometheus 指标 |

授权请求通常包含：

```text
client_id
redirect_uri
response_type=code
scope=openid profile email
state
nonce
code_challenge
code_challenge_method=S256
provider=github|google
```

业务应用应校验 `state`，并使用一次性的 `code_verifier` 调用 `/oauth/token`。

## 安全说明

当前 MVP 已实现 redirect URI 白名单、authorization code TTL、一次性 code 消费、PKCE 参数、Redis/内存 token 存储、RS256 ID Token 和基础安全响应头。以下能力仍在完善中：

- refresh token 的跨设备撤销、用户级撤销和 token reuse detection
- 多身份账号关联和完整授权策略执行
- 生产级密钥持久化、轮换和第三方 access token 加密存储

因此，当前版本不应直接作为公网单点登录服务使用。部署到生产前，请至少补充反向代理 TLS、防暴力破解保护、正式 secret 管理、审计日志和完整安全测试。

## 常见问题

### 为什么启动时报 `at least one provider required`？

`providers` 不能为空。至少配置一个 GitHub、Google 或其他已实现的身份提供商，并确认 YAML 缩进正确。

### 为什么 `/readyz` 返回 503？

当 `redis_addr` 不是 `memory` 时，服务会检查 Redis 连通性。确认 Redis 已启动、地址可达，并检查容器网络或防火墙配置。

### 为什么提示 `invalid client or redirect_uri`？

`client_id` 必须存在于 `clients`，且请求中的 `redirect_uri` 必须与配置中的值逐字符匹配，包括协议、端口、路径和尾部斜杠。

### 本地 HTTP 是否可以使用？

可以。开发配置可将 `cookie_secure` 设为 `false` 并使用 `http://localhost`；生产环境必须使用 HTTPS，并将其设为 `true`。

### 配置里的 `${GITHUB_CLIENT_ID}` 会自动读取环境变量吗？

不会。配置加载器当前读取原始 YAML，不执行环境变量模板替换。请在启动前生成实际配置文件，或后续接入外部 secret/config 渲染工具。

## 路线图

- [x] 基础 OIDC ID Token（JWT）签发、JWKS 发布和 claims 映射
- [x] Google OIDC discovery、JWKS、nonce 和 `email_verified` 校验（仍需补充更多集成测试）
- [x] refresh token 基础轮换和 HTTP Basic client authentication
- [x] OAuth token 撤销端点
- [x] refresh token family 和 reuse detection
- [x] provider / 邮箱域策略接入登录流程
- [x] 统一用户模型和 verified email 账号关联
- [x] 用户级全部会话撤销 API
- [x] signing key key ring 和旧 key JWKS 兼容
- [x] GitHub organization / team 授权策略
- [x] 多身份显式关联、解绑和冲突处理基础 API
- [x] CLI 配置校验和 signing key 生成
- [x] systemd 和 Kubernetes 基础部署示例
- [x] Nginx 反向代理基础部署示例
- [ ] Ingress 完整部署示例
- [x] 基础 CI、race、vet、构建和覆盖率产物
- [ ] 安全扫描和正式版本发布流程

## 开发与验证

格式化、单元测试和静态检查：

```bash
gofmt -w config provider policy server store identity cmd
go test ./...
go test -race ./...
go vet ./...
```

构建服务：

```bash
go build -trimpath -o bin/authd ./cmd/authd
go build -trimpath -o bin/authctl ./cmd/authctl
```

CLI 管理工具：

```bash
./bin/authctl validate-config config.local.yaml
./bin/authctl generate-key
```

`generate-key` 输出 base64 编码的 PKCS#1 RSA 私钥，可保存到 `signing_key` 或 `signing_keys` 配置中。生产环境应通过 Secret Manager 或 Kubernetes Secret 管理该值。

## 发布

推送 `v*` tag 会自动执行发布工作流：

```bash
git tag v0.1.0-beta.1
git push origin v0.1.0-beta.1
```

GitHub Actions 会：

- 使用 GoReleaser 构建 `authd` 和 `authctl`
- 生成 Linux、macOS、Windows 的 amd64/arm64 二进制归档
- 生成 `checksums.txt`
- 创建 GitHub Release
- 构建并推送 `linux/amd64`、`linux/arm64` 镜像到 `ghcr.io/<owner>/<repo>`
- 发布版本、major/minor、`latest` 等镜像 tag

对应配置位于 `.goreleaser.yaml`、`.github/workflows/release.yml` 和 `Dockerfile`。工作流使用仓库内置 `GITHUB_TOKEN`，不需要额外的发布 secret。

## 贡献指南

欢迎提交 Issue、文档改进和 Pull Request。提交代码前请：

1. 为新行为补充测试。
2. 运行 `go test ./...`、`go test -race ./...` 和 `go vet ./...`。
3. 不提交 OAuth secret、Redis 凭据、私钥或真实用户数据。
4. 在 PR 描述中说明协议兼容性、安全影响和部署影响。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源。除非另有说明，项目代码和文档均按照该许可证发布。
