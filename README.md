# CloudOTP

由 Cloudflare Workers 和 D1 驱动的 TOTP/2FA 共享看板。管理员保存获授权账号的 Base32 密钥后，系统自动生成六位验证码和独立分享链接；使用者只需打开链接即可查看当前验证码。

> 仅用于你有权管理的共享账号或服务账号。分享链接本身属于敏感凭据，请勿公开传播。

## 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Time999-1/CloudOTP)

点击按钮后，Cloudflare 会引导你：

1. 复制仓库并创建 Worker。
2. 创建并绑定 D1 数据库。
3. 配置三个必需的加密参数。
4. 构建并发布应用。

部署表单会要求配置三个敏感值：

- `ADMIN_PASSWORD`：管理员初始密码，至少 12 个字符。
- `SESSION_SECRET`：会话签名密钥，建议使用 `openssl rand -hex 32` 生成。
- `APP_ENCRYPTION_KEY`：TOTP 加密密钥，也应独立随机生成并离线备份。部署后不要修改，否则现有 TOTP 密钥将无法解密。

部署完成后访问 Cloudflare 提供的 `workers.dev` 地址，管理员账号固定为 `admin`。

首次部署后请访问 `/health` 检查 Worker。若登录页提示数据表不存在，请在仓库的 Cloudflare 构建命令中加入 `npx wrangler d1 migrations apply DB --remote`，或在本地登录 Wrangler 后运行 `npm run db:migrations:apply`。Cloudflare 部署界面的自动迁移行为可能随项目导入方式变化，因此不要在未验证数据表前直接录入正式密钥。

## 功能

- 管理员登录与 CSRF 防护
- 会员、账号、分类、到期日和备注管理
- 六位 TOTP 验证码与 30 秒倒计时
- 每个会员独立、可停用、可重置的分享链接
- 名称、编号、账号搜索与分类筛选
- 分享页访问日志
- 响应式日间、夜间与跟随系统界面
- Web Crypto AES-GCM 加密保存 TOTP 密钥
- Cloudflare Workers + D1，无需服务器或容器

## 本地开发

需要 Node.js 20 或更高版本：

```bash
npm install
cp .dev.vars.example .dev.vars
# 编辑 .dev.vars，替换全部占位值
npm run dev
```

运行测试：

```bash
npm test
```

命令行部署：

```bash
npx wrangler login
npm run deploy
```

`npm run deploy` 会先发布 Worker 并自动配置 D1，然后执行远程数据库迁移。

## 数据备份

必须同时保存 D1 数据和 `APP_ENCRYPTION_KEY`。只有数据库而没有原加密密钥时，保存的 TOTP 密钥无法恢复。

## 安全说明

- TOTP 原始密钥只在 Worker 内解密，浏览器端不会取得原始密钥。
- 分享令牌只以 SHA-256 摘要检索，展示所需的令牌副本使用 AES-GCM 加密。
- 管理会话使用 `HttpOnly`、`Secure`、`SameSite=Lax` Cookie，并在 12 小时后失效。
- 分享链接泄露后应立即在管理页重置。
