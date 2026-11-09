# 飞书登录

飞书企业自建应用的 OAuth 2.0 登录复用现有 `oidc_connect` 配置、登录按钮和回调路径。其他登录方式继续按各自配置工作。

在飞书应用中启用网页登录能力，将应用可用范围限制为预期成员，并登记完整回调地址。申请基本信息和邮箱读取权限，例如 `contact:user.base:readonly`、`contact:user.email:readonly`；实际权限以飞书控制台和返回字段为准。配置名称为“飞书”或“Feishu”，登录页会显示企业邮箱匹配说明。

通过管理后台 OIDC 设置或服务配置启用连接。以下为配置示例；将域名、App ID 和 Secret 替换为本环境的值，凭证不要提交到仓库：

```yaml
oidc_connect:
  enabled: true
  provider_name: 飞书
  client_id: YOUR_APP_ID
  client_secret: YOUR_APP_SECRET
  issuer_url: https://accounts.feishu.cn
  authorize_url: https://accounts.feishu.cn/open-apis/authen/v1/authorize
  token_url: https://open.feishu.cn/open-apis/authen/v2/oauth/token
  userinfo_url: https://open.feishu.cn/open-apis/authen/v1/user_info
  scopes: contact:user.base:readonly contact:user.email:readonly
  redirect_url: https://YOUR_DOMAIN/api/v1/auth/oauth/oidc/callback
  frontend_redirect_url: https://YOUR_DOMAIN/auth/oidc/callback
  token_auth_method: client_secret_post
  use_pkce: true
  validate_id_token: false
  require_email_verified: false
```

飞书使用 JSON 请求换取访问令牌，用户信息位于响应的 `data` 中，不提供标准 OIDC 的 `openid` scope、ID Token 或 `email_verified`。只有完整匹配官方飞书端点时才启用自动邮箱匹配策略及 scope 例外，普通 OIDC 保持原有要求。兼容 `https://accounts.feishu.cn/oauth/v3/token`，默认示例使用与来源项目相同的 v2 端点并保留 S256 PKCE。

登录规则：

- 以 `issuer + open_id` 标识飞书身份，优先使用 `enterprise_email`，缺失时使用个人 `email`。
- 首次登录匹配已有同邮箱账号并绑定，保留原密码、名称和数据；没有匹配则自动创建账号。公开注册关闭不影响飞书自动建号，邀请码要求和后台模式限制仍生效。
- 飞书没有提供有效邮箱时，使用稳定的内部占位邮箱；之后返回真实邮箱且无其他账号占用时，升级该账号并自动绑定邮箱。
- 历史占位邮箱账号匹配已有真实邮箱账号时，事务合并余额、密钥、用量和相关资源到真实邮箱账号。保留主账号密码，归档来源账号并记录合并审计；重复回调不会重复转移余额。来源账号配置了 TOTP 或 Passkey 时拒绝自动合并。
- 已绑定真实邮箱账号的飞书身份保持原绑定，不因后续飞书邮箱变化而转移到另一账号。
- 头像仅在本地为空时自动补齐；解绑身份只清理明确属于该身份的远程头像，保留自定义头像。
- 使用现有浏览器绑定的 OAuth 待完成会话换取本站令牌；开启 TOTP 的账号继续要求二次验证。飞书访问令牌不会传给前端。

新建飞书账号的随机内部密码不可用于邮箱登录；需要邮箱密码登录时，可使用现有密码重置流程。个人页中，飞书已绑定的真实邮箱无需再次走手动邮箱验证码绑定。

迁移 `249_feishu_account_merge.sql` 在应用正常升级时自动执行，不会在启动时批量合并用户；合并仅由成功的飞书登录触发。数据库回归测试可在已应用全部迁移的隔离测试数据库中运行：

```bash
psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -f backend/migrations/testdata/feishu_account_merge.sql
```

上线前仍需在目标环境配置真实飞书应用凭证和回调白名单，并完成一次真实授权验证；模拟接口测试不等于真实联调。
