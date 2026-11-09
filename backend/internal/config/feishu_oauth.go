package config

import (
	"net/url"
	"strings"
)

// IsFeishuOAuthEndpoints identifies the official Feishu OAuth flow, which does
// not issue an OIDC id_token or use the openid scope. Other OIDC providers keep
// their existing scope and ID-token validation requirements.
func IsFeishuOAuthEndpoints(authorize, token, userinfo string) bool {
	return isExactFeishuEndpoint(authorize, "accounts.feishu.cn", "/open-apis/authen/v1/authorize") &&
		(isExactFeishuEndpoint(token, "accounts.feishu.cn", "/oauth/v3/token") ||
			isExactFeishuEndpoint(token, "open.feishu.cn", "/open-apis/authen/v2/oauth/token")) &&
		isExactFeishuEndpoint(userinfo, "open.feishu.cn", "/open-apis/authen/v1/user_info")
}

func isExactFeishuEndpoint(raw, host, path string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Host, host) && u.Path == path &&
		u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
