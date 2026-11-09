package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeishuOAuthEndpoints(t *testing.T) {
	a := "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	token := "https://accounts.feishu.cn/oauth/v3/token"
	info := "https://open.feishu.cn/open-apis/authen/v1/user_info"
	require.True(t, IsFeishuOAuthEndpoints(a, token, info))
	v2 := "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	require.True(t, IsFeishuOAuthEndpoints(a, v2, info))
	require.False(t, IsFeishuOAuthEndpoints(a, v2+"?forward=other", info))
	require.False(t, IsFeishuOAuthEndpoints(a, strings.Replace(v2, "open.feishu.cn", "open.feishu.cn.evil.test", 1), info))
	require.False(t, IsFeishuOAuthEndpoints(strings.Replace(a, "https:", "http:", 1), token, info))
	require.False(t, IsFeishuOAuthEndpoints(a, strings.Replace(token, "accounts.feishu.cn", "accounts.feishu.cn.evil.test", 1), info))
	require.False(t, IsFeishuOAuthEndpoints(a, token, info+"?forward=other"))
}

func TestFeishuOAuthConfigWithoutOpenIDScope(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	cfg.OIDC = OIDCConnectConfig{
		Enabled:             true,
		ProviderName:        "飞书",
		ClientID:            "cli_qaipool",
		ClientSecret:        "test-secret",
		IssuerURL:           "https://accounts.feishu.cn",
		AuthorizeURL:        "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		TokenURL:            "https://accounts.feishu.cn/oauth/v3/token",
		UserInfoURL:         "https://open.feishu.cn/open-apis/authen/v1/user_info",
		Scopes:              "contact:user.base:readonly",
		RedirectURL:         "https://qaipool.example.com/api/v1/auth/oauth/oidc/callback",
		FrontendRedirectURL: "/auth/oidc/callback",
		TokenAuthMethod:     "client_secret_post",
		UsePKCE:             true,
		ValidateIDToken:     false,
	}
	require.NoError(t, cfg.Validate())
	cfg.OIDC.TokenURL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	require.NoError(t, cfg.Validate())
	cfg.OIDC.TokenURL = "https://other.example.com/token"
	require.ErrorContains(t, cfg.Validate(), "scopes")
}
