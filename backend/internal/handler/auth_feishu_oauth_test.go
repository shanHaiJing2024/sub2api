package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/ent/authidentity"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestFeishuUserInfo(t *testing.T) {
	cfg := config.OIDCConnectConfig{UserInfoURL: "https://open.feishu.cn/open-apis/authen/v1/user_info"}
	claims, err := parseOIDCProviderUserInfo(`{"code":0,"data":{"open_id":"ou_member","name":"Member","enterprise_email":"member@qcraft.ai","email":"personal@example.com","avatar_url":"https://example.com/avatar.png"}}`, cfg)
	require.NoError(t, err)
	require.Equal(t, "ou_member", claims.Subject)
	require.Equal(t, "member@qcraft.ai", claims.Email)
	require.Equal(t, "Member", claims.DisplayName)
	require.Nil(t, claims.EmailVerified)
	for _, body := range []string{
		`{"code":20005,"data":{"open_id":"ou_member"}}`,
		`{"data":{"open_id":"ou_member"}}`,
		`{"code":0,"data":{}}`,
		`{"code":"0","data":{"open_id":"ou_member"}}`,
		`{"code":0.1,"data":{"open_id":"ou_member"}}`,
		`not-json`,
	} {
		_, err := parseOIDCProviderUserInfo(body, cfg)
		require.Error(t, err)
	}
}

func TestFeishuEndpointAndGenericOIDC(t *testing.T) {
	for _, raw := range []string{"http://open.feishu.cn/open-apis/authen/v1/user_info", "https://open.feishu.cn.evil.test/open-apis/authen/v1/user_info", "https://open.feishu.cn/unrelated"} {
		require.False(t, isFeishuUserInfoURL(raw))
	}
	claims, err := parseOIDCProviderUserInfo(`{"sub":"original","email":"member@example.com"}`, config.OIDCConnectConfig{UserInfoURL: "https://idp.example.com/userinfo"})
	require.NoError(t, err)
	require.Equal(t, "original", claims.Subject)
}

func TestFeishuTokenExchangeJSONAndPKCE(t *testing.T) {
	for _, tc := range []struct {
		name      string
		response  string
		wantError bool
	}{
		{"flat", `{"access_token":"test-token","token_type":"Bearer","expires_in":7200}`, false},
		{"nested", `{"code":0,"data":{"access_token":"test-token","expires_in":7200}}`, false},
		{"business error", `{"code":20049,"msg":"PKCE code challenge failed","data":{"access_token":"untrusted"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Contains(t, r.Header.Get("Content-Type"), "application/json")
				var payload map[string]string
				require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
				require.Equal(t, "authorization_code", payload["grant_type"])
				require.Equal(t, "test-client", payload["client_id"])
				require.Equal(t, "test-secret", payload["client_secret"])
				require.Equal(t, "test-code", payload["code"])
				require.Equal(t, "http://localhost/callback", payload["redirect_uri"])
				require.Equal(t, "test-verifier", payload["code_verifier"])
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			cfg := config.OIDCConnectConfig{
				TokenURL:    server.URL,
				UserInfoURL: "https://open.feishu.cn/open-apis/authen/v1/user_info",
				ClientID:    "test-client", ClientSecret: "test-secret",
				TokenAuthMethod: "client_secret_post", UsePKCE: true,
			}
			token, err := oidcExchangeCode(context.Background(), cfg, "test-code", "http://localhost/callback", "test-verifier")
			if tc.wantError {
				require.Error(t, err)
				require.Nil(t, token)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "test-token", token.AccessToken)
			require.EqualValues(t, 7200, token.ExpiresIn)
		})
	}
}

func TestFeishuAutomaticSignupUsesEnterpriseEmail(t *testing.T) {
	handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{settingValues: map[string]string{service.SettingKeyRegistrationEnabled: "false"}})
	t.Cleanup(func() { _ = client.Close() })
	// Production-like policy: public registration is disabled, enterprise login remains available.
	require.False(t, handler.settingSvc.IsRegistrationEnabled(context.Background()))
	identity := service.PendingAuthIdentityKey{ProviderType: "oidc", ProviderKey: "https://accounts.feishu.cn", ProviderSubject: "ou_auto_member"}
	email := oidcSyntheticEmailFromIdentityKey(oidcIdentityKey(identity.ProviderKey, identity.ProviderSubject))
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/oidc/callback", nil)
		handler.continueFeishuOAuthLogin(c, "/auth/oidc/callback", "/dashboard", "browser-key", identity, "飞书用户", map[string]any{"email": email, "compat_email": "existing@example.com"})
		require.Equal(t, "/auth/oidc/callback", recorder.Header().Get("Location"))
		require.NotContains(t, recorder.Header().Get("Location"), "access_token=")
	}
	// Closing public registration must continue to block ordinary OIDC signup.
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/oidc/callback", nil)
	require.False(t, handler.tryOIDCVerifiedEmailFastPath(c, "/auth/oidc/callback", "/dashboard", service.PendingAuthIdentityKey{ProviderType: "oidc", ProviderKey: "https://other.example.com", ProviderSubject: "ordinary-user"}, "ordinary@example.com", "ordinary", nil))
	require.NotContains(t, recorder.Header().Get("Location"), "access_token=")
	count, err := client.User.Query().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, count)
	user, err := client.User.Query().Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, "existing@example.com", user.Email)
	count, err = client.AuthIdentity.Query().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, count)
	count, err = client.PendingAuthSession.Query().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, count)
}

func TestFeishuLoginUpgradesLegacySyntheticEmail(t *testing.T) {
	handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{settingValues: map[string]string{service.SettingKeyRegistrationEnabled: "false"}})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	identity := service.PendingAuthIdentityKey{ProviderType: "oidc", ProviderKey: "https://accounts.feishu.cn", ProviderSubject: "ou_legacy_member"}
	syntheticEmail := oidcSyntheticEmailFromIdentityKey(oidcIdentityKey(identity.ProviderKey, identity.ProviderSubject))
	legacy, err := client.User.Create().SetEmail(syntheticEmail).SetUsername("legacy-feishu").SetPasswordHash("hash").SetRole(service.RoleUser).SetStatus(service.StatusActive).Save(ctx)
	require.NoError(t, err)
	_, err = client.AuthIdentity.Create().SetUserID(legacy.ID).SetProviderType("oidc").SetProviderKey(identity.ProviderKey).SetProviderSubject(identity.ProviderSubject).Save(ctx)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/callback", nil)
	handler.continueFeishuOAuthLogin(c, "/auth/oidc/callback", "/dashboard", "browser-key", identity, "飞书用户", map[string]any{
		"email": syntheticEmail, "compat_email": "yunhao@qcraft.ai",
	})
	require.Equal(t, "/auth/oidc/callback", recorder.Header().Get("Location"))
	require.NotContains(t, recorder.Header().Get("Location"), "access_token=")
	stored, err := client.User.Get(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, "yunhao@qcraft.ai", stored.Email)
	emailIdentity, err := client.AuthIdentity.Query().Where(authidentity.ProviderTypeEQ("email"), authidentity.ProviderSubjectEQ("yunhao@qcraft.ai")).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, legacy.ID, emailIdentity.UserID)
}

func TestFeishuAutomaticallyLinksExistingEmailAccount(t *testing.T) {
	handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{settingValues: map[string]string{service.SettingKeyRegistrationEnabled: "false"}})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	existing, err := client.User.Create().SetEmail("member@qcraft.ai").SetUsername("existing-user").SetPasswordHash("original-hash").SetRole(service.RoleUser).SetStatus(service.StatusActive).Save(ctx)
	require.NoError(t, err)
	identity := service.PendingAuthIdentityKey{ProviderType: "oidc", ProviderKey: "https://accounts.feishu.cn", ProviderSubject: "ou_existing"}
	for i := 0; i < 2; i++ {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodGet, "/callback", nil)
		handler.continueFeishuOAuthLogin(c, "/auth/oidc/callback", "/dashboard", "browser-key", identity, "飞书用户", map[string]any{
			"compat_email":         " MEMBER@qcraft.ai ",
			"suggested_avatar_url": "https://cdn.example/feishu-existing.png",
		})
		require.Equal(t, "/auth/oidc/callback", recorder.Header().Get("Location"))
		require.NotContains(t, recorder.Header().Get("Location"), "access_token=")
	}
	count, err := client.User.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	bound, err := client.AuthIdentity.Query().Where(authidentity.ProviderTypeEQ("oidc"), authidentity.ProviderSubjectEQ("ou_existing")).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, existing.ID, bound.UserID)
	stored, err := client.User.Get(ctx, existing.ID)
	require.NoError(t, err)
	require.Equal(t, "original-hash", stored.PasswordHash)
	require.Equal(t, "existing-user", stored.Username)
	avatar := loadUserAvatarRecord(t, client, existing.ID)
	require.NotNil(t, avatar)
	require.Equal(t, "remote_url", avatar.StorageProvider)
	require.Equal(t, "https://cdn.example/feishu-existing.png", avatar.URL)
}

func TestFeishuAvatarBackfillsExistingIdentityWithoutOverwrite(t *testing.T) {
	handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	user, err := client.User.Create().SetEmail("bound@qcraft.ai").SetUsername("bound-user").SetPasswordHash("hash").SetRole(service.RoleUser).SetStatus(service.StatusActive).Save(ctx)
	require.NoError(t, err)

	handler.adoptFeishuAvatarWhenMissing(ctx, user.ID, "https://cdn.example/first.png")
	avatar := loadUserAvatarRecord(t, client, user.ID)
	require.NotNil(t, avatar)
	require.Equal(t, "remote_url", avatar.StorageProvider)
	require.Equal(t, "https://cdn.example/first.png", avatar.URL)

	// A later Feishu login must not replace an avatar the user already has.
	handler.adoptFeishuAvatarWhenMissing(ctx, user.ID, "https://cdn.example/later.png")
	avatar = loadUserAvatarRecord(t, client, user.ID)
	require.NotNil(t, avatar)
	require.Equal(t, "https://cdn.example/first.png", avatar.URL)
}

func TestFeishuUnbindClearsProviderAvatar(t *testing.T) {
	handler, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	user, err := client.User.Create().SetEmail("unbind@qcraft.ai").SetUsername("unbind-user").SetPasswordHash("hash").SetRole(service.RoleUser).SetStatus(service.StatusActive).Save(ctx)
	require.NoError(t, err)
	_, err = client.AuthIdentity.Create().
		SetUserID(user.ID).
		SetProviderType("email").
		SetProviderKey("email").
		SetProviderSubject(user.Email).
		Save(ctx)
	require.NoError(t, err)
	_, err = client.AuthIdentity.Create().
		SetUserID(user.ID).
		SetProviderType("oidc").
		SetProviderKey("https://accounts.feishu.cn").
		SetProviderSubject("ou_unbind").
		SetMetadata(map[string]any{"avatar_url": "https://cdn.example/feishu-unbind.png"}).
		Save(ctx)
	require.NoError(t, err)
	_, err = handler.userService.SetAvatar(ctx, user.ID, "https://cdn.example/feishu-unbind.png")
	require.NoError(t, err)

	_, unbound, err := handler.userService.UnbindUserAuthProviderWithResult(ctx, user.ID, "oidc")
	require.NoError(t, err)
	require.True(t, unbound)
	require.Nil(t, loadUserAvatarRecord(t, client, user.ID))
	count, err := client.AuthIdentity.Query().Where(authidentity.UserIDEQ(user.ID), authidentity.ProviderTypeEQ("oidc")).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, count)
}

func TestFeishuExistingBindingSurvivesProviderEmailChange(t *testing.T) {
	h, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	u, err := client.User.Create().SetEmail("original@example.com").SetPasswordHash("original-password").SetRole(service.RoleUser).SetStatus(service.StatusActive).Save(ctx)
	require.NoError(t, err)
	_, err = client.AuthIdentity.Create().SetUserID(u.ID).SetProviderType("oidc").SetProviderKey("https://accounts.feishu.cn").SetProviderSubject("ou_bound").Save(ctx)
	require.NoError(t, err)
	resolved, err := h.authService.ResolveFeishuIdentity(ctx, service.EmailOAuthIdentityInput{ProviderType: "oidc", ProviderKey: "https://accounts.feishu.cn", ProviderSubject: "ou_bound", Email: "changed@example.com"}, "")
	require.NoError(t, err)
	require.Equal(t, u.ID, resolved.ID)
	require.Equal(t, u.Email, resolved.Email)
}

func TestFeishuSignupPoliciesAndMissingEmail(t *testing.T) {
	for _, tc := range []struct {
		name        string
		settings    map[string]string
		invitation  bool
		wantSuccess bool
	}{
		{name: "missing email", wantSuccess: true},
		{name: "public signup closed", settings: map[string]string{service.SettingKeyRegistrationEnabled: "false"}, wantSuccess: true},
		{name: "invitation required", invitation: true},
		{name: "backend mode", settings: map[string]string{service.SettingKeyBackendModeEnabled: "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{settingValues: tc.settings, invitationEnabled: tc.invitation})
			t.Cleanup(func() { _ = client.Close() })
			r := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(r)
			c.Request = httptest.NewRequest(http.MethodGet, "/callback", nil)
			h.continueFeishuOAuthLogin(c, "/auth/oidc/callback", "/dashboard", "browser", service.PendingAuthIdentityKey{ProviderType: "oidc", ProviderKey: "https://accounts.feishu.cn", ProviderSubject: "ou_missing_email"}, "Member", map[string]any{})
			count, err := client.User.Query().Count(context.Background())
			require.NoError(t, err)
			if tc.wantSuccess {
				require.EqualValues(t, 1, count)
				u, err := client.User.Query().Only(context.Background())
				require.NoError(t, err)
				require.Contains(t, u.Email, service.OIDCConnectSyntheticEmailDomain)
				require.Equal(t, "/auth/oidc/callback", r.Header().Get("Location"))
			} else {
				require.Zero(t, count)
				require.Contains(t, r.Header().Get("Location"), "error=")
			}
		})
	}
}

func TestFeishuAutomaticLoginRequiresExistingTwoFactor(t *testing.T) {
	cache := &oauthPendingFlowTotpCacheStub{}
	h, client := newOAuthPendingFlowTestHandlerWithDependencies(t, oauthPendingFlowTestHandlerOptions{
		settingValues: map[string]string{service.SettingKeyTotpEnabled: "true"}, totpCache: cache, totpEncryptor: oauthPendingFlowTotpEncryptorStub{},
	})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	u, err := client.User.Create().SetEmail("totp@example.com").SetPasswordHash("original-password").SetRole(service.RoleUser).SetStatus(service.StatusActive).SetTotpEnabled(true).Save(ctx)
	require.NoError(t, err)
	r := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(r)
	c.Request = httptest.NewRequest(http.MethodGet, "/callback", nil)
	h.continueFeishuOAuthLogin(c, "/auth/oidc/callback", "/dashboard", "browser", service.PendingAuthIdentityKey{ProviderType: "oidc", ProviderKey: "https://accounts.feishu.cn", ProviderSubject: "ou_totp"}, "Member", map[string]any{"compat_email": u.Email})
	require.Equal(t, "/auth/oidc/callback", r.Header().Get("Location"))
	session, err := client.PendingAuthSession.Query().Only(ctx)
	require.NoError(t, err)
	r = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(r)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/oidc/complete", nil)
	c.Request.AddCookie(&http.Cookie{Name: oauthPendingSessionCookieName, Value: encodeCookieValue(session.SessionToken)})
	c.Request.AddCookie(&http.Cookie{Name: oauthPendingBrowserCookieName, Value: encodeCookieValue("browser")})
	h.ExchangePendingOAuthCompletion(c)
	require.Equal(t, http.StatusOK, r.Code)
	data := decodeJSONResponseData(t, r)
	require.Equal(t, true, data["requires_2fa"])
	require.NotEmpty(t, data["temp_token"])
	require.NotContains(t, data, "access_token")
}
