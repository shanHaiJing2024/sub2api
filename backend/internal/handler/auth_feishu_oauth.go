package handler

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// Feishu uses OAuth 2.0 rather than OIDC ID tokens. Its user-info endpoint
// returns a business status and nested identity fields; never trust a failed envelope.
func isFeishuUserInfoURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Host, "open.feishu.cn") &&
		u.Path == "/open-apis/authen/v1/user_info" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func parseOIDCProviderUserInfo(body string, cfg config.OIDCConnectConfig) (*oidcUserInfoClaims, error) {
	if !isFeishuUserInfoURL(cfg.UserInfoURL) {
		return oidcParseUserInfo(body, cfg), nil
	}
	code := gjson.Get(body, "code")
	if !gjson.Valid(body) || code.Type != gjson.Number || code.Num != 0 {
		return nil, fmt.Errorf("feishu userinfo request was rejected")
	}
	subject := strings.TrimSpace(gjson.Get(body, "data.open_id").String())
	if subject == "" {
		return nil, fmt.Errorf("feishu userinfo missing open_id")
	}
	claims := &oidcUserInfoClaims{
		Subject:     subject,
		Email:       firstNonEmpty(gjson.Get(body, "data.enterprise_email").String(), gjson.Get(body, "data.email").String()),
		Username:    strings.TrimSpace(gjson.Get(body, "data.name").String()),
		DisplayName: strings.TrimSpace(gjson.Get(body, "data.name").String()),
		AvatarURL:   strings.TrimSpace(gjson.Get(body, "data.avatar_url").String()),
	}
	// Feishu does not return email_verified. Only the official Feishu flow
	// may apply the enterprise email matching policy; generic OIDC stays unchanged.
	return claims, nil
}

// continueFeishuOAuthLogin resolves the enterprise identity, then uses the
// browser-bound pending login flow instead of putting tokens in the redirect.
func (h *AuthHandler) continueFeishuOAuthLogin(c *gin.Context, frontendCallback, redirectTo, browserSessionKey string, identity service.PendingAuthIdentityKey, username string, claims map[string]any) {
	ctx := c.Request.Context()
	claims["feishu_login"] = "true"
	// Backend-only deployments must reject a prospective signup before any
	// user or identity is created. Existing admins can still log in.
	existing, err := h.findOAuthIdentityUser(ctx, identity)
	if err == nil && existing == nil {
		existing, err = h.findOIDCCompatEmailUser(ctx, pendingSessionStringValue(claims, "compat_email"))
	}
	if err == nil {
		if existing != nil {
			var existingUser *service.User
			existingUser, err = h.userService.GetByID(ctx, existing.ID)
			if err == nil {
				err = h.ensureBackendModeAllowsUser(ctx, existingUser)
			}
		} else {
			err = h.ensureBackendModeAllowsNewUserLogin(ctx)
		}
	}
	if err != nil {
		redirectOAuthError(c, frontendCallback, "login_blocked", infraerrors.Reason(err), infraerrors.Message(err))
		return
	}
	resolved, err := h.authService.ResolveFeishuIdentity(ctx, service.EmailOAuthIdentityInput{
		ProviderType: identity.ProviderType, ProviderKey: identity.ProviderKey, ProviderSubject: identity.ProviderSubject,
		Email: pendingSessionStringValue(claims, "compat_email"), Username: username,
		DisplayName: pendingSessionStringValue(claims, "suggested_display_name"),
		AvatarURL:   pendingSessionStringValue(claims, "suggested_avatar_url"), UpstreamMetadata: claims,
	}, readOAuthPromoCode(c))
	if err != nil {
		redirectOAuthError(c, frontendCallback, "registration_failed", infraerrors.Reason(err), infraerrors.Message(err))
		return
	}
	if existing != nil && existing.ID != resolved.ID {
		h.userService.InvalidateAccountMergeCaches(ctx, existing.ID, resolved.ID)
	}
	h.adoptFeishuAvatarWhenMissing(ctx, resolved.ID, pendingSessionStringValue(claims, "suggested_avatar_url"))
	if err := h.createOAuthPendingSession(c, oauthPendingSessionPayload{
		Intent: oauthIntentLogin, Identity: identity, TargetUserID: &resolved.ID,
		ResolvedEmail: resolved.Email, RedirectTo: redirectTo, BrowserSessionKey: browserSessionKey,
		UpstreamIdentityClaims: claims, CompletionResponse: map[string]any{"redirect": redirectTo},
	}); err != nil {
		redirectOAuthError(c, frontendCallback, "session_error", infraerrors.Reason(err), infraerrors.Message(err))
		return
	}
	redirectToFrontendCallback(c, frontendCallback)
}
