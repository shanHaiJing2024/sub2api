package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/authidentity"
	"github.com/Wei-Shaw/sub2api/ent/user"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

type EmailOAuthIdentityInput struct {
	ProviderType     string
	ProviderKey      string
	ProviderSubject  string
	Email            string
	EmailVerified    bool
	Username         string
	DisplayName      string
	AvatarURL        string
	UpstreamMetadata map[string]any
}

func (s *AuthService) LoginOrRegisterVerifiedEmailOAuth(ctx context.Context, input EmailOAuthIdentityInput) (*TokenPair, *User, error) {
	return s.loginOrRegisterVerifiedEmailOAuth(ctx, input, "", "", "")
}

func (s *AuthService) LoginOrRegisterVerifiedEmailOAuthWithInvitation(
	ctx context.Context,
	input EmailOAuthIdentityInput,
	invitationCode string,
	affiliateCode string,
) (*TokenPair, *User, error) {
	return s.loginOrRegisterVerifiedEmailOAuth(ctx, input, invitationCode, affiliateCode, "")
}

func (s *AuthService) LoginOrRegisterVerifiedEmailOAuthWithSignupCodes(
	ctx context.Context,
	input EmailOAuthIdentityInput,
	invitationCode string,
	affiliateCode string,
	promoCode string,
) (*TokenPair, *User, error) {
	return s.loginOrRegisterVerifiedEmailOAuth(ctx, input, invitationCode, affiliateCode, promoCode)
}

func (s *AuthService) loginOrRegisterVerifiedEmailOAuth(
	ctx context.Context,
	input EmailOAuthIdentityInput,
	invitationCode string,
	affiliateCode string,
	promoCode string,
) (*TokenPair, *User, error) {
	return s.loginOrRegisterEmailOAuthIdentity(ctx, input, invitationCode, affiliateCode, promoCode, false, true)
}

// ResolveFeishuIdentity trusts the enterprise email returned by Feishu,
// links an existing account with that email, and uses it directly for signup.
// The synthetic address is retained only as a fallback when Feishu returns no
// usable email.
func (s *AuthService) ResolveFeishuIdentity(ctx context.Context, input EmailOAuthIdentityInput, promoCode string) (*User, error) {
	if input.ProviderType != "oidc" || strings.TrimSpace(input.ProviderSubject) == "" {
		return nil, infraerrors.BadRequest("OAUTH_SUBJECT_MISSING", "invalid Feishu identity")
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(input.ProviderKey)) + "\x1f" + strings.TrimSpace(input.ProviderSubject)))
	providerEmail := strings.ToLower(strings.TrimSpace(input.Email))
	input.Email = "oidc-" + hex.EncodeToString(sum[:16]) + OIDCConnectSyntheticEmailDomain
	if providerEmail != "" && !isReservedEmail(providerEmail) {
		if parsed, err := mail.ParseAddress(providerEmail); err == nil && parsed.Address == providerEmail && len(providerEmail) <= 255 {
			input.Email = providerEmail
			input.EmailVerified = true
		}
	}
	_, resolved, err := s.loginOrRegisterEmailOAuthIdentity(ctx, input, "", "", promoCode, true, false)
	return resolved, err
}

func (s *AuthService) loginOrRegisterEmailOAuthIdentity(ctx context.Context, input EmailOAuthIdentityInput, invitationCode, affiliateCode, promoCode string, authenticatedFeishu, issueTokens bool) (*TokenPair, *User, error) {
	if s == nil || s.userRepo == nil || s.entClient == nil {
		return nil, nil, ErrServiceUnavailable
	}

	providerType := normalizeOAuthSignupSource(input.ProviderType)
	if providerType != "github" && providerType != "google" && providerType != "oidc" {
		return nil, nil, infraerrors.BadRequest("OAUTH_PROVIDER_INVALID", "oauth provider is invalid")
	}
	providerKey := strings.TrimSpace(input.ProviderKey)
	if providerKey == "" {
		providerKey = providerType
	}
	providerSubject := strings.TrimSpace(input.ProviderSubject)
	if providerSubject == "" {
		return nil, nil, infraerrors.BadRequest("OAUTH_SUBJECT_MISSING", "oauth subject is missing")
	}
	if !authenticatedFeishu && !input.EmailVerified {
		return nil, nil, infraerrors.Forbidden("OAUTH_EMAIL_NOT_VERIFIED", "oauth email is not verified")
	}

	email := strings.TrimSpace(strings.ToLower(input.Email))
	if email == "" || len(email) > 255 {
		return nil, nil, infraerrors.BadRequest("INVALID_EMAIL", "invalid email")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, nil, infraerrors.BadRequest("INVALID_EMAIL", "invalid email")
	}
	if !authenticatedFeishu && isReservedEmail(email) {
		return nil, nil, ErrEmailReserved
	}
	if !authenticatedFeishu {
		if err := s.validateRegistrationEmailPolicy(ctx, email); err != nil {
			return nil, nil, err
		}
	}

	identityUser, err := s.findEmailOAuthIdentityOwner(ctx, providerType, providerKey, providerSubject)
	if err != nil {
		return nil, nil, err
	}
	if identityUser != nil && !identityUser.IsActive() {
		return nil, nil, ErrUserNotActive
	}
	if identityUser != nil && authenticatedFeishu {
		// Existing real-email bindings remain authoritative even if Feishu's
		// profile email changes. Only legacy synthetic accounts can be upgraded.
		if !strings.HasSuffix(strings.ToLower(identityUser.Email), OIDCConnectSyntheticEmailDomain) || isReservedEmail(email) {
			email = identityUser.Email
		} else if !strings.EqualFold(identityUser.Email, email) {
			target, lookupErr := s.userRepo.GetByEmail(ctx, email)
			if lookupErr == nil && target.ID != identityUser.ID {
				if err := s.MergeFeishuAccount(ctx, identityUser.ID, target.ID, providerKey, providerSubject); err != nil {
					return nil, nil, err
				}
				identityUser, err = s.userRepo.GetByID(ctx, target.ID)
			} else if errors.Is(lookupErr, ErrUserNotFound) {
				identityUser, err = s.adoptFeishuEnterpriseEmail(ctx, identityUser.ID, email)
			} else if lookupErr != nil {
				return nil, nil, ErrServiceUnavailable
			}
			if err != nil {
				return nil, nil, err
			}
		}
	} else if identityUser != nil && !strings.EqualFold(strings.TrimSpace(identityUser.Email), email) {
		return nil, nil, infraerrors.Conflict("AUTH_IDENTITY_EMAIL_MISMATCH", "oauth identity belongs to a different email")
	}

	user := identityUser
	created := false
	if user == nil {
		user, err = s.userRepo.GetByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				user, err = s.createEmailOAuthIdentityUser(ctx, email, input.Username, providerType, invitationCode, affiliateCode, authenticatedFeishu)
				if err != nil {
					return nil, nil, err
				}
				created = true
			} else {
				logger.LegacyPrintf("service.auth", "[Auth] Database error during %s oauth login: %v", providerType, err)
				return nil, nil, ErrServiceUnavailable
			}
		}
	}

	if !user.IsActive() {
		return nil, nil, ErrUserNotActive
	}
	if err := s.ensureEmailOAuthIdentity(ctx, user.ID, EmailOAuthIdentityInput{
		ProviderType:     providerType,
		ProviderKey:      providerKey,
		ProviderSubject:  providerSubject,
		Email:            email,
		EmailVerified:    input.EmailVerified,
		Username:         input.Username,
		DisplayName:      input.DisplayName,
		AvatarURL:        input.AvatarURL,
		UpstreamMetadata: input.UpstreamMetadata,
	}); err != nil {
		return nil, nil, err
	}
	if authenticatedFeishu && !isReservedEmail(email) {
		if err := ensureBoundEmailAuthIdentityWithClient(ctx, s.entClient, user.ID, normalizeBoundEmailAuthIdentitySubject(email), "feishu_enterprise_email"); err != nil {
			return nil, nil, infraerrors.InternalServer("FEISHU_EMAIL_BIND_FAILED", "failed to bind Feishu enterprise email").WithCause(err)
		}
	}

	if user.Username == "" && strings.TrimSpace(input.Username) != "" {
		user.Username = strings.TrimSpace(input.Username)
		if err := s.userRepo.Update(ctx, user, UserUpdateFields{Username: true}); err != nil {
			logger.LegacyPrintf("service.auth", "[Auth] Failed to update username after %s oauth login: %v", providerType, err)
		}
	}
	if !created {
		if err := s.ApplyProviderDefaultSettingsOnFirstBind(ctx, user.ID, providerType); err != nil {
			logger.LegacyPrintf("service.auth", "[Auth] Failed to apply %s first bind defaults: %v", providerType, err)
		}
	} else {
		user = s.applyOAuthSignupPromoCode(ctx, user, promoCode)
	}
	if !issueTokens {
		return nil, user, nil
	}
	s.RecordSuccessfulLogin(ctx, user.ID)

	tokenPair, err := s.GenerateTokenPair(ctx, user, "")
	if err != nil {
		return nil, nil, fmt.Errorf("generate token pair: %w", err)
	}
	return tokenPair, user, nil
}

// adoptFeishuEnterpriseEmail upgrades a legacy synthetic Feishu account to the
// enterprise email returned by the authenticated provider. Both the primary
// email and its verified email identity are committed atomically.
func (s *AuthService) adoptFeishuEnterpriseEmail(ctx context.Context, userID int64, email string) (*User, error) {
	if s == nil || s.entClient == nil || s.userRepo == nil || userID <= 0 {
		return nil, ErrServiceUnavailable
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || isReservedEmail(email) {
		return nil, infraerrors.BadRequest("INVALID_EMAIL", "invalid enterprise email")
	}
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	defer func() { _ = tx.Rollback() }()

	stored, err := tx.User.Get(ctx, userID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	if !strings.HasSuffix(strings.ToLower(strings.TrimSpace(stored.Email)), OIDCConnectSyntheticEmailDomain) {
		return nil, infraerrors.Conflict("AUTH_IDENTITY_EMAIL_MISMATCH", "Feishu identity already uses another email")
	}
	owned, err := tx.User.Query().Where(user.EmailEQ(email), user.IDNEQ(userID)).Exist(ctx)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	if owned {
		return nil, infraerrors.Conflict("EMAIL_ALREADY_EXISTS", "enterprise email already belongs to another account")
	}
	if _, err := tx.User.UpdateOneID(userID).SetEmail(email).Save(ctx); err != nil {
		return nil, infraerrors.Conflict("EMAIL_ALREADY_EXISTS", "enterprise email already belongs to another account").WithCause(err)
	}
	if err := ensureBoundEmailAuthIdentityWithClient(ctx, tx.Client(), userID, normalizeBoundEmailAuthIdentitySubject(email), "feishu_enterprise_email"); err != nil {
		return nil, infraerrors.InternalServer("FEISHU_EMAIL_BIND_FAILED", "failed to bind Feishu enterprise email").WithCause(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, ErrServiceUnavailable
	}
	updated, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	return updated, nil
}

func (s *AuthService) createEmailOAuthUser(ctx context.Context, email, username, providerType, invitationCode, affiliateCode string) (*User, error) {
	return s.createEmailOAuthIdentityUser(ctx, email, username, providerType, invitationCode, affiliateCode, false)
}

func (s *AuthService) createEmailOAuthIdentityUser(ctx context.Context, email, username, providerType, invitationCode, affiliateCode string, authenticatedFeishu bool) (*User, error) {
	// Public email registration may be closed while enterprise Feishu login is enabled.
	if !authenticatedFeishu && (s.settingService == nil || !s.settingService.IsRegistrationEnabled(ctx)) {
		return nil, ErrRegDisabled
	}
	invitationRedeemCode, err := s.validateOAuthRegistrationInvitation(ctx, invitationCode)
	if err != nil {
		if errors.Is(err, ErrInvitationCodeRequired) {
			return nil, ErrOAuthInvitationRequired
		}
		return nil, err
	}

	randomPassword, err := randomHexString(32)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	hashedPassword, err := s.HashPassword(randomPassword)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	grantPlan := s.resolveSignupGrantPlan(ctx, providerType)
	var defaultRPMLimit int
	if s.settingService != nil {
		defaultRPMLimit = s.settingService.GetDefaultUserRPMLimit(ctx)
	}
	user := &User{
		Email:        email,
		Username:     strings.TrimSpace(username),
		PasswordHash: hashedPassword,
		Role:         RoleUser,
		Balance:      grantPlan.Balance,
		Concurrency:  grantPlan.Concurrency,
		RPMLimit:     defaultRPMLimit,
		Status:       StatusActive,
		SignupSource: providerType,
	}
	if err := s.userRepo.Create(ctx, user); err != nil {
		if errors.Is(err, ErrEmailExists) {
			existing, loadErr := s.userRepo.GetByEmail(ctx, email)
			if loadErr != nil {
				return nil, ErrServiceUnavailable
			}
			return existing, nil
		}
		return nil, ErrServiceUnavailable
	}
	s.postAuthUserBootstrap(ctx, user, providerType, false)
	s.assignSubscriptions(ctx, user.ID, grantPlan.Subscriptions, "auto assigned by signup defaults")
	// snapshot user × platform quota（fail-open）
	_ = s.snapshotPlatformQuotaDefaults(ctx, user.ID, &grantPlan)
	s.bindOAuthAffiliate(ctx, user.ID, affiliateCode)
	if invitationRedeemCode != nil {
		if err := s.useOAuthRegistrationInvitation(ctx, invitationRedeemCode.ID, user.ID); err != nil {
			_ = s.RollbackOAuthEmailAccountCreation(ctx, user.ID, invitationCode)
			return nil, ErrInvitationCodeInvalid
		}
	}
	return user, nil
}

func (s *AuthService) findEmailOAuthIdentityOwner(ctx context.Context, providerType, providerKey, providerSubject string) (*User, error) {
	identity, err := s.entClient.AuthIdentity.Query().
		Where(
			authidentity.ProviderTypeEQ(providerType),
			authidentity.ProviderKeyEQ(providerKey),
			authidentity.ProviderSubjectEQ(providerSubject),
		).
		Only(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			return nil, nil
		}
		return nil, infraerrors.InternalServer("AUTH_IDENTITY_LOOKUP_FAILED", "failed to inspect auth identity ownership").WithCause(err)
	}
	user, err := s.userRepo.GetByID(ctx, identity.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, nil
		}
		return nil, ErrServiceUnavailable
	}
	return user, nil
}

func (s *AuthService) ensureEmailOAuthIdentity(ctx context.Context, userID int64, input EmailOAuthIdentityInput) error {
	metadata := map[string]any{
		"email":          strings.TrimSpace(strings.ToLower(input.Email)),
		"email_verified": input.EmailVerified,
	}
	for key, value := range input.UpstreamMetadata {
		metadata[key] = value
	}
	if strings.TrimSpace(input.Username) != "" {
		metadata["username"] = strings.TrimSpace(input.Username)
	}
	if strings.TrimSpace(input.DisplayName) != "" {
		metadata["display_name"] = strings.TrimSpace(input.DisplayName)
	}
	if strings.TrimSpace(input.AvatarURL) != "" {
		metadata["avatar_url"] = strings.TrimSpace(input.AvatarURL)
	}

	providerType := normalizeOAuthSignupSource(input.ProviderType)
	providerKey := strings.TrimSpace(input.ProviderKey)
	providerSubject := strings.TrimSpace(input.ProviderSubject)
	identity, err := s.entClient.AuthIdentity.Query().
		Where(
			authidentity.ProviderTypeEQ(providerType),
			authidentity.ProviderKeyEQ(providerKey),
			authidentity.ProviderSubjectEQ(providerSubject),
		).
		Only(ctx)
	if err != nil && !dbent.IsNotFound(err) {
		return infraerrors.InternalServer("AUTH_IDENTITY_LOOKUP_FAILED", "failed to inspect auth identity ownership").WithCause(err)
	}
	if identity != nil {
		if identity.UserID != userID {
			return infraerrors.Conflict("AUTH_IDENTITY_OWNERSHIP_CONFLICT", "auth identity already belongs to another user")
		}
		_, err = s.entClient.AuthIdentity.UpdateOneID(identity.ID).
			SetMetadata(metadata).
			Save(ctx)
		return err
	}
	_, err = s.entClient.AuthIdentity.Create().
		SetUserID(userID).
		SetProviderType(providerType).
		SetProviderKey(providerKey).
		SetProviderSubject(providerSubject).
		SetMetadata(metadata).
		Save(ctx)
	return err
}

// MergeFeishuAccount consolidates a previously-created synthetic account in one
// database transaction; the email account remains the canonical login account.
func (s *AuthService) MergeFeishuAccount(ctx context.Context, sourceID, targetID int64, issuer, subject string) error {
	if s == nil || s.entClient == nil {
		return ErrServiceUnavailable
	}
	_, err := s.entClient.ExecContext(ctx, "SELECT merge_feishu_account($1, $2, $3, $4)", sourceID, targetID, issuer, subject)
	if err != nil {
		return infraerrors.Conflict("FEISHU_ACCOUNT_MERGE_FAILED", "飞书账号合并失败，原账号数据已保留").WithCause(err)
	}
	// The source is disabled in the transaction; revoke refresh sessions as well.
	_ = s.RevokeAllUserSessions(ctx, sourceID)
	return nil
}
