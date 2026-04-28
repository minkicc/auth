/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package common

// prefix
const (
	RedisKeySession             = "auth_session:"        // + userID + sessionID -> session info
	RedisKeyUser                = "auth_user:"           // + userID -> user info
	RedisKeyRateLimit           = "auth_ratelimit:"      // + ip -> access count
	RedisKeyLoginAttempts       = "auth_login_attempts:" // + userID + ip -> login attempts count
	RedisKeyGoogleState         = "auth_google_oauth_state:"
	RedisKeyWeixinState         = "auth_weixin_oauth_state:"
	RedisKeyEmailState          = "auth_email_state:"
	RedisKeyEmailVerifyCode     = "auth_email_verify_code:"
	RedisKeyJWTKey              = "auth_jwt_key:"
	RedisKeyVerification        = "auth_verification:"
	RedisKeyVerificationToken   = "auth_verification_token:"
	RedisKeyEmailPreregister    = "auth_email_prereg:"
	RedisKeyPhonePreregister    = "auth_phone_prereg:"
	RedisKeyInvitationPending   = "auth_invitation_pending:"
	RedisKeyOIDCAuthCode        = "auth_oidc_code:"
	RedisKeyOIDCBrowserSession  = "auth_oidc_browser_session:"
	RedisKeyOIDCRevokedToken    = "auth_oidc_revoked_token:"
	RedisKeyEnterpriseOIDCState = "auth_enterprise_oidc_state:"
	RedisKeyEnterpriseSAMLState = "auth_enterprise_saml_state:"
)
