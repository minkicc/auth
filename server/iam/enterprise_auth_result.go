package iam

import "minki.cc/mkauth/server/auth"

// EnterpriseAuthenticationResult captures side effects from enterprise JIT login.
type EnterpriseAuthenticationResult struct {
	User    *auth.User
	Created bool
}
