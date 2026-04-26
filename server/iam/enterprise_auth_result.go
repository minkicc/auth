package iam

import "example.com/auth/server/auth"

// EnterpriseAuthenticationResult captures side effects from enterprise JIT login.
type EnterpriseAuthenticationResult struct {
	User    *auth.User
	Created bool
}
