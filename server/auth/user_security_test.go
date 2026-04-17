package auth

import "testing"

func TestNormalizeTokenVersion(t *testing.T) {
	if got := NormalizeTokenVersion(0); got != DefaultTokenVersion {
		t.Fatalf("expected default token version for zero, got %d", got)
	}
	if got := NormalizeTokenVersion(3); got != 3 {
		t.Fatalf("expected explicit token version to be preserved, got %d", got)
	}
}

func TestEnsureUserCanAuthenticate(t *testing.T) {
	tests := []struct {
		name   string
		user   *User
		wantOK bool
		code   ErrorCode
	}{
		{
			name:   "active user",
			user:   &User{Status: UserStatusActive},
			wantOK: true,
		},
		{
			name: "locked user",
			user: &User{Status: UserStatusLocked},
			code: ErrCodeUserLocked,
		},
		{
			name: "inactive user",
			user: &User{Status: UserStatusInactive},
			code: ErrCodeUserDisabled,
		},
		{
			name: "banned user",
			user: &User{Status: UserStatusBanned},
			code: ErrCodeUserDisabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EnsureUserCanAuthenticate(tt.user)
			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected user to authenticate, got %v", err)
				}
				return
			}

			appErr, ok := err.(*AppError)
			if !ok {
				t.Fatalf("expected AppError, got %T", err)
			}
			if appErr.Code != tt.code {
				t.Fatalf("expected error code %d, got %d", tt.code, appErr.Code)
			}
		})
	}
}
