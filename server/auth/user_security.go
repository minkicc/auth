package auth

const DefaultTokenVersion = 1

func NormalizeTokenVersion(version int) int {
	if version < DefaultTokenVersion {
		return DefaultTokenVersion
	}
	return version
}

func EffectiveUserTokenVersion(user *User) int {
	if user == nil {
		return DefaultTokenVersion
	}
	return NormalizeTokenVersion(user.TokenVersion)
}

func EnsureUserCanAuthenticate(user *User) error {
	if user == nil {
		return ErrInvalidLogin
	}

	switch user.Status {
	case UserStatusActive:
		return nil
	case UserStatusLocked:
		return ErrUserLocked
	case UserStatusInactive, UserStatusBanned:
		return NewAppError(ErrCodeUserDisabled, "Account is disabled", nil)
	default:
		return NewAppError(ErrCodeUserDisabled, "Account is disabled", nil)
	}
}
