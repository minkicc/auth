package auth

import (
	"net/mail"
	"regexp"
	"strings"
)

var accountIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{1,62}[A-Za-z0-9]$`)

func NormalizeAccountID(userID string) (string, error) {
	normalized := strings.TrimSpace(userID)
	if normalized == "" {
		return "", ErrInvalidInput("Account ID must be provided for normal account")
	}
	if len(normalized) < 3 || len(normalized) > 64 {
		return "", ErrInvalidUsername("Account ID must be between 3 and 64 characters")
	}
	if !accountIDPattern.MatchString(normalized) {
		return "", ErrInvalidUsername("Account ID may only contain letters, numbers, dots, underscores, hyphens, and @")
	}
	return normalized, nil
}

func NormalizeEmailAddress(email string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return "", ErrInvalidEmail("Valid email must be provided")
	}

	parsed, err := mail.ParseAddress(normalized)
	if err != nil || parsed.Address != normalized {
		return "", ErrInvalidEmail("Valid email must be provided")
	}

	return normalized, nil
}

func NormalizePhoneNumber(phone string) (string, error) {
	raw := strings.TrimSpace(phone)
	if raw == "" {
		return "", ErrInvalidPhoneFormat("Invalid phone number format")
	}

	var digits strings.Builder
	hasPlus := false
	for index, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == '+' && index == 0 && !hasPlus:
			hasPlus = true
		case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
			continue
		default:
			return "", ErrInvalidPhoneFormat("Invalid phone number format")
		}
	}

	if digits.Len() < 7 || digits.Len() > 15 {
		return "", ErrInvalidPhoneFormat("Invalid phone number format")
	}

	if hasPlus {
		return "+" + digits.String(), nil
	}
	return digits.String(), nil
}
