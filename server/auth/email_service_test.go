package auth

import "testing"

func TestNormalizeEmailTemplatePlaceholders(t *testing.T) {
	content := `https://auth.example.test/verify-email?token=%3C%25Token%25%3E&code=%3C%25Code%25%3E`

	got := normalizeEmailTemplatePlaceholders(content)

	if got != `https://auth.example.test/verify-email?token={{.Token}}&code={{.Code}}` {
		t.Fatalf("unexpected normalized content: %s", got)
	}
}

