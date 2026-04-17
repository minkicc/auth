package auth

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestGenerateUserIDUsesReadableInternalPrefix(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:generate-user-id?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		t.Fatalf("failed to migrate user table: %v", err)
	}

	userID, err := GenerateUserID(db)
	if err != nil {
		t.Fatalf("GenerateUserID returned error: %v", err)
	}

	if !strings.HasPrefix(userID, UserIDPrefix) {
		t.Fatalf("expected user ID prefix %q, got %q", UserIDPrefix, userID)
	}
	if len(userID) != len(UserIDPrefix)+userIDRandomLength {
		t.Fatalf("expected user ID length %d, got %d", len(UserIDPrefix)+userIDRandomLength, len(userID))
	}
	for _, ch := range strings.TrimPrefix(userID, UserIDPrefix) {
		if !strings.ContainsRune(readableIDChars, ch) {
			t.Fatalf("generated user ID contains non-readable character %q in %q", ch, userID)
		}
	}
}
