package iam

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestServiceAutoMigrateCreatesFoundationTables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:iam-auto-migrate?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	service := NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to auto-migrate iam tables: %v", err)
	}

	for _, model := range []any{
		&Organization{},
		&OrganizationDomain{},
		&OrganizationIdentityProvider{},
		&ExternalIdentity{},
		&OrganizationMembership{},
	} {
		if !db.Migrator().HasTable(model) {
			t.Fatalf("expected table for %T to exist", model)
		}
	}
}

func TestServiceGeneratesReadablePrefixedIDs(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:iam-id-generation?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	service := NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to auto-migrate iam tables: %v", err)
	}

	orgID, err := service.GenerateOrganizationID()
	if err != nil {
		t.Fatalf("failed to generate organization ID: %v", err)
	}
	if !strings.HasPrefix(orgID, OrganizationIDPrefix) || len(orgID) != len(OrganizationIDPrefix)+readableRandomIDLength {
		t.Fatalf("unexpected organization ID format: %q", orgID)
	}

	idpID, err := service.GenerateIdentityProviderID()
	if err != nil {
		t.Fatalf("failed to generate identity provider ID: %v", err)
	}
	if !strings.HasPrefix(idpID, IdentityProviderIDPrefix) || len(idpID) != len(IdentityProviderIDPrefix)+readableRandomIDLength {
		t.Fatalf("unexpected identity provider ID format: %q", idpID)
	}

	externalID, err := service.GenerateExternalIdentityID()
	if err != nil {
		t.Fatalf("failed to generate external identity ID: %v", err)
	}
	if !strings.HasPrefix(externalID, ExternalIdentityIDPrefix) || len(externalID) != len(ExternalIdentityIDPrefix)+readableRandomIDLength {
		t.Fatalf("unexpected external identity ID format: %q", externalID)
	}
}
