/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

type sequenceEnterpriseLDAPAuthenticator struct {
	responses []*EnterpriseLDAPUserInfo
	calls     int
}

func (f *sequenceEnterpriseLDAPAuthenticator) Authenticate(_ context.Context, _ config.EnterpriseLDAPProviderConfig, _, _ string) (*EnterpriseLDAPUserInfo, error) {
	if len(f.responses) == 0 {
		return &EnterpriseLDAPUserInfo{}, nil
	}
	index := f.calls
	if index >= len(f.responses) {
		index = len(f.responses) - 1
	}
	f.calls++
	response := *f.responses[index]
	response.Groups = append([]EnterpriseLDAPGroupInfo(nil), f.responses[index].Groups...)
	return &response, nil
}

func TestEnterpriseLDAPManagerSyncsDirectoryGroups(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:enterprise-ldap-groups?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sqlite handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		t.Fatalf("failed to migrate users: %v", err)
	}
	service := NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	authenticator := &sequenceEnterpriseLDAPAuthenticator{
		responses: []*EnterpriseLDAPUserInfo{
			{
				Subject:           "ldap-subject-001",
				Email:             "ada@globex.com",
				EmailVerified:     true,
				Name:              "Ada Lovelace",
				PreferredUsername: "ada",
				DN:                "uid=ada,ou=people,dc=globex,dc=test",
				Groups: []EnterpriseLDAPGroupInfo{
					{ExternalID: "grp-engineering", DisplayName: "Engineering Team"},
					{ExternalID: "grp-ops", DisplayName: "Ops Oncall"},
				},
			},
			{
				Subject:           "ldap-subject-001",
				Email:             "ada@globex.com",
				EmailVerified:     true,
				Name:              "Ada Lovelace",
				PreferredUsername: "ada",
				DN:                "uid=ada,ou=people,dc=globex,dc=test",
				Groups: []EnterpriseLDAPGroupInfo{
					{ExternalID: "grp-engineering", DisplayName: "Product Team"},
				},
			},
		},
	}

	manager, err := NewEnterpriseLDAPManagerWithAuthenticator(config.IAMConfig{EnterpriseLDAP: []config.EnterpriseLDAPProviderConfig{{
		Slug:                 "globex-ldap",
		Name:                 "Globex Directory",
		OrganizationID:       "org_globex000000000",
		URL:                  "ldaps://ldap.globex.test:636",
		BaseDN:               "dc=globex,dc=test",
		UserFilter:           "(&(objectClass=person)(uid={username}))",
		GroupMemberAttribute: "memberOf",
		GroupIdentifierAttr:  "entryUUID",
		GroupNameAttribute:   "displayName",
	}}}, db, nil, authenticator)
	if err != nil {
		t.Fatalf("failed to create enterprise ldap manager: %v", err)
	}

	user, err := manager.Authenticate(context.Background(), "globex-ldap", "ada", "correct-horse")
	if err != nil {
		t.Fatalf("failed to authenticate first ldap login: %v", err)
	}
	assertEnterpriseLDAPMembershipRoles(t, db, "org_globex000000000", user.UserID, []string{"engineering-team", "ops-oncall"})

	userAgain, err := manager.Authenticate(context.Background(), "globex-ldap", "ada", "correct-horse")
	if err != nil {
		t.Fatalf("failed to authenticate second ldap login: %v", err)
	}
	if userAgain.UserID != user.UserID {
		t.Fatalf("expected stable user id across ldap logins, got %q then %q", user.UserID, userAgain.UserID)
	}

	assertEnterpriseLDAPMembershipRoles(t, db, "org_globex000000000", user.UserID, []string{"product-team"})

	var renamedGroup OrganizationGroup
	if err := db.First(&renamedGroup, "organization_id = ? AND provider_type = ? AND provider_id = ? AND external_id = ?", "org_globex000000000", IdentityProviderTypeLDAP, "globex-ldap", "grp-engineering").Error; err != nil {
		t.Fatalf("expected renamed ldap group: %v", err)
	}
	if renamedGroup.DisplayName != "Product Team" || renamedGroup.RoleName != "product-team" {
		t.Fatalf("unexpected renamed ldap group: %#v", renamedGroup)
	}

	var staleGroupCount int64
	if err := db.Model(&OrganizationGroup{}).
		Where("organization_id = ? AND provider_type = ? AND provider_id = ? AND external_id = ?", "org_globex000000000", IdentityProviderTypeLDAP, "globex-ldap", "grp-ops").
		Count(&staleGroupCount).Error; err != nil {
		t.Fatalf("failed to count stale ldap group: %v", err)
	}
	if staleGroupCount != 0 {
		t.Fatalf("expected removed ldap group to be cleaned up, got count %d", staleGroupCount)
	}
}

func assertEnterpriseLDAPMembershipRoles(t *testing.T, db *gorm.DB, organizationID, userID string, want []string) {
	t.Helper()
	var membership OrganizationMembership
	if err := db.First(&membership, "organization_id = ? AND user_id = ?", organizationID, userID).Error; err != nil {
		t.Fatalf("expected organization membership: %v", err)
	}
	got := parseEnterpriseLDAPStringListJSON(membership.RolesJSON)
	if len(got) != len(want) {
		t.Fatalf("unexpected ldap membership roles length: got %#v want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("unexpected ldap membership roles: got %#v want %#v", got, want)
		}
	}
}
