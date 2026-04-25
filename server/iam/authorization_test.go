package iam

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestResolveOrganizationAuthorizationMergesLegacyRolesGroupRolesAndBindings(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:iam-authorization?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	service := NewService(db)
	if err := service.AutoMigrate(); err != nil {
		t.Fatalf("failed to auto-migrate iam tables: %v", err)
	}

	now := time.Now()
	legacyRolesJSON, err := json.Marshal([]string{"viewer"})
	if err != nil {
		t.Fatalf("failed to marshal legacy roles: %v", err)
	}

	fixtures := []any{
		&Organization{
			OrganizationID: "org_acme0000000000",
			Slug:           "acme",
			Name:           "Acme",
			Status:         OrganizationStatusActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationMembership{
			OrganizationID: "org_acme0000000000",
			UserID:         "usr_demo0000000000",
			Status:         MembershipStatusActive,
			RolesJSON:      string(legacyRolesJSON),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationGroup{
			GroupID:        "grp_platform000000",
			OrganizationID: "org_acme0000000000",
			ProviderType:   IdentityProviderTypeManual,
			ProviderID:     ManualOrganizationGroupProvider,
			ExternalID:     "grp_platform000000",
			DisplayName:    "Platform Team",
			RoleName:       "ops-team",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationGroupMember{
			OrganizationID: "org_acme0000000000",
			GroupID:        "grp_platform000000",
			UserID:         "usr_demo0000000000",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRole{
			RoleID:         "rol_viewer00000000",
			OrganizationID: "org_acme0000000000",
			Name:           "Viewer",
			Slug:           "viewer",
			Enabled:        true,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRole{
			RoleID:         "rol_admin000000000",
			OrganizationID: "org_acme0000000000",
			Name:           "Admin",
			Slug:           "admin",
			Enabled:        true,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRole{
			RoleID:         "rol_finance000000",
			OrganizationID: "org_acme0000000000",
			Name:           "Finance",
			Slug:           "finance",
			Enabled:        true,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRolePermission{
			OrganizationID: "org_acme0000000000",
			RoleID:         "rol_viewer00000000",
			PermissionKey:  "dashboard.read",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRolePermission{
			OrganizationID: "org_acme0000000000",
			RoleID:         "rol_admin000000000",
			PermissionKey:  "settings.manage",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRolePermission{
			OrganizationID: "org_acme0000000000",
			RoleID:         "rol_finance000000",
			PermissionKey:  "billing.read",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRoleBinding{
			BindingID:      "rbd_member0000000",
			OrganizationID: "org_acme0000000000",
			RoleID:         "rol_admin000000000",
			SubjectType:    RoleBindingSubjectMembership,
			SubjectID:      "usr_demo0000000000",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		&OrganizationRoleBinding{
			BindingID:      "rbd_group000000000",
			OrganizationID: "org_acme0000000000",
			RoleID:         "rol_finance000000",
			SubjectType:    RoleBindingSubjectGroup,
			SubjectID:      "grp_platform000000",
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	}

	for _, fixture := range fixtures {
		if err := db.Create(fixture).Error; err != nil {
			t.Fatalf("failed to create fixture %T: %v", fixture, err)
		}
	}

	authz, err := service.ResolveOrganizationAuthorization("usr_demo0000000000", "org_acme0000000000")
	if err != nil {
		t.Fatalf("failed to resolve organization authorization: %v", err)
	}

	if authz.OrganizationID != "org_acme0000000000" {
		t.Fatalf("unexpected organization ID: %#v", authz)
	}
	assertStringListEqual(t, authz.RoleSlugs, []string{"admin", "finance", "ops-team", "viewer"})
	assertStringListEqual(t, authz.PermissionKeys, []string{"billing.read", "dashboard.read", "settings.manage"})
	assertStringListEqual(t, authz.GroupNames, []string{"Platform Team"})
}

func assertStringListEqual(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("unexpected list length: got %#v want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected list contents: got %#v want %#v", got, want)
		}
	}
}
