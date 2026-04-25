package iam

import "testing"

func TestOrganizationAuthorizationMatches(t *testing.T) {
	authz := OrganizationAuthorization{
		OrganizationID: "org_acme0000000000",
		RoleSlugs:      []string{"Admin", "Security"},
		GroupNames:     []string{"Employees", "Platform"},
		PermissionKeys: []string{"settings.manage", "billing.read"},
	}

	tests := []struct {
		name        string
		requirement OrganizationAuthorizationRequirement
		want        bool
	}{
		{
			name: "require organization context",
			requirement: OrganizationAuthorizationRequirement{
				RequireOrganization: true,
			},
			want: true,
		},
		{
			name: "any role matches case-insensitively",
			requirement: OrganizationAuthorizationRequirement{
				AnyRoles: []string{"admin"},
			},
			want: true,
		},
		{
			name: "all roles matches case-insensitively",
			requirement: OrganizationAuthorizationRequirement{
				AllRoles: []string{"admin", "security"},
			},
			want: true,
		},
		{
			name: "all groups fails when missing",
			requirement: OrganizationAuthorizationRequirement{
				AllGroups: []string{"employees", "finance"},
			},
			want: false,
		},
		{
			name: "any permission matches",
			requirement: OrganizationAuthorizationRequirement{
				AnyPermissions: []string{"billing.read"},
			},
			want: true,
		},
		{
			name: "all permissions fails when missing",
			requirement: OrganizationAuthorizationRequirement{
				AllPermissions: []string{"settings.manage", "users.write"},
			},
			want: false,
		},
		{
			name: "combined requirement passes",
			requirement: OrganizationAuthorizationRequirement{
				RequireOrganization: true,
				AllRoles:            []string{"admin", "security"},
				AnyGroups:           []string{"platform"},
				AnyPermissions:      []string{"billing.read"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OrganizationAuthorizationMatches(authz, tt.requirement); got != tt.want {
				t.Fatalf("OrganizationAuthorizationMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}
