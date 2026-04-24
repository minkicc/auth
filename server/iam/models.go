/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import "time"

type OrganizationStatus string

const (
	OrganizationStatusActive   OrganizationStatus = "active"
	OrganizationStatusInactive OrganizationStatus = "inactive"
)

type MembershipStatus string

const (
	MembershipStatusActive   MembershipStatus = "active"
	MembershipStatusInvited  MembershipStatus = "invited"
	MembershipStatusDisabled MembershipStatus = "disabled"
)

type IdentityProviderType string

const (
	IdentityProviderTypeOIDC   IdentityProviderType = "oidc"
	IdentityProviderTypeSAML   IdentityProviderType = "saml"
	IdentityProviderTypeLDAP   IdentityProviderType = "ldap"
	IdentityProviderTypeSCIM   IdentityProviderType = "scim"
	IdentityProviderTypeGoogle IdentityProviderType = "google"
	IdentityProviderTypeWeixin IdentityProviderType = "weixin"
)

const (
	OrganizationIDPrefix            = "org_"
	IdentityProviderIDPrefix        = "idp_"
	ExternalIdentityIDPrefix        = "ext_"
	OrganizationGroupIDPrefix       = "grp_"
	DefaultIdentityProviderPriority = 100
	readableRandomIDLength          = 16
)

// Organization represents a customer, workspace, or enterprise tenant.
type Organization struct {
	OrganizationID string             `json:"organization_id" gorm:"primaryKey;size:32"`
	Slug           string             `json:"slug" gorm:"uniqueIndex;size:80;not null"`
	Name           string             `json:"name" gorm:"size:120;not null"`
	DisplayName    string             `json:"display_name,omitempty" gorm:"size:120"`
	Status         OrganizationStatus `json:"status" gorm:"size:20;not null;default:'active'"`
	MetadataJSON   string             `json:"metadata_json,omitempty" gorm:"type:text"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

// OrganizationDomain maps verified email domains to organizations for home realm discovery.
type OrganizationDomain struct {
	Domain            string    `json:"domain" gorm:"primaryKey;size:255"`
	OrganizationID    string    `json:"organization_id" gorm:"index;not null;size:32"`
	Verified          bool      `json:"verified" gorm:"not null;default:false"`
	VerificationToken string    `json:"-" gorm:"size:128"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// OrganizationIdentityProvider stores the upstream enterprise IdP configuration shell.
// Secrets should be encrypted or resolved from external secret stores before real use.
type OrganizationIdentityProvider struct {
	IdentityProviderID string               `json:"identity_provider_id" gorm:"primaryKey;size:32"`
	OrganizationID     string               `json:"organization_id,omitempty" gorm:"index;size:32"`
	ProviderType       IdentityProviderType `json:"provider_type" gorm:"size:32;not null"`
	Name               string               `json:"name" gorm:"size:120;not null"`
	Slug               string               `json:"slug" gorm:"uniqueIndex;size:80;not null"`
	Enabled            bool                 `json:"enabled" gorm:"not null;default:true"`
	Priority           int                  `json:"priority" gorm:"not null;default:100"`
	IsDefault          bool                 `json:"is_default" gorm:"not null;default:false"`
	AutoRedirect       bool                 `json:"auto_redirect" gorm:"not null;default:false"`
	ConfigJSON         string               `json:"config_json,omitempty" gorm:"type:text"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

// ExternalIdentity links an upstream IdP subject to MKAuth's stable internal user ID.
type ExternalIdentity struct {
	ExternalIdentityID string               `json:"external_identity_id" gorm:"primaryKey;size:32"`
	ProviderType       IdentityProviderType `json:"provider_type" gorm:"size:32;not null;uniqueIndex:idx_external_identity_subject"`
	ProviderID         string               `json:"provider_id" gorm:"size:80;not null;uniqueIndex:idx_external_identity_subject"`
	Subject            string               `json:"subject" gorm:"size:255;not null;uniqueIndex:idx_external_identity_subject"`
	UserID             string               `json:"user_id" gorm:"index;not null;size:32"`
	OrganizationID     string               `json:"organization_id,omitempty" gorm:"index;size:32"`
	Email              string               `json:"email,omitempty" gorm:"size:255;index"`
	EmailVerified      bool                 `json:"email_verified" gorm:"not null;default:false"`
	DisplayName        string               `json:"display_name,omitempty" gorm:"size:120"`
	ProfileJSON        string               `json:"profile_json,omitempty" gorm:"type:text"`
	LastLoginAt        *time.Time           `json:"last_login_at,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

// OrganizationMembership assigns a user to an organization with optional role names.
type OrganizationMembership struct {
	OrganizationID string           `json:"organization_id" gorm:"primaryKey;size:32"`
	UserID         string           `json:"user_id" gorm:"primaryKey;size:32"`
	Status         MembershipStatus `json:"status" gorm:"size:20;not null;default:'active'"`
	RolesJSON      string           `json:"roles_json,omitempty" gorm:"type:text"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

// OrganizationGroup maps an upstream directory group to a lightweight organization role.
type OrganizationGroup struct {
	GroupID        string               `json:"group_id" gorm:"primaryKey;size:32"`
	OrganizationID string               `json:"organization_id" gorm:"index;not null;size:32;uniqueIndex:idx_organization_group_external"`
	ProviderType   IdentityProviderType `json:"provider_type" gorm:"size:32;not null;uniqueIndex:idx_organization_group_external"`
	ProviderID     string               `json:"provider_id" gorm:"size:80;not null;uniqueIndex:idx_organization_group_external"`
	ExternalID     string               `json:"external_id" gorm:"size:255;not null;uniqueIndex:idx_organization_group_external"`
	DisplayName    string               `json:"display_name" gorm:"size:120;not null"`
	RoleName       string               `json:"role_name" gorm:"size:64;not null"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
}

// OrganizationGroupMember stores SCIM-managed group membership for role recalculation.
type OrganizationGroupMember struct {
	OrganizationID string    `json:"organization_id" gorm:"primaryKey;size:32"`
	GroupID        string    `json:"group_id" gorm:"primaryKey;size:32"`
	UserID         string    `json:"user_id" gorm:"primaryKey;size:32"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
