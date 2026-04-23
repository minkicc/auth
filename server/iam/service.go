/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"fmt"

	"gorm.io/gorm"
	"minki.cc/mkauth/server/auth"
)

// Service owns the CIAM/IAM foundation tables and helpers.
type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) AutoMigrate() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("iam service requires database")
	}
	return s.db.AutoMigrate(
		&Organization{},
		&OrganizationDomain{},
		&OrganizationIdentityProvider{},
		&ExternalIdentity{},
		&OrganizationMembership{},
	)
}

func (s *Service) GenerateOrganizationID() (string, error) {
	return s.generateUniqueID(OrganizationIDPrefix, &Organization{}, "organization_id")
}

func (s *Service) GenerateIdentityProviderID() (string, error) {
	return s.generateUniqueID(IdentityProviderIDPrefix, &OrganizationIdentityProvider{}, "identity_provider_id")
}

func (s *Service) GenerateExternalIdentityID() (string, error) {
	return s.generateUniqueID(ExternalIdentityIDPrefix, &ExternalIdentity{}, "external_identity_id")
}

func (s *Service) generateUniqueID(prefix string, model any, column string) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("iam service requires database")
	}

	for attempts := 0; attempts < 10; attempts++ {
		suffix, err := auth.GenerateReadableRandomString(readableRandomIDLength)
		if err != nil {
			return "", fmt.Errorf("generate readable ID: %w", err)
		}
		id := prefix + suffix

		var count int64
		if err := s.db.Model(model).Where(column+" = ?", id).Count(&count).Error; err != nil {
			return "", err
		}
		if count == 0 {
			return id, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique %s ID", prefix)
}
