/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"errors"
	"strings"

	"gorm.io/gorm"
)

func EnterpriseProviders(enterpriseOIDC *EnterpriseOIDCManager, enterpriseSAML *EnterpriseSAMLManager) []EnterpriseOIDCProviderSummary {
	providers := make([]EnterpriseOIDCProviderSummary, 0)
	if enterpriseOIDC != nil {
		providers = append(providers, enterpriseOIDC.Providers()...)
	}
	if enterpriseSAML != nil {
		providers = append(providers, enterpriseSAML.Providers()...)
	}
	sortEnterpriseOIDCProviderSummaries(providers)
	return providers
}

func DiscoverEnterpriseIdentityByEmail(db *gorm.DB, email string, enterpriseOIDC *EnterpriseOIDCManager, enterpriseSAML *EnterpriseSAMLManager) (EnterpriseOIDCDiscoveryResult, error) {
	result := EnterpriseOIDCDiscoveryResult{
		Email:     strings.TrimSpace(strings.ToLower(email)),
		Providers: []EnterpriseOIDCProviderSummary{},
	}

	domain, err := normalizeEnterpriseOIDCEmailDomain(result.Email)
	if err != nil {
		return result, err
	}
	return DiscoverEnterpriseIdentityByDomain(db, domain, enterpriseOIDC, enterpriseSAML)
}

func DiscoverEnterpriseIdentityByDomain(db *gorm.DB, domain string, enterpriseOIDC *EnterpriseOIDCManager, enterpriseSAML *EnterpriseSAMLManager) (EnterpriseOIDCDiscoveryResult, error) {
	result := EnterpriseOIDCDiscoveryResult{
		Providers: []EnterpriseOIDCProviderSummary{},
	}
	normalizedDomain, err := normalizeEnterpriseOIDCDomain(domain)
	if err != nil {
		return result, err
	}
	result.Domain = normalizedDomain

	if db == nil {
		result.Status = EnterpriseOIDCDiscoveryNoProvider
		return result, nil
	}

	var organizationDomain OrganizationDomain
	if err := db.First(&organizationDomain, "domain = ? AND verified = ?", normalizedDomain, true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			result.Status = EnterpriseOIDCDiscoveryDomainNotFound
			return result, nil
		}
		return result, err
	}

	var organization Organization
	if err := db.First(&organization, "organization_id = ?", organizationDomain.OrganizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			result.Status = EnterpriseOIDCDiscoveryOrganizationNotFound
			return result, nil
		}
		return result, err
	}
	result.OrganizationID = organization.OrganizationID
	result.OrganizationSlug = organization.Slug
	result.OrganizationName = organization.Name
	result.OrganizationDisplayName = organization.DisplayName

	if organization.Status != OrganizationStatusActive {
		result.Status = EnterpriseOIDCDiscoveryOrganizationInactive
		return result, nil
	}

	if enterpriseOIDC != nil {
		result.Providers = append(result.Providers, enterpriseOIDC.ProvidersForOrganization(organization.OrganizationID)...)
	}
	if enterpriseSAML != nil {
		result.Providers = append(result.Providers, enterpriseSAML.ProvidersForOrganization(organization.OrganizationID)...)
	}
	sortEnterpriseOIDCProviderSummaries(result.Providers)
	if len(result.Providers) == 0 {
		result.Status = EnterpriseOIDCDiscoveryNoProvider
		return result, nil
	}
	preferred, hasPreferred := preferredEnterpriseOIDCProvider(result.Providers)
	if hasPreferred {
		result.PreferredProviderSlug = preferred.Slug
		result.AutoRedirect = len(result.Providers) == 1 || preferred.AutoRedirect
	}
	result.Status = EnterpriseOIDCDiscoveryMatched
	return result, nil
}
