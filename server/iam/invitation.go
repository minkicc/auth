/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

const (
	bootstrapInvitationID    = "inv_bootstrap_first_user"
	bootstrapInvitationUseID = "ivu_bootstrap_first_user"
)

var invitationRolePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

type InvitationCreateInput struct {
	Name           string
	Code           string
	Scope          string
	OrganizationID string
	ClientID       string
	MaxUses        int
	ExpiresAt      *time.Time
	AllowedEmail   string
	AllowedDomain  string
	DefaultRoles   []string
	DefaultGroups  []string
	CreatedBy      string
}

type InvitationRedeemInput struct {
	Code         string
	Registration config.RegistrationConfig
	Provider     string
	Identifier   string
	Email        string
	ClientID     string
	UserID       string
	IP           string
}

type InvitationRedemption struct {
	Invitation InvitationCode
	UseID      string
	Bootstrap  bool
}

func HashInvitationCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *Service) GenerateInvitationCode() (string, error) {
	suffix, err := auth.GenerateReadableRandomString(24)
	if err != nil {
		return "", err
	}
	return "invite_" + suffix, nil
}

func (s *Service) CreateInvitation(input InvitationCreateInput) (InvitationCode, string, error) {
	if s == nil || s.db == nil {
		return InvitationCode{}, "", fmt.Errorf("iam service requires database")
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return InvitationCode{}, "", fmt.Errorf("invitation name is required")
	}
	code := strings.TrimSpace(input.Code)
	if code == "" {
		generated, err := s.GenerateInvitationCode()
		if err != nil {
			return InvitationCode{}, "", err
		}
		code = generated
	}
	if len(code) < 8 {
		return InvitationCode{}, "", fmt.Errorf("invitation code must be at least 8 characters")
	}
	scope := InvitationCodeScope(strings.TrimSpace(strings.ToLower(input.Scope)))
	if scope == "" {
		scope = InvitationCodeScopeGlobal
	}
	switch scope {
	case InvitationCodeScopeGlobal, InvitationCodeScopeOrganization, InvitationCodeScopeClient:
	default:
		return InvitationCode{}, "", fmt.Errorf("invalid invitation scope")
	}
	if scope == InvitationCodeScopeOrganization && strings.TrimSpace(input.OrganizationID) == "" {
		return InvitationCode{}, "", fmt.Errorf("organization invitation requires organization_id")
	}
	if scope == InvitationCodeScopeClient && strings.TrimSpace(input.ClientID) == "" {
		return InvitationCode{}, "", fmt.Errorf("client invitation requires client_id")
	}
	rolesJSON, err := invitationStringListJSON(input.DefaultRoles, true)
	if err != nil {
		return InvitationCode{}, "", err
	}
	groupsJSON, err := invitationStringListJSON(input.DefaultGroups, false)
	if err != nil {
		return InvitationCode{}, "", err
	}
	maxUses := input.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	invitationID, err := s.GenerateInvitationID()
	if err != nil {
		return InvitationCode{}, "", err
	}
	now := time.Now()
	invitation := InvitationCode{
		InvitationID:      invitationID,
		Name:              name,
		CodeHash:          HashInvitationCode(code),
		Status:            InvitationCodeStatusActive,
		Scope:             scope,
		OrganizationID:    strings.TrimSpace(input.OrganizationID),
		ClientID:          strings.TrimSpace(input.ClientID),
		MaxUses:           maxUses,
		ExpiresAt:         input.ExpiresAt,
		AllowedEmail:      strings.TrimSpace(strings.ToLower(input.AllowedEmail)),
		AllowedDomain:     normalizeInvitationDomain(input.AllowedDomain),
		DefaultRolesJSON:  rolesJSON,
		DefaultGroupsJSON: groupsJSON,
		CreatedBy:         strings.TrimSpace(input.CreatedBy),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.validateInvitationTarget(invitation); err != nil {
		return InvitationCode{}, "", err
	}
	if err := s.db.Create(&invitation).Error; err != nil {
		return InvitationCode{}, "", err
	}
	return invitation, code, nil
}

func (s *Service) ListInvitations() ([]InvitationCode, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("iam service requires database")
	}
	var invitations []InvitationCode
	if err := s.db.Order("created_at DESC").Find(&invitations).Error; err != nil {
		return nil, err
	}
	return invitations, nil
}

func (s *Service) DisableInvitation(invitationID string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("iam service requires database")
	}
	invitationID = strings.TrimSpace(invitationID)
	if invitationID == "" {
		return fmt.Errorf("invitation_id is required")
	}
	update := s.db.Model(&InvitationCode{}).
		Where("invitation_id = ?", invitationID).
		Update("status", InvitationCodeStatusDisabled)
	if update.Error != nil {
		return update.Error
	}
	if update.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *Service) RedeemInvitation(input InvitationRedeemInput) (*InvitationRedemption, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("iam service requires database")
	}
	code := strings.TrimSpace(input.Code)
	if code == "" {
		return nil, fmt.Errorf("invitation code is required")
	}
	if bootstrap, ok, err := s.bootstrapInvitation(input, code); ok || err != nil {
		return bootstrap, err
	}

	hash := HashInvitationCode(code)
	var invitation InvitationCode
	if err := s.db.First(&invitation, "code_hash = ?", hash).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("invitation code is invalid")
		}
		return nil, err
	}
	if err := s.validateInvitationForUse(invitation, input); err != nil {
		return nil, err
	}
	useID, err := s.GenerateInvitationUseID()
	if err != nil {
		return nil, err
	}
	use := invitationUseFromInput(useID, invitation.InvitationID, input)
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		update := tx.Model(&InvitationCode{}).
			Where("invitation_id = ? AND status = ? AND (max_uses <= 0 OR used_count < max_uses)", invitation.InvitationID, InvitationCodeStatusActive).
			UpdateColumn("used_count", gorm.Expr("used_count + ?", 1))
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected == 0 {
			return fmt.Errorf("invitation code has no remaining uses")
		}
		if err := tx.Create(&use).Error; err != nil {
			return err
		}
		if input.UserID != "" {
			return applyInvitationEffects(tx, invitation, input.UserID)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &InvitationRedemption{Invitation: invitation, UseID: useID}, nil
}

func (s *Service) CompleteInvitationRedemption(redemption *InvitationRedemption, userID string) error {
	if s == nil || s.db == nil || redemption == nil || strings.TrimSpace(userID) == "" {
		return nil
	}
	userID = strings.TrimSpace(userID)
	return s.db.Transaction(func(tx *gorm.DB) error {
		if redemption.UseID != "" {
			if err := tx.Model(&InvitationCodeUse{}).Where("use_id = ?", redemption.UseID).Update("user_id", userID).Error; err != nil {
				return err
			}
		}
		return applyInvitationEffects(tx, redemption.Invitation, userID)
	})
}

func (s *Service) CancelInvitationRedemption(redemption *InvitationRedemption) error {
	if s == nil || s.db == nil || redemption == nil || strings.TrimSpace(redemption.UseID) == "" {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		deleted := tx.Delete(&InvitationCodeUse{}, "use_id = ? AND user_id = ''", redemption.UseID)
		if deleted.Error != nil {
			return deleted.Error
		}
		if deleted.RowsAffected == 0 {
			return nil
		}
		if redemption.Bootstrap {
			return nil
		}
		return tx.Model(&InvitationCode{}).
			Where("invitation_id = ? AND used_count > 0", redemption.Invitation.InvitationID).
			UpdateColumn("used_count", gorm.Expr("used_count - ?", 1)).Error
	})
}

func (s *Service) bootstrapInvitation(input InvitationRedeemInput, code string) (*InvitationRedemption, bool, error) {
	bootstrapCode := strings.TrimSpace(input.Registration.BootstrapInvitationCode)
	if bootstrapCode == "" {
		return nil, false, nil
	}
	if subtle.ConstantTimeCompare([]byte(HashInvitationCode(code)), []byte(HashInvitationCode(bootstrapCode))) != 1 {
		return nil, false, nil
	}
	var userCount int64
	if err := s.db.Model(&auth.User{}).Count(&userCount).Error; err != nil {
		return nil, true, err
	}
	if userCount > 0 {
		return nil, true, fmt.Errorf("bootstrap invitation code is only valid before the first user is created")
	}
	var useCount int64
	if err := s.db.Model(&InvitationCodeUse{}).Where("invitation_id = ?", bootstrapInvitationID).Count(&useCount).Error; err != nil {
		return nil, true, err
	}
	if useCount > 0 {
		return nil, true, fmt.Errorf("bootstrap invitation code has already been used")
	}
	invitation := InvitationCode{
		InvitationID: bootstrapInvitationID,
		Name:         "Bootstrap first user",
		Status:       InvitationCodeStatusActive,
		Scope:        InvitationCodeScopeGlobal,
		MaxUses:      1,
		UsedCount:    0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	use := invitationUseFromInput(bootstrapInvitationUseID, bootstrapInvitationID, input)
	if err := s.db.Create(&use).Error; err != nil {
		return nil, true, err
	}
	return &InvitationRedemption{Invitation: invitation, UseID: bootstrapInvitationUseID, Bootstrap: true}, true, nil
}

func (s *Service) validateInvitationTarget(invitation InvitationCode) error {
	if invitation.AllowedEmail != "" && !strings.Contains(invitation.AllowedEmail, "@") {
		return fmt.Errorf("allowed_email is invalid")
	}
	if invitation.AllowedDomain != "" && strings.Contains(invitation.AllowedDomain, "@") {
		return fmt.Errorf("allowed_domain is invalid")
	}
	return nil
}

func (s *Service) validateInvitationForUse(invitation InvitationCode, input InvitationRedeemInput) error {
	if invitation.Status != InvitationCodeStatusActive {
		return fmt.Errorf("invitation code is disabled")
	}
	if invitation.ExpiresAt != nil && time.Now().After(*invitation.ExpiresAt) {
		return fmt.Errorf("invitation code has expired")
	}
	if invitation.MaxUses > 0 && invitation.UsedCount >= invitation.MaxUses {
		return fmt.Errorf("invitation code has no remaining uses")
	}
	if invitation.ClientID != "" && strings.TrimSpace(input.ClientID) != invitation.ClientID {
		return fmt.Errorf("invitation code is not valid for this client")
	}
	if invitation.Scope == InvitationCodeScopeClient && invitation.ClientID == "" {
		return fmt.Errorf("client invitation is missing client_id")
	}
	email := invitationEmailFromInput(input)
	if invitation.AllowedEmail != "" && email != invitation.AllowedEmail {
		return fmt.Errorf("invitation code is not valid for this email")
	}
	if invitation.AllowedDomain != "" && invitationDomain(email) != invitation.AllowedDomain {
		return fmt.Errorf("invitation code is not valid for this email domain")
	}
	return nil
}

func invitationUseFromInput(useID, invitationID string, input InvitationRedeemInput) InvitationCodeUse {
	return InvitationCodeUse{
		UseID:        useID,
		InvitationID: invitationID,
		UserID:       strings.TrimSpace(input.UserID),
		Provider:     strings.TrimSpace(strings.ToLower(input.Provider)),
		Identifier:   strings.TrimSpace(input.Identifier),
		Email:        invitationEmailFromInput(input),
		IP:           strings.TrimSpace(input.IP),
		UsedAt:       time.Now(),
	}
}

func applyInvitationEffects(tx *gorm.DB, invitation InvitationCode, userID string) error {
	if tx == nil || strings.TrimSpace(invitation.OrganizationID) == "" || strings.TrimSpace(userID) == "" {
		return nil
	}
	roles := parseInvitationStringListJSON(invitation.DefaultRolesJSON)
	rolesJSON, err := invitationStringListJSON(roles, true)
	if err != nil {
		return err
	}
	now := time.Now()
	var membership OrganizationMembership
	err = tx.First(&membership, "organization_id = ? AND user_id = ?", invitation.OrganizationID, userID).Error
	switch err {
	case nil:
		merged := mergeInvitationStringLists(parseInvitationStringListJSON(membership.RolesJSON), roles)
		rolesJSON, err = invitationStringListJSON(merged, true)
		if err != nil {
			return err
		}
		membership.Status = MembershipStatusActive
		membership.RolesJSON = rolesJSON
		membership.UpdatedAt = now
		return tx.Save(&membership).Error
	case gorm.ErrRecordNotFound:
		membership = OrganizationMembership{
			OrganizationID: invitation.OrganizationID,
			UserID:         userID,
			Status:         MembershipStatusActive,
			RolesJSON:      rolesJSON,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		return tx.Create(&membership).Error
	default:
		return err
	}
}

func invitationEmailFromInput(input InvitationRedeemInput) string {
	email := strings.TrimSpace(strings.ToLower(input.Email))
	if email == "" && strings.Contains(input.Identifier, "@") {
		email = strings.TrimSpace(strings.ToLower(input.Identifier))
	}
	return email
}

func invitationDomain(email string) string {
	parts := strings.Split(strings.TrimSpace(strings.ToLower(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return normalizeInvitationDomain(parts[1])
}

func normalizeInvitationDomain(domain string) string {
	return strings.TrimPrefix(strings.TrimSpace(strings.ToLower(domain)), "@")
}

func invitationStringListJSON(values []string, validateRole bool) (string, error) {
	normalized := mergeInvitationStringLists(nil, values)
	if validateRole {
		for _, value := range normalized {
			if !invitationRolePattern.MatchString(value) {
				return "", fmt.Errorf("role %q is invalid", value)
			}
		}
	}
	content, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func parseInvitationStringListJSON(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return []string{}
	}
	return mergeInvitationStringLists(nil, values)
}

func mergeInvitationStringLists(left, right []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(left)+len(right))
	for _, value := range append(append([]string{}, left...), right...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
