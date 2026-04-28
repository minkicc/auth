/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"minki.cc/mkauth/server/common"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

const pendingRegistrationInvitationTTL = 24 * time.Hour

type pendingRegistrationInvitation struct {
	Redemption iam.InvitationRedemption `json:"redemption"`
}

func (h *AuthHandler) rejectRegistrationIfDisabled(c *gin.Context, provider string) bool {
	if h == nil || h.config == nil {
		return false
	}
	if h.config.Registration.ModeOrDefault() != config.RegistrationModeDisabled {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "Self-service registration is disabled"})
	return true
}

func (h *AuthHandler) beginRegistrationInvitation(c *gin.Context, provider, identifier, email, clientID, code string) (*iam.InvitationRedemption, bool) {
	if h == nil || h.config == nil || !h.config.Registration.RequiresInvitation(provider) {
		return nil, true
	}
	if strings.TrimSpace(code) == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invitation code is required"})
		return nil, false
	}
	if h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Invitation service is unavailable"})
		return nil, false
	}

	redemption, err := iam.NewService(h.accountAuth.DB()).RedeemInvitation(iam.InvitationRedeemInput{
		Code:         code,
		Registration: h.config.Registration,
		Provider:     provider,
		Identifier:   identifier,
		Email:        email,
		ClientID:     clientID,
		IP:           c.ClientIP(),
	})
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return nil, false
	}
	return redemption, true
}

func (h *AuthHandler) completeRegistrationInvitation(c *gin.Context, redemption *iam.InvitationRedemption, userID string) bool {
	if redemption == nil {
		return true
	}
	if h == nil || h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Invitation service is unavailable"})
		return false
	}
	if err := iam.NewService(h.accountAuth.DB()).CompleteInvitationRedemption(redemption, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to apply invitation"})
		return false
	}
	return true
}

func (h *AuthHandler) cancelRegistrationInvitation(redemption *iam.InvitationRedemption) {
	if redemption == nil || h == nil || h.accountAuth == nil || h.accountAuth.DB() == nil {
		return
	}
	if err := iam.NewService(h.accountAuth.DB()).CancelInvitationRedemption(redemption); err != nil && h.logger != nil {
		h.logger.Printf("Failed to cancel invitation redemption %s: %v", redemption.UseID, err)
	}
}

func (h *AuthHandler) storePendingRegistrationInvitation(c *gin.Context, key string, redemption *iam.InvitationRedemption) bool {
	if redemption == nil {
		return true
	}
	if h == nil || h.redisStore == nil {
		h.cancelRegistrationInvitation(redemption)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Invitation verification state is unavailable"})
		return false
	}
	if err := h.redisStore.Set(common.RedisKeyInvitationPending+key, pendingRegistrationInvitation{Redemption: *redemption}, pendingRegistrationInvitationTTL); err != nil {
		h.cancelRegistrationInvitation(redemption)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store invitation verification state"})
		return false
	}
	return true
}

func (h *AuthHandler) loadPendingRegistrationInvitation(c *gin.Context, provider, key string) (*iam.InvitationRedemption, bool) {
	if h == nil || h.config == nil || !h.config.Registration.RequiresInvitation(provider) {
		return nil, true
	}
	if h.redisStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Invitation verification state is unavailable"})
		return nil, false
	}
	var pending pendingRegistrationInvitation
	if err := h.redisStore.Get(common.RedisKeyInvitationPending+key, &pending); err != nil {
		if errors.Is(err, redis.Nil) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invitation verification state is missing or expired"})
			return nil, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load invitation verification state"})
		return nil, false
	}
	return &pending.Redemption, true
}

func (h *AuthHandler) deletePendingRegistrationInvitation(key string) {
	if h == nil || h.redisStore == nil {
		return
	}
	if err := h.redisStore.Delete(common.RedisKeyInvitationPending + key); err != nil && h.logger != nil {
		h.logger.Printf("Failed to delete pending invitation state %s: %v", key, err)
	}
}

func pendingEmailInvitationKey(token string) string {
	return "email:" + strings.TrimSpace(token)
}

func pendingPhoneInvitationKey(phone string) string {
	return "phone:" + strings.TrimSpace(phone)
}
