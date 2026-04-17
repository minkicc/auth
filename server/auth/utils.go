/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"gorm.io/gorm"
)

const (
	UserIDPrefix       = "usr_"
	userIDRandomLength = 16
	readableIDChars    = "0123456789abcdefghjkmnpqrstvwxyz"
)

func _generateUserID() (string, error) {
	suffix, err := GenerateReadableRandomString(userIDRandomLength)
	if err != nil {
		return "", err
	}
	return UserIDPrefix + suffix, nil
}

func GenerateReadableRandomString(length int) (string, error) {
	result := make([]byte, length)
	base := big.NewInt(int64(len(readableIDChars)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, base)
		if err != nil {
			return "", err
		}
		result[i] = readableIDChars[n.Int64()]
	}
	return string(result), nil
}

func GenerateUserID(db *gorm.DB) (string, error) {
	// Generate random UserID
	userID, err := _generateUserID()
	if err != nil {
		return "", fmt.Errorf("failed to generate random ID: %v", err)
	}

	// Ensure UserID is unique
	for {
		var count int64
		db.Model(&User{}).Where("user_id = ?", userID).Count(&count)
		if count == 0 {
			break
		}
		// Generate new UserID
		userID, err = _generateUserID()
		if err != nil {
			return "", fmt.Errorf("failed to generate random ID: %v", err)
		}
	}
	return userID, nil
}
