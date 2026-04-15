package auth

import (
	"errors"
	"time"

	"minki.cc/mkauth/server/common"
)

const OIDCSessionCookieName = "oidc_session"

var ErrBrowserSessionNotFound = errors.New("browser session not found")

type BrowserSession struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

func CreateBrowserSession(redis *RedisStore, session *Session) (string, error) {
	if redis == nil || session == nil {
		return "", ErrBrowserSessionNotFound
	}

	browserSessionID, err := GenerateBase62String(32)
	if err != nil {
		return "", err
	}

	data := BrowserSession{
		UserID:    session.UserID,
		SessionID: session.ID,
		CreatedAt: time.Now(),
	}

	if err := persistBrowserSession(redis, browserSessionID, data, time.Until(session.ExpiresAt)); err != nil {
		return "", err
	}

	return browserSessionID, nil
}

func ResolveBrowserSession(redis *RedisStore, sessionMgr *SessionManager, browserSessionID string) (*BrowserSession, *Session, error) {
	if redis == nil || sessionMgr == nil || browserSessionID == "" {
		return nil, nil, ErrBrowserSessionNotFound
	}

	var data BrowserSession
	if err := redis.Get(common.RedisKeyOIDCBrowserSession+browserSessionID, &data); err != nil {
		return nil, nil, err
	}
	if data.UserID == "" || data.SessionID == "" {
		return nil, nil, ErrBrowserSessionNotFound
	}

	session, err := sessionMgr.GetSession(data.UserID, data.SessionID)
	if err != nil || session == nil {
		return nil, nil, ErrBrowserSessionNotFound
	}

	if err := persistBrowserSession(redis, browserSessionID, data, time.Until(session.ExpiresAt)); err != nil {
		return nil, nil, err
	}

	return &data, session, nil
}

func DeleteBrowserSession(redis *RedisStore, browserSessionID string) error {
	if redis == nil || browserSessionID == "" {
		return nil
	}
	return redis.Delete(common.RedisKeyOIDCBrowserSession + browserSessionID)
}

func persistBrowserSession(redis *RedisStore, browserSessionID string, data BrowserSession, ttl time.Duration) error {
	if ttl <= 0 {
		return ErrBrowserSessionNotFound
	}
	return redis.Set(common.RedisKeyOIDCBrowserSession+browserSessionID, data, ttl)
}
