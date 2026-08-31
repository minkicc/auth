/*
 * Licensed under the MIT License.
 */

package handlers

import (
	"fmt"
	"net/http"
	"time"

	"cc.minki/auth/server/auth"
	"cc.minki/auth/server/common"
	"cc.minki/auth/server/iam"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type weixinOAuthState struct {
	State          string `json:"state"`
	ClientID       string `json:"client_id,omitempty"`
	InvitationCode string `json:"invitation_code,omitempty"`
	Status         string `json:"status"`
	UserID         string `json:"user_id,omitempty"`
}

const weixinQRSessionTTL = 10 * time.Minute

// WeixinLoginURL Get WeChat login URL
func (h *AuthHandler) WeixinLoginURL(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	state := uuid.New().String()
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, state)
	stateData := weixinOAuthState{
		State:          state,
		ClientID:       c.Query("client_id"),
		InvitationCode: c.Query("invitation_code"),
		Status:         "pending",
	}

	if err := h.redisStore.Set(stateKey, stateData, weixinQRSessionTTL); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"url":            h.weixinLogin.GetAuthURL(state),
		"transaction_id": state,
		"expires_in":     int(weixinQRSessionTTL / time.Second),
	})
}

// WeixinCallback Handle WeChat callback
func (h *AuthHandler) WeixinCallback(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	// Verify state
	actualState := c.Query("state")
	if actualState == "" {
		renderWeixinCallbackPage(c, false, "登录状态无效，请返回电脑重新扫码")
		return
	}

	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, actualState)
	var stateData weixinOAuthState
	if err := h.redisStore.Get(stateKey, &stateData); err != nil {
		h.logger.Printf("Failed to get OAuth state from Redis: %v", err)
		renderWeixinCallbackPage(c, false, "二维码已失效，请返回电脑重新获取")
		return
	}

	// Verify state value
	if stateData.State != actualState {
		renderWeixinCallbackPage(c, false, "登录状态无效，请返回电脑重新扫码")
		return
	}

	// Handle callback
	code := c.Query("code")
	if code == "" {
		renderWeixinCallbackPage(c, false, "微信授权未完成，请重新扫码")
		return
	}

	if err := h.runHook(c, iam.HookPreAuthenticate, nil, "weixin", nil, map[string]string{
		"login_method": "oauth_code",
	}); err != nil {
		renderWeixinCallbackPage(c, false, "当前账号暂时无法登录")
		return
	}

	loginResp, err := h.weixinLogin.HandleCallback(code)
	if err != nil {
		h.logger.Printf("WeChat login processing failed: %v", err)
		renderWeixinCallbackPage(c, false, "微信登录暂时不可用，请稍后重试")
		return
	}
	weixinUserInfo, err := h.weixinLogin.GetUserInfo(loginResp.AccessToken, loginResp.OpenID)
	if err != nil {
		h.logger.Printf("WeChat login processing failed: %v", err)
		renderWeixinCallbackPage(c, false, "微信登录暂时不可用，请稍后重试")
		return
	}
	if weixinUserInfo.UnionID == "" {
		weixinUserInfo.UnionID = loginResp.UnionID
	}
	if weixinUserInfo.UnionID == "" {
		h.logger.Printf("WeChat login response did not include a UnionID")
		renderWeixinCallbackPage(c, false, "微信账号未返回统一身份，请联系管理员检查开放平台绑定")
		return
	}
	user, err := h.weixinLogin.GetUserByWeixinID(weixinUserInfo.UnionID)
	if err != nil {
		h.logger.Printf("WeChat user lookup failed: %v", err)
		renderWeixinCallbackPage(c, false, "微信登录暂时不可用，请稍后重试")
		return
	}
	created := user == nil
	if user == nil {
		if h.rejectRegistrationIfDisabled(c, "weixin") {
			return
		}
		redemption, ok := h.beginRegistrationInvitation(c, "weixin", weixinUserInfo.UnionID, "", stateData.ClientID, stateData.InvitationCode)
		if !ok {
			return
		}
		user, err = h.weixinLogin.CreateUserFromWeixin(weixinUserInfo)
		if err != nil {
			h.cancelRegistrationInvitation(redemption)
			h.logger.Printf("WeChat user creation failed: %v", err)
			renderWeixinCallbackPage(c, false, "微信登录暂时不可用，请稍后重试")
			return
		}
		if !h.completeRegistrationInvitation(c, redemption, user.UserID) {
			return
		}
	} else {
		if err := auth.EnsureUserCanAuthenticate(user); err != nil {
			renderWeixinCallbackPage(c, false, "当前账号暂时无法登录")
			return
		}
		if h.accountAuth != nil && h.accountAuth.DB() != nil {
			if err := h.accountAuth.DB().Model(&auth.User{}).Where("user_id = ?", user.UserID).Update("last_login", time.Now()).Error; err != nil {
				h.logger.Printf("Failed to update WeChat user's last login time: %v", err)
			}
		}
	}
	if created {
		if err := h.runHook(c, iam.HookPostRegister, user, "weixin", nil, map[string]string{
			"weixin_subject": weixinUserInfo.UnionID,
		}); err != nil {
			renderWeixinCallbackPage(c, false, "当前账号暂时无法登录")
			return
		}
	}
	stateData.Status = "completed"
	stateData.UserID = user.UserID
	if err := h.redisStore.Set(stateKey, stateData, weixinQRSessionTTL); err != nil {
		h.logger.Printf("Failed to complete WeChat QR session: %v", err)
		renderWeixinCallbackPage(c, false, "登录结果保存失败，请返回电脑重试")
		return
	}
	renderWeixinCallbackPage(c, true, "登录成功，请返回原浏览器继续")
}

// WeixinLoginStatus lets the browser that rendered the QR code claim the
// completed login. The phone that scanned the code never receives its cookie.
func (h *AuthHandler) WeixinLoginStatus(c *gin.Context) {
	transactionID := c.Query("transaction_id")
	if transactionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transaction"})
		return
	}
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, transactionID)
	var stateData weixinOAuthState
	if err := h.redisStore.Get(stateKey, &stateData); err != nil {
		c.JSON(http.StatusGone, gin.H{"status": "expired", "error": "二维码已失效，请刷新后重试"})
		return
	}
	if stateData.State != transactionID || stateData.Status != "completed" || stateData.UserID == "" {
		c.JSON(http.StatusOK, gin.H{"status": "pending"})
		return
	}
	user, err := h.accountAuth.GetUserByID(stateData.UserID)
	if err != nil {
		h.logger.Printf("Failed to resolve completed WeChat QR user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "微信登录暂时不可用"})
		return
	}
	if err := h.redisStore.Delete(stateKey); err != nil {
		h.logger.Printf("Failed to consume WeChat QR session: %v", err)
	}
	h.completeBrowserLoginWithProvider(c, user, "", "weixin")
}

func renderWeixinCallbackPage(c *gin.Context, success bool, message string) {
	title := "微信登录未完成"
	color := "#b5473c"
	if success {
		title = "微信登录成功"
		color = "#078b5b"
	}
	body := fmt.Sprintf(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title></head><body style="margin:0;background:#f5f8fa;color:#173a57;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif"><main style="min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box"><section style="width:min(420px,100%%);padding:36px 28px;background:#fff;border-radius:12px;text-align:center;box-shadow:0 12px 40px rgba(24,58,87,.12)"><div style="font-size:44px;color:%s">%s</div><h1 style="font-size:24px">%s</h1><p style="color:#6c8293;line-height:1.7">%s</p></section></main></body></html>`, title, color, map[bool]string{true: "&#10003;", false: "!"}[success], title, message)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(body))
}
