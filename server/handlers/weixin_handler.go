/*
 * Licensed under the MIT License.
 */

package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	ReturnURI      string `json:"return_uri,omitempty"`
}

const weixinQRSessionTTL = 10 * time.Minute

// WeixinLoginURL Get WeChat login URL
func (h *AuthHandler) WeixinLoginURL(c *gin.Context) {
	if h.weixinLogin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "WeChat login is not enabled"})
		return
	}

	state := uuid.New().String()
	clientID := uuid.New().String()
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, clientID)
	stateData := weixinOAuthState{
		State:          state,
		ClientID:       c.Query("client_id"),
		InvitationCode: c.Query("invitation_code"),
		ReturnURI:      h.weixinReturnURI(c.Query("client_id"), c.Query("redirect_uri")),
	}

	if err := h.redisStore.Set(stateKey, stateData, weixinQRSessionTTL); err != nil {
		h.logger.Printf("Failed to save OAuth state to Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	setLaxCookie(c, "weixin_client_id", clientID, int(weixinQRSessionTTL/time.Second), "/", "", h.browserSessionCookieSecure(c), true)
	c.JSON(http.StatusOK, gin.H{
		"url": h.weixinLogin.GetAuthURL(state),
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

	clientID, err := c.Cookie("weixin_client_id")
	if err != nil || clientID == "" {
		h.logger.Printf("Failed to get WeChat login cookie: %v", err)
		renderWeixinCallbackPage(c, false, "登录状态无效，请返回登录页重试")
		return
	}
	stateKey := fmt.Sprintf("%s%s", common.RedisKeyWeixinState, clientID)
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
	if err := h.redisStore.Delete(stateKey); err != nil {
		h.logger.Printf("Failed to clear WeChat OAuth state: %v", err)
	}
	setLaxCookie(c, "weixin_client_id", "", -1, "/", "", h.browserSessionCookieSecure(c), true)

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
	h.completeBrowserLoginWithProviderRedirect(c, user, "weixin", stateData.ReturnURI)
}

func (h *AuthHandler) weixinReturnURI(clientID, returnURI string) string {
	returnURI = strings.TrimSpace(returnURI)
	if returnURI == "" || clientID == "" || h.publicBaseURL() == "" {
		return ""
	}

	parsed, err := url.Parse(returnURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	base, err := url.Parse(h.publicBaseURL())
	if err != nil || parsed.Scheme != base.Scheme || parsed.Host != base.Host {
		return ""
	}
	if strings.TrimRight(parsed.Path, "/") != "/oauth2/authorize" || parsed.Query().Get("client_id") != clientID {
		return ""
	}
	return parsed.String()
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
