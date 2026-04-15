/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	defaultIssuer       = "http://127.0.0.1:8080"
	defaultClientID     = "demo-backend"
	defaultClientSecret = "demo-backend-secret"
	defaultRedirectURL  = "http://127.0.0.1:8082/auth/callback"
	defaultListenAddr   = ":8082"
	sessionCookieName   = "mkauth_example_session"
	sessionTTL          = 12 * time.Hour
)

type appConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	ListenAddr   string
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type sessionData struct {
	ID           string
	State        string
	Nonce        string
	CodeVerifier string
	AccessToken  string
	IDToken      string
	TokenExpiry  time.Time
	IDClaims     map[string]any
	UserInfo     map[string]any
	UpdatedAt    time.Time
}

type sessionStore struct {
	mu    sync.Mutex
	items map[string]*sessionData
}

type exampleApp struct {
	cfg        appConfig
	discovery  discoveryDocument
	oauth2     oauth2.Config
	provider   *oidc.Provider
	idVerifier *oidc.IDTokenVerifier
	sessions   *sessionStore
}

type pageData struct {
	Config             appConfig
	Discovery          discoveryDocument
	LoggedIn           bool
	HasSession         bool
	Error              string
	AccessToken        string
	IDToken            string
	TokenExpiry        string
	IDClaimsPretty     string
	UserInfoPretty     string
	PostLogoutRedirect string
}

var pageTemplate = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MKAuth Go OIDC BFF Example</title>
  <style>
    :root {
      --bg: #f4efe6;
      --panel: rgba(255, 250, 244, 0.95);
      --ink: #18222f;
      --muted: #5b6978;
      --accent: #1f6b8f;
      --accent-2: #b9522c;
      --line: rgba(24, 34, 47, 0.12);
      --shadow: 0 18px 42px rgba(24, 34, 47, 0.12);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(31, 107, 143, 0.16), transparent 24%),
        radial-gradient(circle at top right, rgba(185, 82, 44, 0.16), transparent 22%),
        linear-gradient(180deg, #f8f2e9 0%, var(--bg) 100%);
    }

    .shell {
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 18px 40px;
    }

    .hero, .grid {
      display: grid;
      gap: 18px;
    }

    .hero {
      grid-template-columns: 1.4fr 1fr;
      margin-bottom: 18px;
    }

    .grid {
      grid-template-columns: 1fr 1fr;
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 22px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }

    .pill {
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(31, 107, 143, 0.11);
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    h1 {
      margin: 14px 0 10px;
      font-size: clamp(30px, 4vw, 54px);
      line-height: 0.95;
    }

    h2 {
      margin: 0 0 14px;
      font-size: 18px;
    }

    p, li {
      color: var(--muted);
      line-height: 1.65;
    }

    ul {
      margin: 0;
      padding-left: 18px;
    }

    code {
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 0.94em;
      background: rgba(24, 34, 47, 0.06);
      padding: 2px 6px;
      border-radius: 8px;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 16px;
    }

    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 11px 16px;
      border-radius: 999px;
      text-decoration: none;
      font-weight: 600;
      transition: transform 0.16s ease, opacity 0.16s ease;
    }

    .button:hover {
      transform: translateY(-1px);
      opacity: 0.96;
    }

    .button-primary {
      background: var(--accent);
      color: #f8fbff;
    }

    .button-secondary {
      background: rgba(24, 34, 47, 0.08);
      color: var(--ink);
    }

    .button-danger {
      background: rgba(185, 82, 44, 0.12);
      color: var(--accent-2);
    }

    .status {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(185, 82, 44, 0.1);
      color: var(--accent-2);
      font-weight: 600;
    }

    .kv {
      display: grid;
      gap: 10px;
    }

    .kv div {
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(24, 34, 47, 0.04);
      color: var(--muted);
    }

    .kv strong {
      display: block;
      color: var(--ink);
      margin-bottom: 4px;
    }

    pre {
      margin: 0;
      padding: 16px;
      border-radius: 18px;
      background: #16202a;
      color: #eef4fa;
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      font-size: 13px;
      line-height: 1.55;
      white-space: pre-wrap;
      word-break: break-word;
      overflow-x: auto;
    }

    @media (max-width: 980px) {
      .hero, .grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <article class="card">
        <span class="pill">Confidential Client / BFF Example</span>
        <h1>MKAuth OIDC backend callback flow for Go services.</h1>
        <p>
          This example keeps the OIDC code exchange on the backend. It discovers the provider,
          starts <code>Authorization Code + PKCE</code>, validates the returned <code>id_token</code>,
          fetches <code>/oauth2/userinfo</code>, and stores the login state in a local server-side session.
        </p>
        <p>
          The session implementation is intentionally simple and memory-backed so the flow stays easy to read.
          For production, move sessions to Redis or another shared store and put the app behind HTTPS.
        </p>
        <div class="actions">
          <a class="button button-primary" href="/login">Login With MKAuth</a>
          <a class="button button-secondary" href="/">Refresh Page</a>
          <a class="button button-danger" href="/logout">Logout</a>
        </div>
        {{ if .Error }}
        <div class="status">{{ .Error }}</div>
        {{ end }}
      </article>

      <aside class="card">
        <h2>Runtime Config</h2>
        <div class="kv">
          <div><strong>Issuer</strong><code>{{ .Config.Issuer }}</code></div>
          <div><strong>Client ID</strong><code>{{ .Config.ClientID }}</code></div>
          <div><strong>Redirect URL</strong><code>{{ .Config.RedirectURL }}</code></div>
          <div><strong>Post-logout Redirect</strong><code>{{ .PostLogoutRedirect }}</code></div>
          <div><strong>Session Present</strong>{{ .HasSession }}</div>
          <div><strong>Logged In</strong>{{ .LoggedIn }}</div>
          <div><strong>Token Expiry</strong>{{ .TokenExpiry }}</div>
        </div>
      </aside>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Discovery Metadata</h2>
        <pre>{{ .Discovery.Issuer }}
authorization_endpoint: {{ .Discovery.AuthorizationEndpoint }}
token_endpoint: {{ .Discovery.TokenEndpoint }}
userinfo_endpoint: {{ .Discovery.UserInfoEndpoint }}
jwks_uri: {{ .Discovery.JWKSURI }}
end_session_endpoint: {{ .Discovery.EndSessionEndpoint }}</pre>
      </article>

      <article class="card">
        <h2>Why This Example Exists</h2>
        <ul>
          <li>It demonstrates the recommended OIDC-first integration path on this branch.</li>
          <li>It avoids the removed legacy <code>/api/login/verify</code> flow entirely.</li>
          <li>It shows that browser apps with a backend can keep the code exchange off the frontend.</li>
          <li>It uses <code>/oauth2/userinfo</code> for profile data, which is the standard OIDC path.</li>
        </ul>
      </article>

      <article class="card">
        <h2>Access Token</h2>
        <pre>{{ .AccessToken }}</pre>
      </article>

      <article class="card">
        <h2>ID Token</h2>
        <pre>{{ .IDToken }}</pre>
      </article>

      <article class="card">
        <h2>ID Token Claims</h2>
        <pre>{{ .IDClaimsPretty }}</pre>
      </article>

      <article class="card">
        <h2>UserInfo</h2>
        <pre>{{ .UserInfoPretty }}</pre>
      </article>
    </section>
  </div>
</body>
</html>`))

func main() {
	cfg := loadConfig()
	app, err := newExampleApp(context.Background(), cfg)
	if err != nil {
		log.Fatalf("failed to initialize example app: %v", err)
	}

	r := gin.Default()
	r.GET("/", app.index)
	r.GET("/login", app.login)
	r.GET("/auth/callback", app.callback)
	r.GET("/logout", app.logout)

	log.Printf("MKAuth OIDC BFF example listening on %s", cfg.ListenAddr)
	log.Printf("Open %s in your browser", displayBaseURL(cfg.ListenAddr))
	if err := r.Run(cfg.ListenAddr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func newExampleApp(ctx context.Context, cfg appConfig) (*exampleApp, error) {
	discovery, err := fetchDiscovery(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &exampleApp{
		cfg:       cfg,
		discovery: discovery,
		oauth2:    oauthConfig,
		provider:  provider,
		idVerifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		}),
		sessions: newSessionStore(),
	}, nil
}

func (a *exampleApp) index(c *gin.Context) {
	session, _ := a.currentSession(c, false)
	data := pageData{
		Config:             a.cfg,
		Discovery:          a.discovery,
		Error:              strings.TrimSpace(c.Query("error")),
		PostLogoutRedirect: a.postLogoutRedirectURL(),
		HasSession:         session != nil,
	}

	if session != nil {
		data.AccessToken = valueOrPlaceholder(session.AccessToken)
		data.IDToken = valueOrPlaceholder(session.IDToken)
		data.TokenExpiry = session.TokenExpiry.Format(time.RFC3339)
		data.IDClaimsPretty = prettyJSON(session.IDClaims)
		data.UserInfoPretty = prettyJSON(session.UserInfo)
		data.LoggedIn = session.AccessToken != "" && session.IDToken != ""
	}
	if data.AccessToken == "" {
		data.AccessToken = "No access token yet."
	}
	if data.IDToken == "" {
		data.IDToken = "No ID token yet."
	}
	if data.IDClaimsPretty == "" {
		data.IDClaimsPretty = "No ID token claims yet."
	}
	if data.UserInfoPretty == "" {
		data.UserInfoPretty = "No userinfo response yet."
	}
	if data.TokenExpiry == "" || data.TokenExpiry == "0001-01-01T00:00:00Z" {
		data.TokenExpiry = "Not logged in"
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(c.Writer, data); err != nil {
		c.String(http.StatusInternalServerError, "template error: %v", err)
	}
}

func (a *exampleApp) login(c *gin.Context) {
	session, err := a.currentSession(c, true)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape(err.Error()))
		return
	}

	state, err := randomString(32)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape(err.Error()))
		return
	}
	nonce, err := randomString(32)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape(err.Error()))
		return
	}
	verifier, err := randomString(64)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape(err.Error()))
		return
	}
	challenge := pkceChallenge(verifier)

	session.State = state
	session.Nonce = nonce
	session.CodeVerifier = verifier
	session.UpdatedAt = time.Now()
	a.sessions.put(session)

	authURL := a.oauth2.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	c.Redirect(http.StatusFound, authURL)
}

func (a *exampleApp) callback(c *gin.Context) {
	if errCode := c.Query("error"); errCode != "" {
		message := errCode
		if desc := c.Query("error_description"); desc != "" {
			message += ": " + desc
		}
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape(message))
		return
	}

	session, err := a.currentSession(c, false)
	if err != nil || session == nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("missing session; restart login"))
		return
	}

	if c.Query("state") != session.State {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("state mismatch"))
		return
	}

	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("missing authorization code"))
		return
	}

	token, err := a.oauth2.Exchange(
		c.Request.Context(),
		code,
		oauth2.SetAuthURLParam("code_verifier", session.CodeVerifier),
	)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("token exchange failed: "+err.Error()))
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("missing id_token in token response"))
		return
	}

	idToken, err := a.idVerifier.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("id_token verification failed: "+err.Error()))
		return
	}
	if idToken.Nonce != session.Nonce {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("nonce mismatch"))
		return
	}
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
			c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("access token hash verification failed: "+err.Error()))
			return
		}
	}

	var idClaims map[string]any
	if err := idToken.Claims(&idClaims); err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("failed to decode id_token claims: "+err.Error()))
		return
	}

	userInfo, err := a.provider.UserInfo(c.Request.Context(), oauth2.StaticTokenSource(token))
	if err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("userinfo request failed: "+err.Error()))
		return
	}
	var userInfoClaims map[string]any
	if err := userInfo.Claims(&userInfoClaims); err != nil {
		c.Redirect(http.StatusFound, "/?error="+url.QueryEscape("failed to decode userinfo claims: "+err.Error()))
		return
	}

	session.State = ""
	session.Nonce = ""
	session.CodeVerifier = ""
	session.AccessToken = token.AccessToken
	session.IDToken = rawIDToken
	session.IDClaims = idClaims
	session.UserInfo = userInfoClaims
	session.TokenExpiry = token.Expiry
	session.UpdatedAt = time.Now()
	a.sessions.put(session)

	c.Redirect(http.StatusFound, "/")
}

func (a *exampleApp) logout(c *gin.Context) {
	if session, _ := a.currentSession(c, false); session != nil {
		a.sessions.delete(session.ID)
	}
	clearSessionCookie(c, a.cookieSecure())

	if a.discovery.EndSessionEndpoint == "" {
		c.Redirect(http.StatusFound, "/")
		return
	}

	logoutURL, err := url.Parse(a.discovery.EndSessionEndpoint)
	if err != nil {
		c.Redirect(http.StatusFound, "/")
		return
	}
	values := logoutURL.Query()
	values.Set("client_id", a.cfg.ClientID)
	values.Set("post_logout_redirect_uri", a.postLogoutRedirectURL())
	logoutURL.RawQuery = values.Encode()

	c.Redirect(http.StatusFound, logoutURL.String())
}

func (a *exampleApp) currentSession(c *gin.Context, create bool) (*sessionData, error) {
	if sessionID, err := c.Cookie(sessionCookieName); err == nil && sessionID != "" {
		if session, ok := a.sessions.get(sessionID); ok {
			return session, nil
		}
		clearSessionCookie(c, a.cookieSecure())
	}
	if !create {
		return nil, nil
	}

	sessionID, err := randomString(32)
	if err != nil {
		return nil, err
	}
	session := &sessionData{
		ID:        sessionID,
		UpdatedAt: time.Now(),
	}
	a.sessions.put(session)
	c.SetCookie(sessionCookieName, sessionID, int(sessionTTL.Seconds()), "/", "", a.cookieSecure(), true)
	return session, nil
}

func (a *exampleApp) cookieSecure() bool {
	redirectURL, err := url.Parse(a.cfg.RedirectURL)
	if err != nil {
		return false
	}
	return redirectURL.Scheme == "https"
}

func (a *exampleApp) postLogoutRedirectURL() string {
	redirectURL, err := url.Parse(a.cfg.RedirectURL)
	if err != nil {
		return a.cfg.Issuer
	}
	redirectURL.Path = "/"
	redirectURL.RawQuery = ""
	redirectURL.Fragment = ""
	return redirectURL.String()
}

func newSessionStore() *sessionStore {
	return &sessionStore{items: make(map[string]*sessionData)}
}

func (s *sessionStore) get(id string) (*sessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.items[id]
	if !ok {
		return nil, false
	}
	if time.Since(session.UpdatedAt) > sessionTTL {
		delete(s.items, id)
		return nil, false
	}
	return session, true
}

func (s *sessionStore) put(session *sessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[session.ID] = session
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

func fetchDiscovery(ctx context.Context, issuer string) (discoveryDocument, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryDocument{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return discoveryDocument{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discoveryDocument{}, fmt.Errorf("discovery failed: %s", resp.Status)
	}

	var document discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		return discoveryDocument{}, err
	}
	return document, nil
}

func loadConfig() appConfig {
	return appConfig{
		Issuer:       envOrDefault("MKAUTH_ISSUER", defaultIssuer),
		ClientID:     envOrDefault("MKAUTH_CLIENT_ID", defaultClientID),
		ClientSecret: envOrDefault("MKAUTH_CLIENT_SECRET", defaultClientSecret),
		RedirectURL:  envOrDefault("MKAUTH_REDIRECT_URL", defaultRedirectURL),
		ListenAddr:   envOrDefault("LISTEN_ADDR", defaultListenAddr),
	}
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func displayBaseURL(listenAddr string) string {
	if strings.HasPrefix(listenAddr, ":") {
		return "http://127.0.0.1" + listenAddr
	}
	if strings.HasPrefix(listenAddr, "http://") || strings.HasPrefix(listenAddr, "https://") {
		return listenAddr
	}
	return "http://" + listenAddr
}

func randomString(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer)[:length], nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func prettyJSON(value any) string {
	if value == nil {
		return ""
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

func valueOrPlaceholder(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return value
}

func clearSessionCookie(c *gin.Context, secure bool) {
	c.SetCookie(sessionCookieName, "", -1, "/", "", secure, true)
}
