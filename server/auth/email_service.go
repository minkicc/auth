/*
 * Copyright (c) 2025 Open Source Contributors (https://example.com)
 * Licensed under the MIT License.
 */

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"time"
)

var htmlTagPattern = regexp.MustCompile(`<[^>]+>`)

// SmtpConfig Email Configuration
type SmtpConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// BaseURL  string // Used to generate verification links
}

// CloudflareEmailConfig configures Cloudflare Email Service.
type CloudflareEmailConfig struct {
	AccountID   string
	APIToken    string
	APITokenEnv string
	From        string
	Endpoint    string
	Timeout     time.Duration
}

// EmailServiceImpl Email service implementation
type EmailServiceImpl struct {
	config SmtpConfig
}

type CloudflareEmailService struct {
	config CloudflareEmailConfig
	client *http.Client
}

// NewEmailService Create a new email service instance
func NewEmailService(config SmtpConfig) EmailService {
	return &EmailServiceImpl{
		config: config,
	}
}

// NewCloudflareEmailService creates a Cloudflare Email Service sender.
func NewCloudflareEmailService(config CloudflareEmailConfig) (EmailService, error) {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if strings.TrimSpace(config.Endpoint) == "" {
		config.Endpoint = "https://api.cloudflare.com/client/v4"
	}
	if strings.TrimSpace(config.AccountID) == "" {
		return nil, fmt.Errorf("cloudflare email account_id is required")
	}
	if strings.TrimSpace(config.From) == "" {
		return nil, fmt.Errorf("cloudflare email from is required")
	}
	if strings.TrimSpace(config.effectiveAPIToken()) == "" {
		return nil, fmt.Errorf("cloudflare email api_token is required")
	}

	return &CloudflareEmailService{
		config: config,
		client: &http.Client{Timeout: config.Timeout},
	}, nil
}

// SendVerificationEmail Send verification email
func (s *EmailServiceImpl) SendVerificationEmail(email, token, title, content string) error {
	content = normalizeEmailTemplatePlaceholders(content)
	data := struct {
		Token string
		Code  string
	}{
		Token: token,
		Code:  token,
	}
	return s.sendEmail(email, title, content, data)
}

// SendLoginCodeEmail Send login verification code email.
func (s *EmailServiceImpl) SendLoginCodeEmail(email, code, title, content string) error {
	data := struct {
		Token string
		Code  string
	}{
		Token: code,
		Code:  code,
	}
	return s.sendEmail(email, title, content, data)
}

// SendPasswordResetEmail Send password reset email
func (s *EmailServiceImpl) SendPasswordResetEmail(email, token, title, content string) error {
	content = normalizeEmailTemplatePlaceholders(content)
	data := struct {
		// BaseURL string
		Token string
		Code  string
	}{
		// BaseURL: s.config.BaseURL,
		Token: token,
		Code:  token,
	}
	return s.sendEmail(email, title, content, data)
}

// SendLoginNotificationEmail Send login notification email
func (s *EmailServiceImpl) SendLoginNotificationEmail(email, ip, title, content string) error {
	data := struct {
		Ip   string
		Time string
	}{
		Ip:   ip,
		Time: time.Now().Format("2006-01-02 15:04:05"),
	}
	return s.sendEmail(email, title, content, data)
}

func (c CloudflareEmailConfig) effectiveAPIToken() string {
	if token := strings.TrimSpace(c.APIToken); token != "" {
		return token
	}
	if envName := strings.TrimSpace(c.APITokenEnv); envName != "" {
		return strings.TrimSpace(os.Getenv(envName))
	}
	return ""
}

func (s *CloudflareEmailService) SendVerificationEmail(email, token, title, content string) error {
	content = normalizeEmailTemplatePlaceholders(content)
	data := struct {
		Token string
		Code  string
	}{
		Token: token,
		Code:  token,
	}
	return s.sendEmail(context.Background(), email, title, content, data)
}

func (s *CloudflareEmailService) SendLoginCodeEmail(email, code, title, content string) error {
	data := struct {
		Token string
		Code  string
	}{
		Token: code,
		Code:  code,
	}
	return s.sendEmail(context.Background(), email, title, content, data)
}

func (s *CloudflareEmailService) SendPasswordResetEmail(email, token, title, content string) error {
	content = normalizeEmailTemplatePlaceholders(content)
	data := struct {
		Token string
		Code  string
	}{
		Token: token,
		Code:  token,
	}
	return s.sendEmail(context.Background(), email, title, content, data)
}

func (s *CloudflareEmailService) SendLoginNotificationEmail(email, ip, title, content string) error {
	data := struct {
		Ip   string
		Time string
	}{
		Ip:   ip,
		Time: time.Now().Format("2006-01-02 15:04:05"),
	}
	return s.sendEmail(context.Background(), email, title, content, data)
}

func (s *CloudflareEmailService) sendEmail(ctx context.Context, to, subject, tplStr string, data interface{}) error {
	tpl, err := template.New("email").Parse(tplStr)
	if err != nil {
		return err
	}

	var body bytes.Buffer
	if err := tpl.Execute(&body, data); err != nil {
		return err
	}

	fromEmail, _ := splitDisplayEmail(s.config.From)
	htmlBody := body.String()

	payload := map[string]interface{}{
		"to":      to,
		"from":    fromEmail,
		"subject": subject,
		"html":    htmlBody,
		"text":    stripHTMLForText(htmlBody),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint := strings.TrimRight(s.config.Endpoint, "/")
	url := fmt.Sprintf("%s/accounts/%s/email/sending/send", endpoint, strings.TrimSpace(s.config.AccountID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.config.effectiveAPIToken())
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("cloudflare email send failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &parsed); err == nil && !parsed.Success {
		if len(parsed.Errors) > 0 {
			return fmt.Errorf("cloudflare email send failed: %s", parsed.Errors[0].Message)
		}
		return fmt.Errorf("cloudflare email send failed")
	}

	return nil
}

// sendEmail General method for sending emails
func (s *EmailServiceImpl) sendEmail(to, subject, tplStr string, data interface{}) error {
	// Parse template
	tpl, err := template.New("email").Parse(tplStr)
	if err != nil {
		return err
	}

	// Render template
	var body bytes.Buffer
	if err := tpl.Execute(&body, data); err != nil {
		return err
	}

	fromEmail, fromHeader := splitDisplayEmail(s.config.From)
	msg := []byte(buildHTMLMessage(fromHeader, to, subject, body.String()))

	// Send email
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	return smtp.SendMail(addr, auth, fromEmail, []string{to}, msg)
}

func splitDisplayEmail(from string) (string, string) {
	from = strings.TrimSpace(from)
	fromEmail := from
	if idx := strings.LastIndex(fromEmail, "<"); idx >= 0 {
		if end := strings.LastIndex(fromEmail, ">"); end > idx {
			fromEmail = fromEmail[idx+1 : end]
		}
	}
	return strings.TrimSpace(fromEmail), from
}

func buildHTMLMessage(from, to, subject, body string) string {
	return fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n%s", to, from, subject, body)
}

func normalizeEmailTemplatePlaceholders(content string) string {
	replacer := strings.NewReplacer(
		"%3C%25Token%25%3E", "{{.Token}}",
		"%3c%25Token%25%3e", "{{.Token}}",
		"%3C%25Code%25%3E", "{{.Code}}",
		"%3c%25Code%25%3e", "{{.Code}}",
	)
	return replacer.Replace(content)
}

func stripHTMLForText(input string) string {
	text := htmlTagPattern.ReplaceAllString(input, " ")
	return strings.Join(strings.Fields(text), " ")
}
