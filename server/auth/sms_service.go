/*
 * Licensed under the MIT License.
 */

package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/dysmsapi"
)

// SMS Configuration
type SMSConfig struct {
	Provider   string // SMS service provider, such as "aliyun", "tencent", etc.
	AccessKey  string // Access key
	SecretKey  string // Secret key
	SignName   string // SMS signature
	TemplateID string // Template ID
	Region     string // Region
}

// Default SMS Service implementation
type DefaultSMSService struct {
	config SMSConfig
}

// Create a new SMS service
func NewSMSService(config SMSConfig) SMSService {
	return &DefaultSMSService{
		config: config,
	}
}

// Send verification code SMS
func (s *DefaultSMSService) SendVerificationSMS(phone, code string) error {
	// In a real project, this should call the SMS API to send a message
	// Example implementation, only logs metadata
	log.Printf("Sending verification code SMS to %s", phone)

	// Can be integrated with different SMS providers
	switch s.config.Provider {
	case "aliyun":
		// Call Aliyun SMS API
		return s.sendAliyunSMS(phone, code, "Verification Code")
	case "tencent":
		// Call Tencent Cloud SMS API
		return s.sendTencentSMS(phone, code, "Verification Code")
	default:
		// Default to log metadata only
		log.Printf("[SMS Service] Verification SMS: Phone=%s", phone)
		return nil
	}
}

// Send password reset SMS
func (s *DefaultSMSService) SendPasswordResetSMS(phone, code string) error {
	// Example implementation, only logs metadata
	log.Printf("Sending password reset SMS to %s", phone)

	switch s.config.Provider {
	case "aliyun":
		// Call Aliyun SMS API
		return s.sendAliyunSMS(phone, code, "Password Reset")
	case "tencent":
		// Call Tencent Cloud SMS API
		return s.sendTencentSMS(phone, code, "Password Reset")
	default:
		// Default to log metadata only
		log.Printf("[SMS Service] Password reset SMS: Phone=%s", phone)
		return nil
	}
}

// Send login notification SMS
func (s *DefaultSMSService) SendLoginNotificationSMS(phone, ip string) error {
	// Example implementation, only logs
	log.Printf("Sending login notification SMS to %s, IP: %s", phone, ip)

	switch s.config.Provider {
	case "aliyun":
		// Call Aliyun SMS API
		return s.sendAliyunSMS(phone, ip, "Login Notification")
	case "tencent":
		// Call Tencent Cloud SMS API
		return s.sendTencentSMS(phone, ip, "Login Notification")
	default:
		// Default to log
		log.Printf("[SMS Service] Login notification SMS: Phone=%s, IP=%s", phone, ip)
		return nil
	}
}

// Aliyun SMS API integration example
func (s *DefaultSMSService) sendAliyunSMS(phone, content, smsType string) error {
	if strings.TrimSpace(s.config.AccessKey) == "" || strings.TrimSpace(s.config.SecretKey) == "" {
		return fmt.Errorf("aliyun SMS requires access_key and secret_key")
	}
	if strings.TrimSpace(s.config.SignName) == "" || strings.TrimSpace(s.config.TemplateID) == "" {
		return fmt.Errorf("aliyun SMS requires sign_name and template_id")
	}
	region := strings.TrimSpace(s.config.Region)
	if region == "" {
		region = "cn-hangzhou"
	}
	client, err := dysmsapi.NewClientWithAccessKey(region, s.config.AccessKey, s.config.SecretKey)
	if err != nil {
		return fmt.Errorf("initialize aliyun SMS client: %w", err)
	}
	params, err := json.Marshal(map[string]string{"code": content})
	if err != nil {
		return fmt.Errorf("encode aliyun SMS template params: %w", err)
	}
	request := dysmsapi.CreateSendMessageWithTemplateRequest()
	request.Scheme = "https"
	request.To = strings.TrimPrefix(strings.TrimSpace(phone), "+86")
	request.TemplateCode = s.config.TemplateID
	request.TemplateParam = string(params)
	request.From = s.config.SignName
	response, err := client.SendMessageWithTemplate(request)
	if err != nil {
		return fmt.Errorf("send aliyun %s SMS: %w", smsType, err)
	}
	if response == nil || response.ResponseCode != "OK" {
		if response == nil {
			return fmt.Errorf("send aliyun %s SMS: empty response", smsType)
		}
		return fmt.Errorf("send aliyun %s SMS failed: code=%s message=%s", smsType, response.ResponseCode, response.ResponseDescription)
	}
	log.Printf("[Aliyun SMS] sent %s SMS to %s, message_id=%s", smsType, phone, response.MessageId)
	return nil
}

// Tencent Cloud SMS API integration example
func (s *DefaultSMSService) sendTencentSMS(phone, content, smsType string) error {
	// In a real project, this should integrate the Tencent Cloud SMS SDK
	// This is just a placeholder example
	log.Printf("[Tencent Cloud SMS] Sending %s SMS to %s", smsType, phone)

	// Actual implementation code example:
	/*
		credential := common.NewCredential(s.config.AccessKey, s.config.SecretKey)
		client, err := sms.NewClient(credential, s.config.Region, clientProfile)
		if err != nil {
			return err
		}

		request := sms.NewSendSmsRequest()
		request.PhoneNumberSet = []*string{&phone}
		request.TemplateID = &s.config.TemplateID
		request.SmsSdkAppId = &s.config.SdkAppID
		request.SignName = &s.config.SignName
		request.TemplateParamSet = []*string{&content}

		response, err := client.SendSms(request)
		if err != nil {
			return err
		}

		if response.Response.SendStatusSet[0].Code != "Ok" {
			return fmt.Errorf("Failed to send SMS: %s", *response.Response.SendStatusSet[0].Message)
		}
	*/

	return nil
}
