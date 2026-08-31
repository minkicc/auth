package auth

import "testing"

func TestAliyunSendSMSRequestUsesDomesticSMSAPI(t *testing.T) {
	request := newAliyunSendSMSRequest()
	if request.GetProduct() != "Dysmsapi" {
		t.Fatalf("unexpected product: %s", request.GetProduct())
	}
	if request.GetVersion() != "2017-05-25" {
		t.Fatalf("unexpected API version: %s", request.GetVersion())
	}
	if request.GetActionName() != "SendSms" {
		t.Fatalf("unexpected action: %s", request.GetActionName())
	}
}
