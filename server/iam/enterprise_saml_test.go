package iam

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

func TestEnterpriseSAMLManagerLoadsDatabaseProviders(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:enterprise-saml-db-load?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	configJSON, err := xmlConfigJSON(config.EnterpriseSAMLProviderConfig{
		IDPMetadataXML: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"></EntityDescriptor>`,
	})
	if err != nil {
		t.Fatalf("failed to marshal saml config: %v", err)
	}
	if err := db.Create(&OrganizationIdentityProvider{
		IdentityProviderID: "idp_acme1234567890",
		OrganizationID:     "org_acme000000000000",
		ProviderType:       IdentityProviderTypeSAML,
		Name:               "Acme SAML",
		Slug:               "acme-saml",
		Enabled:            true,
		ConfigJSON:         string(configJSON),
	}).Error; err != nil {
		t.Fatalf("failed to create organization identity provider: %v", err)
	}

	manager, err := NewEnterpriseSAMLManager(config.IAMConfig{}, "https://auth.example.com", db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise saml manager: %v", err)
	}
	if !manager.HasProviders() {
		t.Fatalf("expected database-backed provider to be loaded")
	}
	providers := manager.Providers()
	if len(providers) != 1 || providers[0].Slug != "acme-saml" || providers[0].ProviderType != "saml" {
		t.Fatalf("unexpected providers: %#v", providers)
	}
}

func TestEnterpriseSAMLAuthenticateCreatesUserAndExternalIdentity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:enterprise-saml-auth?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.User{}, &auth.EmailUser{}); err != nil {
		t.Fatalf("failed to migrate auth tables: %v", err)
	}
	if err := NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	key, cert := newTestSAMLKeyPair(t)
	var serviceProviderMetadata *saml.EntityDescriptor
	idp := saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustParseSAMLURL(t, "https://idp.example.com/metadata"),
		SSOURL:      mustParseSAMLURL(t, "https://idp.example.com/sso"),
		ServiceProviderProvider: staticServiceProviderProvider{
			GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
				if serviceProviderMetadata != nil && serviceProviderID == serviceProviderMetadata.EntityID {
					return serviceProviderMetadata, nil
				}
				return nil, os.ErrNotExist
			},
		},
		SessionProvider: staticSessionProvider{
			Session: &saml.Session{
				ID:             "session-1",
				CreateTime:     time.Now().Add(-time.Minute),
				ExpireTime:     time.Now().Add(time.Hour),
				Index:          "session-index-1",
				NameID:         "saml-user-1",
				NameIDFormat:   string(saml.PersistentNameIDFormat),
				UserEmail:      "user@example.com",
				UserCommonName: "SAML User",
				UserName:       "saml.user",
			},
		},
	}
	metadataXML, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatalf("failed to marshal idp metadata: %v", err)
	}

	manager, err := NewEnterpriseSAMLManager(config.IAMConfig{
		EnterpriseSAML: []config.EnterpriseSAMLProviderConfig{{
			Slug:                 "acme-saml",
			Name:                 "Acme SAML",
			OrganizationID:       "org_acme000000000000",
			IDPMetadataXML:       string(metadataXML),
			NameIDFormat:         string(saml.PersistentNameIDFormat),
			EmailAttribute:       "mail",
			DisplayNameAttribute: "cn",
			UsernameAttribute:    "uid",
		}},
	}, "https://auth.example.com", db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise saml manager: %v", err)
	}

	provider, ok := manager.provider("acme-saml")
	if !ok {
		t.Fatalf("expected provider to be loaded")
	}
	serviceProviderMetadata = provider.sp.Metadata()

	flow, err := manager.StartAuthFlow("acme-saml", "relay-state-1")
	if err != nil {
		t.Fatalf("failed to start saml auth flow: %v", err)
	}
	if flow.RequestID == "" || flow.RedirectURL == "" {
		t.Fatalf("unexpected saml auth flow: %#v", flow)
	}

	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodGet, flow.RedirectURL, nil)
	if err != nil {
		t.Fatalf("failed to create idp request: %v", err)
	}
	idp.ServeSSO(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected idp sso 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	form := url.Values{}
	form.Set("RelayState", hiddenInputValue(t, recorder.Body.String(), "RelayState"))
	form.Set("SAMLResponse", hiddenInputValue(t, recorder.Body.String(), "SAMLResponse"))
	acsRequest := httptest.NewRequest(http.MethodPost, provider.sp.AcsURL.String(), strings.NewReader(form.Encode()))
	acsRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	user, err := manager.Authenticate(acsRequest, "acme-saml", []string{flow.RequestID})
	if err != nil {
		t.Fatalf("failed to authenticate enterprise saml user: %T %v", err, err)
	}
	if !strings.HasPrefix(user.UserID, auth.UserIDPrefix) {
		t.Fatalf("expected internal user ID, got %q", user.UserID)
	}
	if user.Nickname != "SAML User" {
		t.Fatalf("expected nickname from SAML profile, got %q", user.Nickname)
	}

	var identity ExternalIdentity
	if err := db.First(&identity, "provider_type = ? AND provider_id = ? AND subject = ?", IdentityProviderTypeSAML, "acme-saml", "saml-user-1").Error; err != nil {
		t.Fatalf("failed to load external identity: %v", err)
	}
	if identity.UserID != user.UserID {
		t.Fatalf("expected identity user %s, got %s", user.UserID, identity.UserID)
	}
	if identity.Email != "user@example.com" || !identity.EmailVerified {
		t.Fatalf("expected normalized verified email, got %q verified=%v", identity.Email, identity.EmailVerified)
	}

	var membership OrganizationMembership
	if err := db.First(&membership, "organization_id = ? AND user_id = ?", "org_acme000000000000", user.UserID).Error; err != nil {
		t.Fatalf("expected organization membership: %v", err)
	}
}

func xmlConfigJSON(cfg config.EnterpriseSAMLProviderConfig) ([]byte, error) {
	return json.Marshal(cfg)
}

func newTestSAMLKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "enterprise-saml-test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return privateKey, certificate
}

func mustParseSAMLURL(t *testing.T, raw string) url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse url %q: %v", raw, err)
	}
	return *parsed
}

type staticServiceProviderProvider struct {
	GetServiceProviderFunc func(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error)
}

func (s staticServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	return s.GetServiceProviderFunc(r, serviceProviderID)
}

type staticSessionProvider struct {
	Session *saml.Session
}

func (s staticSessionProvider) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return s.Session
}

func hiddenInputValue(t *testing.T, body, name string) string {
	t.Helper()

	pattern := regexp.MustCompile(fmt.Sprintf(`name="%s"\s+value="([^"]+)"`, regexp.QuoteMeta(name)))
	matches := pattern.FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("expected hidden input %s in body %q", name, body)
	}
	return html.UnescapeString(matches[1])
}
