package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

func TestDiscoverEnterpriseProvidersIncludesSAML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open("file:enterprise-saml-handler-discover?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}
	if err := db.Create(&iam.Organization{
		OrganizationID: "org_acme000000000000",
		Slug:           "acme",
		Name:           "Acme Inc",
		Status:         iam.OrganizationStatusActive,
	}).Error; err != nil {
		t.Fatalf("failed to create organization: %v", err)
	}
	if err := db.Create(&iam.OrganizationDomain{
		Domain:         "example.com",
		OrganizationID: "org_acme000000000000",
		Verified:       true,
	}).Error; err != nil {
		t.Fatalf("failed to create organization domain: %v", err)
	}

	manager := newTestEnterpriseSAMLManager(t, db)
	h := &AuthHandler{enterpriseSAML: manager}
	router := gin.New()
	router.GET("/enterprise/discover", h.DiscoverEnterpriseProviders)

	req := httptest.NewRequest(http.MethodGet, "/enterprise/discover?email=user@example.com", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	var body iam.EnterpriseOIDCDiscoveryResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode discovery response: %v", err)
	}
	if body.Status != iam.EnterpriseOIDCDiscoveryMatched || len(body.Providers) != 1 || body.Providers[0].ProviderType != "saml" {
		t.Fatalf("unexpected discovery body: %#v", body)
	}
}

func TestEnterpriseSAMLLoginRedirectsToIdentityProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open("file:enterprise-saml-handler-login?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer redisServer.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	defer redisClient.Close()
	redisStore := auth.NewRedisStoreFromClient(redisClient)

	manager := newTestEnterpriseSAMLManager(t, db)
	h := &AuthHandler{
		enterpriseSAML: manager,
		redisStore:     redisStore,
		config: &config.Config{
			OIDC: config.OIDCConfig{Issuer: "https://auth.example.com"},
		},
	}
	router := gin.New()
	router.GET("/enterprise/saml/:slug/login", h.EnterpriseSAMLLogin)

	req := httptest.NewRequest(http.MethodGet, "/enterprise/saml/acme-saml/login?return_uri=/profile", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "https://idp.example.com/sso?") {
		t.Fatalf("expected redirect to idp sso endpoint, got %q", location)
	}
}

func newTestEnterpriseSAMLManager(t *testing.T, db *gorm.DB) *iam.EnterpriseSAMLManager {
	t.Helper()

	metadataXML := string(testEnterpriseSAMLMetadataXML(t))
	manager, err := iam.NewEnterpriseSAMLManager(config.IAMConfig{
		EnterpriseSAML: []config.EnterpriseSAMLProviderConfig{{
			Slug:           "acme-saml",
			Name:           "Acme SAML",
			OrganizationID: "org_acme000000000000",
			IDPMetadataXML: metadataXML,
		}},
	}, "https://auth.example.com", db, nil)
	if err != nil {
		t.Fatalf("failed to create enterprise saml manager: %v", err)
	}
	return manager
}

func testEnterpriseSAMLMetadataXML(t *testing.T) []byte {
	t.Helper()

	key, cert := testEnterpriseSAMLKeyPair(t)
	idp := saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustParseEnterpriseSAMLURL(t, "https://idp.example.com/metadata"),
		SSOURL:      mustParseEnterpriseSAMLURL(t, "https://idp.example.com/sso"),
	}
	metadataXML, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatalf("failed to marshal idp metadata: %v", err)
	}
	return metadataXML
}

func testEnterpriseSAMLKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "enterprise-saml-handler-test",
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

func mustParseEnterpriseSAMLURL(t *testing.T, raw string) url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse url %q: %v", raw, err)
	}
	return *parsed
}
