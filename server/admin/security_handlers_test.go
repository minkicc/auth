package admin

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
	"minki.cc/mkauth/server/secureconfig"
)

func TestSecurityHandlersResealManagedSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	oldCodec, err := secureconfig.New("old-secrets-key")
	if err != nil {
		t.Fatalf("failed to create old secure config codec: %v", err)
	}
	secureconfig.SetDefault(oldCodec)
	defer secureconfig.SetDefault(nil)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&oidc.ClientRecord{}); err != nil {
		t.Fatalf("failed to migrate oidc clients: %v", err)
	}
	if err := iam.NewService(db).AutoMigrate(); err != nil {
		t.Fatalf("failed to migrate iam tables: %v", err)
	}

	clientRecord, err := oidc.ClientRecordFromConfig(config.OIDCClientConfig{
		Name:         "Legacy API",
		ClientID:     "legacy-api",
		ClientSecret: "legacy-client-secret",
		RedirectURIs: []string{"https://api.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
	}, true)
	if err != nil {
		t.Fatalf("failed to create legacy oidc client record: %v", err)
	}
	if err := db.Create(&clientRecord).Error; err != nil {
		t.Fatalf("failed to store oidc client record: %v", err)
	}
	oldClientConfigJSON := clientRecord.ConfigJSON

	plainProviderConfig, err := json.Marshal(config.EnterpriseOIDCProviderConfig{
		Issuer:       "https://login.example.com",
		ClientID:     "enterprise-client",
		ClientSecret: "legacy-provider-secret",
		RedirectURI:  "https://auth.example.com/api/enterprise/oidc/legacy/callback",
		Scopes:       []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("failed to marshal plain provider config: %v", err)
	}
	providerRecord := iam.OrganizationIdentityProvider{
		IdentityProviderID: "idp_legacyprovider1",
		OrganizationID:     "org_acme0000000000",
		ProviderType:       iam.IdentityProviderTypeOIDC,
		Name:               "Legacy Workforce",
		Slug:               "legacy-workforce",
		Enabled:            true,
		ConfigJSON:         string(plainProviderConfig),
	}
	if err := db.Create(&providerRecord).Error; err != nil {
		t.Fatalf("failed to store provider record: %v", err)
	}

	rotatedCodec, err := secureconfig.New("new-secrets-key", "old-secrets-key")
	if err != nil {
		t.Fatalf("failed to create rotated secure config codec: %v", err)
	}
	secureconfig.SetDefault(rotatedCodec)

	server := &AdminServer{
		db:                      db,
		secretsEnabled:          true,
		secretsFallbackKeyCount: 1,
	}
	router := gin.New()
	router.GET("/security/secrets/status", server.handleGetSecretsStatus)
	router.GET("/security/audit", server.handleGetSecurityAudit)
	router.GET("/security/secrets/audit", server.handleGetSecretsAudit)
	router.POST("/security/secrets/reseal", server.handleResealManagedSecrets)

	statusResp := performJSON(t, router, http.MethodGet, "/security/secrets/status", nil)
	if statusResp.Code != http.StatusOK {
		t.Fatalf("expected secrets status 200, got %d: %s", statusResp.Code, statusResp.Body.String())
	}
	var statusBody struct {
		Status secretsStatusView `json:"status"`
	}
	if err := json.Unmarshal(statusResp.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if !statusBody.Status.Enabled || statusBody.Status.FallbackKeyCount != 1 || statusBody.Status.ManagedOIDCClientCount != 1 || statusBody.Status.ManagedIdentityProviderCount != 1 {
		t.Fatalf("unexpected secrets status: %#v", statusBody.Status)
	}

	resealResp := performJSON(t, router, http.MethodPost, "/security/secrets/reseal", nil)
	if resealResp.Code != http.StatusOK {
		t.Fatalf("expected reseal status 200, got %d: %s", resealResp.Code, resealResp.Body.String())
	}
	var resealBody struct {
		Result secretsResealResult `json:"result"`
	}
	if err := json.Unmarshal(resealResp.Body.Bytes(), &resealBody); err != nil {
		t.Fatalf("failed to decode reseal response: %v", err)
	}
	if resealBody.Result.OIDCClients != 1 || resealBody.Result.IdentityProviders != 1 || resealBody.Result.OIDCProviders != 1 {
		t.Fatalf("unexpected reseal result: %#v", resealBody.Result)
	}

	auditResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit?limit=10", nil)
	if auditResp.Code != http.StatusOK {
		t.Fatalf("expected security audit status 200, got %d: %s", auditResp.Code, auditResp.Body.String())
	}
	var auditBody struct {
		Audit []securityAuditEntryView `json:"audit"`
	}
	if err := json.Unmarshal(auditResp.Body.Bytes(), &auditBody); err != nil {
		t.Fatalf("failed to decode security audit response: %v", err)
	}
	if len(auditBody.Audit) != 1 || auditBody.Audit[0].Action != securityAuditActionSecretsReseal || !auditBody.Audit[0].Success {
		t.Fatalf("unexpected security audit entries: %#v", auditBody.Audit)
	}
	if auditBody.Audit[0].Details["oidc_clients"] != "1" || auditBody.Audit[0].Details["identity_providers"] != "1" || auditBody.Audit[0].Details["fallback_key_count"] != "1" {
		t.Fatalf("unexpected security audit details: %#v", auditBody.Audit[0].Details)
	}

	var updatedClientRecord oidc.ClientRecord
	if err := db.Where("client_id = ?", "legacy-api").First(&updatedClientRecord).Error; err != nil {
		t.Fatalf("failed to reload oidc client record: %v", err)
	}
	if updatedClientRecord.ConfigJSON == oldClientConfigJSON {
		t.Fatalf("expected oidc client config json to be resealed")
	}
	if strings.Contains(updatedClientRecord.ConfigJSON, "legacy-client-secret") || !secureconfig.LooksEncrypted(updatedClientRecord.ConfigJSON) {
		t.Fatalf("expected oidc client config json to be encrypted, got %q", updatedClientRecord.ConfigJSON)
	}
	decodedClientConfig, err := oidc.ClientConfigFromRecord(updatedClientRecord)
	if err != nil {
		t.Fatalf("failed to decode resealed oidc client config: %v", err)
	}
	if decodedClientConfig.ClientSecret != "legacy-client-secret" {
		t.Fatalf("unexpected resealed oidc client config: %#v", decodedClientConfig)
	}

	var updatedProviderRecord iam.OrganizationIdentityProvider
	if err := db.Where("identity_provider_id = ?", providerRecord.IdentityProviderID).First(&updatedProviderRecord).Error; err != nil {
		t.Fatalf("failed to reload provider record: %v", err)
	}
	if strings.Contains(updatedProviderRecord.ConfigJSON, "legacy-provider-secret") || !secureconfig.LooksEncrypted(updatedProviderRecord.ConfigJSON) {
		t.Fatalf("expected identity provider config json to be encrypted, got %q", updatedProviderRecord.ConfigJSON)
	}
	decodedProviderConfig, err := decodeStoredEnterpriseOIDCConfig(updatedProviderRecord)
	if err != nil {
		t.Fatalf("failed to decode resealed provider config: %v", err)
	}
	if decodedProviderConfig.ClientSecret != "legacy-provider-secret" {
		t.Fatalf("unexpected resealed provider config: %#v", decodedProviderConfig)
	}
}

func TestSecurityHandlersAuditFailedReseal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secureconfig.SetDefault(nil)
	defer secureconfig.SetDefault(nil)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	server := &AdminServer{
		db:                      db,
		secretsEnabled:          false,
		secretsFallbackKeyCount: 0,
	}
	router := gin.New()
	router.GET("/security/audit", server.handleGetSecurityAudit)
	router.GET("/security/audit/export", server.handleExportSecurityAudit)
	router.GET("/security/secrets/audit", server.handleGetSecretsAudit)
	router.GET("/security/secrets/audit/export", server.handleExportSecretsAudit)
	router.POST("/security/secrets/reseal", server.handleResealManagedSecrets)

	resealResp := performJSON(t, router, http.MethodPost, "/security/secrets/reseal", nil)
	if resealResp.Code != http.StatusConflict {
		t.Fatalf("expected reseal conflict status 409, got %d: %s", resealResp.Code, resealResp.Body.String())
	}

	auditResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit?limit=10", nil)
	if auditResp.Code != http.StatusOK {
		t.Fatalf("expected security audit status 200, got %d: %s", auditResp.Code, auditResp.Body.String())
	}
	var auditBody struct {
		Audit []securityAuditEntryView `json:"audit"`
	}
	if err := json.Unmarshal(auditResp.Body.Bytes(), &auditBody); err != nil {
		t.Fatalf("failed to decode security audit response: %v", err)
	}
	if len(auditBody.Audit) != 1 || auditBody.Audit[0].Success {
		t.Fatalf("expected one failed security audit entry, got %#v", auditBody.Audit)
	}
	if auditBody.Audit[0].Details["reason"] != "encryption_disabled" {
		t.Fatalf("unexpected failed audit details: %#v", auditBody.Audit[0].Details)
	}
}

func TestSecurityHandlersListAuditWithFiltersAndPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	server := &AdminServer{db: db}
	if err := server.ensureSecurityAuditTable(); err != nil {
		t.Fatalf("failed to migrate security audit table: %v", err)
	}

	baseTime := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	events := []struct {
		id      string
		actorID string
		time    time.Time
		action  string
		success bool
		error   string
		details map[string]string
	}{
		{
			id:      "secaud_test_01",
			actorID: "security-admin",
			time:    baseTime.Add(-4 * time.Minute),
			action:  securityAuditActionSecretsReseal,
			success: true,
			details: map[string]string{"fallback_key_count": "1"},
		},
		{
			id:      "secaud_test_02",
			actorID: "ops-admin",
			time:    baseTime.Add(-3 * time.Minute),
			action:  securityAuditActionOIDCClientCreate,
			success: true,
			details: map[string]string{"resource_type": "oidc_client", "client_id": "client-a"},
		},
		{
			id:      "secaud_test_03",
			actorID: "security-admin",
			time:    baseTime.Add(-2 * time.Minute),
			action:  securityAuditActionIdentityProviderCreate,
			success: true,
			details: map[string]string{
				"resource_type":   "identity_provider",
				"provider_id":     "idp-1",
				"organization_id": "org_acme0000000000",
				"slug":            "acme-sso",
			},
		},
		{
			id:      "secaud_test_04",
			actorID: "ops-admin",
			time:    baseTime.Add(-1 * time.Minute),
			action:  securityAuditActionOIDCClientDelete,
			success: false,
			error:   "delete failed",
			details: map[string]string{"resource_type": "oidc_client", "client_id": "client-b", "stage": "delete_record"},
		},
	}
	for _, event := range events {
		detailsJSON, err := json.Marshal(event.details)
		if err != nil {
			t.Fatalf("failed to marshal details: %v", err)
		}
		record := SecurityAuditEvent{
			EventID:     event.id,
			Time:        event.time,
			Action:      event.action,
			ActorID:     event.actorID,
			Success:     event.success,
			Error:       event.error,
			DetailsJSON: string(detailsJSON),
		}
		if err := db.Create(&record).Error; err != nil {
			t.Fatalf("failed to insert security audit event %s: %v", event.id, err)
		}
	}

	router := gin.New()
	router.GET("/security/audit", server.handleGetSecurityAudit)
	router.GET("/security/audit/export", server.handleExportSecurityAudit)
	router.GET("/security/secrets/audit", server.handleGetSecretsAudit)
	router.GET("/security/secrets/audit/export", server.handleExportSecretsAudit)

	pageResp := performJSON(t, router, http.MethodGet, "/security/audit?page=1&size=2", nil)
	if pageResp.Code != http.StatusOK {
		t.Fatalf("expected paginated audit status 200, got %d: %s", pageResp.Code, pageResp.Body.String())
	}
	var pageBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
		Page  int                      `json:"page"`
		Size  int                      `json:"size"`
	}
	if err := json.Unmarshal(pageResp.Body.Bytes(), &pageBody); err != nil {
		t.Fatalf("failed to decode paginated audit response: %v", err)
	}
	if pageBody.Total != 4 || pageBody.Page != 1 || pageBody.Size != 2 || len(pageBody.Audit) != 2 {
		t.Fatalf("unexpected paginated audit response: %#v", pageBody)
	}
	if pageBody.Audit[0].Action != securityAuditActionOIDCClientDelete || pageBody.Audit[1].Action != securityAuditActionIdentityProviderCreate {
		t.Fatalf("expected latest audit entries first, got %#v", pageBody.Audit)
	}

	filteredResp := performJSON(t, router, http.MethodGet, "/security/audit?page=1&size=10&resource_type=oidc_client&success=false", nil)
	if filteredResp.Code != http.StatusOK {
		t.Fatalf("expected filtered audit status 200, got %d: %s", filteredResp.Code, filteredResp.Body.String())
	}
	var filteredBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(filteredResp.Body.Bytes(), &filteredBody); err != nil {
		t.Fatalf("failed to decode filtered audit response: %v", err)
	}
	if filteredBody.Total != 1 || len(filteredBody.Audit) != 1 {
		t.Fatalf("expected one filtered audit entry, got %#v", filteredBody)
	}
	if filteredBody.Audit[0].Action != securityAuditActionOIDCClientDelete || filteredBody.Audit[0].Details["client_id"] != "client-b" {
		t.Fatalf("unexpected filtered audit entry: %#v", filteredBody.Audit[0])
	}

	clientResp := performJSON(t, router, http.MethodGet, "/security/audit?client_id=client-a", nil)
	if clientResp.Code != http.StatusOK {
		t.Fatalf("expected client_id-filtered audit status 200, got %d: %s", clientResp.Code, clientResp.Body.String())
	}
	var clientBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(clientResp.Body.Bytes(), &clientBody); err != nil {
		t.Fatalf("failed to decode client_id-filtered audit response: %v", err)
	}
	if clientBody.Total != 1 || len(clientBody.Audit) != 1 || clientBody.Audit[0].Details["client_id"] != "client-a" {
		t.Fatalf("unexpected client_id-filtered audit response: %#v", clientBody)
	}

	clientExactResp := performJSON(t, router, http.MethodGet, "/security/audit?client_id=client", nil)
	if clientExactResp.Code != http.StatusOK {
		t.Fatalf("expected exact client_id filter audit status 200, got %d: %s", clientExactResp.Code, clientExactResp.Body.String())
	}
	var clientExactBody struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(clientExactResp.Body.Bytes(), &clientExactBody); err != nil {
		t.Fatalf("failed to decode exact client_id-filtered audit response: %v", err)
	}
	if clientExactBody.Total != 0 {
		t.Fatalf("expected exact client_id filter to avoid partial matches, got %#v", clientExactBody)
	}

	actionResp := performJSON(t, router, http.MethodGet, "/security/audit?action=identity_provider_create&success=true", nil)
	if actionResp.Code != http.StatusOK {
		t.Fatalf("expected action-filtered audit status 200, got %d: %s", actionResp.Code, actionResp.Body.String())
	}
	var actionBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(actionResp.Body.Bytes(), &actionBody); err != nil {
		t.Fatalf("failed to decode action-filtered audit response: %v", err)
	}
	if actionBody.Total != 1 || len(actionBody.Audit) != 1 || actionBody.Audit[0].Details["provider_id"] != "idp-1" {
		t.Fatalf("unexpected action-filtered audit response: %#v", actionBody)
	}

	providerResp := performJSON(t, router, http.MethodGet, "/security/audit?provider_id=idp-1", nil)
	if providerResp.Code != http.StatusOK {
		t.Fatalf("expected provider_id-filtered audit status 200, got %d: %s", providerResp.Code, providerResp.Body.String())
	}
	var providerBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(providerResp.Body.Bytes(), &providerBody); err != nil {
		t.Fatalf("failed to decode provider_id-filtered audit response: %v", err)
	}
	if providerBody.Total != 1 || len(providerBody.Audit) != 1 || providerBody.Audit[0].Details["provider_id"] != "idp-1" {
		t.Fatalf("unexpected provider_id-filtered audit response: %#v", providerBody)
	}

	orgResp := performJSON(t, router, http.MethodGet, "/security/audit?organization_id=org_acme0000000000", nil)
	if orgResp.Code != http.StatusOK {
		t.Fatalf("expected organization_id-filtered audit status 200, got %d: %s", orgResp.Code, orgResp.Body.String())
	}
	var orgBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(orgResp.Body.Bytes(), &orgBody); err != nil {
		t.Fatalf("failed to decode organization_id-filtered audit response: %v", err)
	}
	if orgBody.Total != 1 || len(orgBody.Audit) != 1 || orgBody.Audit[0].Details["organization_id"] != "org_acme0000000000" {
		t.Fatalf("unexpected organization_id-filtered audit response: %#v", orgBody)
	}

	actorResp := performJSON(t, router, http.MethodGet, "/security/audit?actor_id=ops", nil)
	if actorResp.Code != http.StatusOK {
		t.Fatalf("expected actor-filtered audit status 200, got %d: %s", actorResp.Code, actorResp.Body.String())
	}
	var actorBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(actorResp.Body.Bytes(), &actorBody); err != nil {
		t.Fatalf("failed to decode actor-filtered audit response: %v", err)
	}
	if actorBody.Total != 2 || len(actorBody.Audit) != 2 {
		t.Fatalf("expected two actor-filtered audit entries, got %#v", actorBody)
	}
	for _, entry := range actorBody.Audit {
		if !strings.Contains(entry.Actor.ID, "ops") {
			t.Fatalf("unexpected actor-filtered audit entry: %#v", entry)
		}
	}

	queryResp := performJSON(t, router, http.MethodGet, "/security/audit?query=acme-sso", nil)
	if queryResp.Code != http.StatusOK {
		t.Fatalf("expected query-filtered audit status 200, got %d: %s", queryResp.Code, queryResp.Body.String())
	}
	var queryBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(queryResp.Body.Bytes(), &queryBody); err != nil {
		t.Fatalf("failed to decode query-filtered audit response: %v", err)
	}
	if queryBody.Total != 1 || len(queryBody.Audit) != 1 || queryBody.Audit[0].Details["slug"] != "acme-sso" {
		t.Fatalf("unexpected query-filtered audit response: %#v", queryBody)
	}

	timeFrom := baseTime.Add(-2 * time.Minute).Format(time.RFC3339)
	timeTo := baseTime.Add(-2 * time.Minute).Format(time.RFC3339)
	timeResp := performJSON(t, router, http.MethodGet, "/security/audit?time_from="+timeFrom+"&time_to="+timeTo, nil)
	if timeResp.Code != http.StatusOK {
		t.Fatalf("expected time-filtered audit status 200, got %d: %s", timeResp.Code, timeResp.Body.String())
	}
	var timeBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
	}
	if err := json.Unmarshal(timeResp.Body.Bytes(), &timeBody); err != nil {
		t.Fatalf("failed to decode time-filtered audit response: %v", err)
	}
	if timeBody.Total != 1 || len(timeBody.Audit) != 1 || timeBody.Audit[0].Details["provider_id"] != "idp-1" {
		t.Fatalf("unexpected time-filtered audit response: %#v", timeBody)
	}

	dateOnlyResp := performJSON(t, router, http.MethodGet, "/security/audit?time_from=2026-04-24&time_to=2026-04-24", nil)
	if dateOnlyResp.Code != http.StatusOK {
		t.Fatalf("expected date-only filtered audit status 200, got %d: %s", dateOnlyResp.Code, dateOnlyResp.Body.String())
	}
	var dateOnlyBody struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(dateOnlyResp.Body.Bytes(), &dateOnlyBody); err != nil {
		t.Fatalf("failed to decode date-only audit response: %v", err)
	}
	if dateOnlyBody.Total != 4 {
		t.Fatalf("expected date-only filter to include the whole day, got %#v", dateOnlyBody)
	}

	exportResp := performJSON(t, router, http.MethodGet, "/security/audit/export?resource_type=oidc_client", nil)
	if exportResp.Code != http.StatusOK {
		t.Fatalf("expected export audit status 200, got %d: %s", exportResp.Code, exportResp.Body.String())
	}
	if contentType := exportResp.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("expected csv content type, got %q", contentType)
	}
	if exportResp.Header().Get("X-MKAuth-Export-Total") != "2" {
		t.Fatalf("expected export total header 2, got %q", exportResp.Header().Get("X-MKAuth-Export-Total"))
	}
	rows, err := csv.NewReader(strings.NewReader(exportResp.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse exported csv: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected csv header plus 2 rows, got %#v", rows)
	}
	if rows[0][0] != "id" || rows[0][1] != "time" || rows[0][2] != "action" {
		t.Fatalf("unexpected csv header: %#v", rows[0])
	}
	if rows[1][2] != securityAuditActionOIDCClientDelete || rows[2][2] != securityAuditActionOIDCClientCreate {
		t.Fatalf("unexpected csv export ordering: %#v", rows)
	}

	compatExportResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit/export?query=acme-sso", nil)
	if compatExportResp.Code != http.StatusOK {
		t.Fatalf("expected compatibility export status 200, got %d: %s", compatExportResp.Code, compatExportResp.Body.String())
	}
	compatRows, err := csv.NewReader(strings.NewReader(compatExportResp.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse compatibility exported csv: %v", err)
	}
	if len(compatRows) != 2 || !strings.Contains(strings.Join(compatRows[1], ","), "acme-sso") {
		t.Fatalf("unexpected compatibility export rows: %#v", compatRows)
	}

	compatResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit?limit=2", nil)
	if compatResp.Code != http.StatusOK {
		t.Fatalf("expected compatibility audit status 200, got %d: %s", compatResp.Code, compatResp.Body.String())
	}
	var compatBody struct {
		Audit []securityAuditEntryView `json:"audit"`
		Total int64                    `json:"total"`
		Page  int                      `json:"page"`
		Size  int                      `json:"size"`
	}
	if err := json.Unmarshal(compatResp.Body.Bytes(), &compatBody); err != nil {
		t.Fatalf("failed to decode compatibility audit response: %v", err)
	}
	if compatBody.Page != 1 || compatBody.Size != 2 || compatBody.Total != 4 || len(compatBody.Audit) != 2 {
		t.Fatalf("unexpected compatibility audit response: %#v", compatBody)
	}

	badResp := performJSON(t, router, http.MethodGet, "/security/audit?success=maybe", nil)
	if badResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid success filter to be rejected, got %d: %s", badResp.Code, badResp.Body.String())
	}
	if !strings.Contains(badResp.Body.String(), fmt.Sprintf("%q", "success must be true or false")) && !strings.Contains(badResp.Body.String(), "success must be true or false") {
		t.Fatalf("unexpected invalid filter response: %s", badResp.Body.String())
	}

	badTimeResp := performJSON(t, router, http.MethodGet, "/security/audit?time_from=not-a-time", nil)
	if badTimeResp.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid time_from to be rejected, got %d: %s", badTimeResp.Code, badTimeResp.Body.String())
	}
	if !strings.Contains(badTimeResp.Body.String(), "time_from must be RFC3339 or YYYY-MM-DD") {
		t.Fatalf("unexpected invalid time_from response: %s", badTimeResp.Body.String())
	}

	reversedTimeResp := performJSON(t, router, http.MethodGet, fmt.Sprintf("/security/audit?time_from=%s&time_to=%s", baseTime.Format(time.RFC3339), baseTime.Add(-time.Minute).Format(time.RFC3339)), nil)
	if reversedTimeResp.Code != http.StatusBadRequest {
		t.Fatalf("expected reversed time range to be rejected, got %d: %s", reversedTimeResp.Code, reversedTimeResp.Body.String())
	}
	if !strings.Contains(reversedTimeResp.Body.String(), "time_from must be earlier than or equal to time_to") {
		t.Fatalf("unexpected reversed time range response: %s", reversedTimeResp.Body.String())
	}
}

func TestSecurityHandlersAsyncExportJobs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "security-audit-export-jobs.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	server := &AdminServer{db: db}
	if err := server.ensureSecurityAuditTable(); err != nil {
		t.Fatalf("failed to migrate security audit table: %v", err)
	}

	baseTime := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	for idx, event := range []SecurityAuditEvent{
		{
			EventID:     "secaud_export_01",
			Time:        baseTime,
			Action:      securityAuditActionIdentityProviderCreate,
			ActorID:     "ops-admin",
			Success:     true,
			DetailsJSON: `{"resource_type":"identity_provider","provider_id":"idp-acme","organization_id":"org_acme0000000000","slug":"acme-sso"}`,
		},
		{
			EventID:     "secaud_export_02",
			Time:        baseTime.Add(time.Minute),
			Action:      securityAuditActionOIDCClientUpdate,
			ActorID:     "security-admin",
			Success:     false,
			Error:       "reload failed",
			DetailsJSON: `{"resource_type":"oidc_client","client_id":"client-a","stage":"reload_oidc_clients"}`,
		},
	} {
		if err := db.Create(&event).Error; err != nil {
			t.Fatalf("failed to insert security audit event %d: %v", idx, err)
		}
	}

	router := gin.New()
	router.GET("/security/audit/export-jobs", server.handleListSecurityAuditExportJobs)
	router.POST("/security/audit/export-jobs", server.handleCreateSecurityAuditExportJob)
	router.POST("/security/audit/export-jobs/cleanup", server.handleCleanupSecurityAuditExportJobs)
	router.GET("/security/audit/export-jobs/:job_id", server.handleGetSecurityAuditExportJob)
	router.DELETE("/security/audit/export-jobs/:job_id", server.handleDeleteSecurityAuditExportJob)
	router.GET("/security/audit/export-jobs/:job_id/download", server.handleDownloadSecurityAuditExportJob)
	router.GET("/security/secrets/audit/export-jobs", server.handleListSecretsAuditExportJobs)
	router.POST("/security/secrets/audit/export-jobs", server.handleCreateSecretsAuditExportJob)
	router.POST("/security/secrets/audit/export-jobs/cleanup", server.handleCleanupSecretsAuditExportJobs)
	router.GET("/security/secrets/audit/export-jobs/:job_id", server.handleGetSecretsAuditExportJob)
	router.DELETE("/security/secrets/audit/export-jobs/:job_id", server.handleDeleteSecretsAuditExportJob)
	router.GET("/security/secrets/audit/export-jobs/:job_id/download", server.handleDownloadSecretsAuditExportJob)

	createResp := performJSON(t, router, http.MethodPost, "/security/audit/export-jobs", map[string]any{
		"resource_type":   "identity_provider",
		"organization_id": "org_acme0000000000",
	})
	if createResp.Code != http.StatusAccepted {
		t.Fatalf("expected async export creation status 202, got %d: %s", createResp.Code, createResp.Body.String())
	}
	var createBody struct {
		Job securityAuditExportJobView `json:"job"`
	}
	if err := json.Unmarshal(createResp.Body.Bytes(), &createBody); err != nil {
		t.Fatalf("failed to decode async export create response: %v", err)
	}
	if createBody.Job.JobID == "" || createBody.Job.Status != securityAuditExportJobStatusPending {
		t.Fatalf("unexpected async export job create response: %#v", createBody.Job)
	}
	if createBody.Job.Query == nil || createBody.Job.Query.ResourceType != "identity_provider" || createBody.Job.Query.OrganizationID != "org_acme0000000000" {
		t.Fatalf("unexpected async export job query view: %#v", createBody.Job.Query)
	}

	listResp := performJSON(t, router, http.MethodGet, "/security/audit/export-jobs?organization_id=org_acme0000000000", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected async export list status 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var listBody struct {
		Jobs  []securityAuditExportJobView `json:"jobs"`
		Total int64                        `json:"total"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("failed to decode async export list response: %v", err)
	}
	if listBody.Total != 1 || len(listBody.Jobs) != 1 || listBody.Jobs[0].JobID != createBody.Job.JobID {
		t.Fatalf("unexpected async export list response: %#v", listBody)
	}

	var jobBody struct {
		Job securityAuditExportJobView `json:"job"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		statusResp := performJSON(t, router, http.MethodGet, "/security/audit/export-jobs/"+createBody.Job.JobID, nil)
		if statusResp.Code != http.StatusOK {
			t.Fatalf("expected async export status 200, got %d: %s", statusResp.Code, statusResp.Body.String())
		}
		if err := json.Unmarshal(statusResp.Body.Bytes(), &jobBody); err != nil {
			t.Fatalf("failed to decode async export status response: %v", err)
		}
		if jobBody.Job.Status == securityAuditExportJobStatusCompleted {
			break
		}
		if jobBody.Job.Status == securityAuditExportJobStatusFailed {
			t.Fatalf("expected async export job success, got failure: %#v", jobBody.Job)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for async export job completion: %#v", jobBody.Job)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !jobBody.Job.DownloadReady || jobBody.Job.RowCount != 1 || jobBody.Job.TotalCount != 1 {
		t.Fatalf("unexpected completed async export job: %#v", jobBody.Job)
	}

	downloadResp := performJSON(t, router, http.MethodGet, "/security/audit/export-jobs/"+createBody.Job.JobID+"/download", nil)
	if downloadResp.Code != http.StatusOK {
		t.Fatalf("expected async export download status 200, got %d: %s", downloadResp.Code, downloadResp.Body.String())
	}
	if contentType := downloadResp.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("expected async export csv content type, got %q", contentType)
	}
	rows, err := csv.NewReader(strings.NewReader(downloadResp.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse async export csv: %v", err)
	}
	if len(rows) != 2 || !strings.Contains(strings.Join(rows[1], ","), "acme-sso") {
		t.Fatalf("unexpected async export csv rows: %#v", rows)
	}

	compatCreateResp := performJSON(t, router, http.MethodPost, "/security/secrets/audit/export-jobs", map[string]any{
		"query": "client-a",
	})
	if compatCreateResp.Code != http.StatusAccepted {
		t.Fatalf("expected compatibility async export creation status 202, got %d: %s", compatCreateResp.Code, compatCreateResp.Body.String())
	}
	var compatCreateBody struct {
		Job securityAuditExportJobView `json:"job"`
	}
	if err := json.Unmarshal(compatCreateResp.Body.Bytes(), &compatCreateBody); err != nil {
		t.Fatalf("failed to decode compatibility async export create response: %v", err)
	}
	compatStatusResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit/export-jobs/"+compatCreateBody.Job.JobID, nil)
	if compatStatusResp.Code != http.StatusOK {
		t.Fatalf("expected compatibility async export status 200, got %d: %s", compatStatusResp.Code, compatStatusResp.Body.String())
	}

	compatListResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit/export-jobs?size=5", nil)
	if compatListResp.Code != http.StatusOK {
		t.Fatalf("expected compatibility async export list status 200, got %d: %s", compatListResp.Code, compatListResp.Body.String())
	}
	var compatListBody struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(compatListResp.Body.Bytes(), &compatListBody); err != nil {
		t.Fatalf("failed to decode compatibility async export list response: %v", err)
	}
	if compatListBody.Total < 2 {
		t.Fatalf("expected compatibility async export list to include both jobs, got %#v", compatListBody)
	}
}

func TestSecurityHandlersManageExportJobs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	server := &AdminServer{db: db}
	if err := server.ensureSecurityAuditExportJobTable(); err != nil {
		t.Fatalf("failed to migrate security audit export job table: %v", err)
	}

	now := time.Now().UTC()
	oldCompletedQuery := `{"organization_id":"org_acme0000000000","resource_type":"identity_provider"}`
	oldFailedQuery := `{"organization_id":"org_acme0000000000","provider_id":"idp-acme"}`
	newCompletedQuery := `{"organization_id":"org_globex000000000","resource_type":"oidc_client"}`
	for _, record := range []SecurityAuditExportJob{
		{
			JobID:       "secaudexp_old_completed",
			Status:      securityAuditExportJobStatusCompleted,
			QueryJSON:   oldCompletedQuery,
			FileName:    "old-completed.csv",
			ContentType: "text/csv; charset=utf-8",
			Content:     "id,time\n",
			RowCount:    1,
			TotalCount:  1,
			CreatedAt:   now.Add(-10 * 24 * time.Hour),
			UpdatedAt:   now.Add(-10 * 24 * time.Hour),
			CompletedAt: pointerToTime(now.Add(-10 * 24 * time.Hour)),
		},
		{
			JobID:       "secaudexp_old_failed",
			Status:      securityAuditExportJobStatusFailed,
			QueryJSON:   oldFailedQuery,
			FileName:    "old-failed.csv",
			ContentType: "text/csv; charset=utf-8",
			Error:       "export failed",
			CreatedAt:   now.Add(-9 * 24 * time.Hour),
			UpdatedAt:   now.Add(-9 * 24 * time.Hour),
			CompletedAt: pointerToTime(now.Add(-9 * 24 * time.Hour)),
		},
		{
			JobID:       "secaudexp_new_completed",
			Status:      securityAuditExportJobStatusCompleted,
			QueryJSON:   newCompletedQuery,
			FileName:    "new-completed.csv",
			ContentType: "text/csv; charset=utf-8",
			Content:     "id,time\n",
			RowCount:    1,
			TotalCount:  1,
			CreatedAt:   now.Add(-2 * 24 * time.Hour),
			UpdatedAt:   now.Add(-2 * 24 * time.Hour),
			CompletedAt: pointerToTime(now.Add(-2 * 24 * time.Hour)),
		},
		{
			JobID:       "secaudexp_running",
			Status:      securityAuditExportJobStatusRunning,
			QueryJSON:   oldCompletedQuery,
			FileName:    "running.csv",
			ContentType: "text/csv; charset=utf-8",
			CreatedAt:   now.Add(-time.Hour),
			UpdatedAt:   now.Add(-time.Hour),
		},
	} {
		if err := db.Create(&record).Error; err != nil {
			t.Fatalf("failed to insert export job %s: %v", record.JobID, err)
		}
	}

	router := gin.New()
	router.GET("/security/audit/export-jobs", server.handleListSecurityAuditExportJobs)
	router.POST("/security/audit/export-jobs/cleanup", server.handleCleanupSecurityAuditExportJobs)
	router.DELETE("/security/audit/export-jobs/:job_id", server.handleDeleteSecurityAuditExportJob)
	router.GET("/security/secrets/audit/export-jobs", server.handleListSecretsAuditExportJobs)

	listResp := performJSON(t, router, http.MethodGet, "/security/audit/export-jobs?organization_id=org_acme0000000000", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected export job list status 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	var listBody struct {
		Jobs  []securityAuditExportJobView `json:"jobs"`
		Total int64                        `json:"total"`
	}
	if err := json.Unmarshal(listResp.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("failed to decode export job list response: %v", err)
	}
	if listBody.Total != 3 || len(listBody.Jobs) != 3 {
		t.Fatalf("expected three organization-scoped jobs, got %#v", listBody)
	}

	deleteRunningResp := performJSON(t, router, http.MethodDelete, "/security/audit/export-jobs/secaudexp_running", nil)
	if deleteRunningResp.Code != http.StatusConflict {
		t.Fatalf("expected running export job delete status 409, got %d: %s", deleteRunningResp.Code, deleteRunningResp.Body.String())
	}

	deleteCompletedResp := performJSON(t, router, http.MethodDelete, "/security/audit/export-jobs/secaudexp_new_completed", nil)
	if deleteCompletedResp.Code != http.StatusOK {
		t.Fatalf("expected completed export job delete status 200, got %d: %s", deleteCompletedResp.Code, deleteCompletedResp.Body.String())
	}

	cleanupResp := performJSON(t, router, http.MethodPost, "/security/audit/export-jobs/cleanup", map[string]any{
		"organization_id": "org_acme0000000000",
		"older_than_days": 7,
	})
	if cleanupResp.Code != http.StatusOK {
		t.Fatalf("expected export job cleanup status 200, got %d: %s", cleanupResp.Code, cleanupResp.Body.String())
	}
	var cleanupBody struct {
		Result securityAuditExportJobCleanupResult `json:"result"`
	}
	if err := json.Unmarshal(cleanupResp.Body.Bytes(), &cleanupBody); err != nil {
		t.Fatalf("failed to decode export job cleanup response: %v", err)
	}
	if cleanupBody.Result.Deleted != 2 || cleanupBody.Result.OlderThanDays != 7 {
		t.Fatalf("unexpected export job cleanup result: %#v", cleanupBody.Result)
	}

	remainingResp := performJSON(t, router, http.MethodGet, "/security/secrets/audit/export-jobs?size=10", nil)
	if remainingResp.Code != http.StatusOK {
		t.Fatalf("expected compatibility export job list status 200, got %d: %s", remainingResp.Code, remainingResp.Body.String())
	}
	var remainingBody struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(remainingResp.Body.Bytes(), &remainingBody); err != nil {
		t.Fatalf("failed to decode remaining export job list response: %v", err)
	}
	if remainingBody.Total != 1 {
		t.Fatalf("expected only running job to remain, got %#v", remainingBody)
	}
}

func pointerToTime(value time.Time) *time.Time {
	return &value
}
