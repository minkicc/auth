package admin

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

const (
	adminPrincipalSourceConfig   = "config"
	adminPrincipalSourceDatabase = "database"
)

var (
	ErrAdminPrincipalNotFound          = errors.New("admin principal not found")
	ErrAdminPrincipalManagedByConfig   = errors.New("admin principal is managed by config")
	ErrAdminPrincipalAlreadyConfigured = errors.New("admin principal already exists")
)

type AccessController struct {
	config *config.AdminConfig
	db     *gorm.DB
}

type AdminPrincipalRecord struct {
	UserID    string    `json:"user_id" gorm:"primaryKey;size:32"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (AdminPrincipalRecord) TableName() string {
	return "admin_principals"
}

type AdminPrincipalView struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username,omitempty"`
	Nickname  string    `json:"nickname,omitempty"`
	Status    string    `json:"status,omitempty"`
	Sources   []string  `json:"sources"`
	Editable  bool      `json:"editable"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func NewAccessController(cfg *config.AdminConfig, db *gorm.DB) *AccessController {
	return &AccessController{
		config: cfg,
		db:     db,
	}
}

func (c *AccessController) ensureTable() error {
	if c == nil || c.db == nil {
		return fmt.Errorf("admin access controller requires database")
	}
	return c.db.AutoMigrate(&AdminPrincipalRecord{})
}

func (c *AccessController) configuredUserIDs() []string {
	if c == nil || c.config == nil {
		return nil
	}
	return c.config.EffectiveUserIDs()
}

func (c *AccessController) hasConfiguredUserID(userID string) bool {
	trimmed := strings.TrimSpace(userID)
	if trimmed == "" {
		return false
	}
	for _, configuredUserID := range c.configuredUserIDs() {
		if configuredUserID == trimmed {
			return true
		}
	}
	return false
}

func (c *AccessController) IsAdminUser(userID string) (bool, []string, error) {
	trimmed := strings.TrimSpace(userID)
	if trimmed == "" {
		return false, nil, nil
	}

	sources := make([]string, 0, 2)
	if c.hasConfiguredUserID(trimmed) {
		sources = append(sources, adminPrincipalSourceConfig)
	}

	if c != nil && c.db != nil {
		if err := c.ensureTable(); err != nil {
			return false, nil, err
		}
		var record AdminPrincipalRecord
		err := c.db.Where("user_id = ?", trimmed).First(&record).Error
		switch {
		case err == nil:
			sources = append(sources, adminPrincipalSourceDatabase)
		case errors.Is(err, gorm.ErrRecordNotFound):
		default:
			return false, nil, err
		}
	}

	return len(sources) > 0, sources, nil
}

func (c *AccessController) ListAdminPrincipals() ([]AdminPrincipalView, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("admin access controller requires database")
	}
	if err := c.ensureTable(); err != nil {
		return nil, err
	}

	type principalAggregate struct {
		view   AdminPrincipalView
		record *AdminPrincipalRecord
	}

	items := make(map[string]*principalAggregate)
	for _, userID := range c.configuredUserIDs() {
		items[userID] = &principalAggregate{
			view: AdminPrincipalView{
				UserID:   userID,
				Sources:  []string{adminPrincipalSourceConfig},
				Editable: false,
			},
		}
	}

	var records []AdminPrincipalRecord
	if err := c.db.Order("created_at ASC").Find(&records).Error; err != nil {
		return nil, err
	}
	for i := range records {
		record := records[i]
		existing, ok := items[record.UserID]
		if !ok {
			items[record.UserID] = &principalAggregate{
				view: AdminPrincipalView{
					UserID:    record.UserID,
					Sources:   []string{adminPrincipalSourceDatabase},
					Editable:  true,
					CreatedAt: record.CreatedAt,
					UpdatedAt: record.UpdatedAt,
				},
				record: &record,
			}
			continue
		}
		existing.view.Sources = append(existing.view.Sources, adminPrincipalSourceDatabase)
		existing.view.CreatedAt = record.CreatedAt
		existing.view.UpdatedAt = record.UpdatedAt
		existing.record = &record
	}

	views := make([]AdminPrincipalView, 0, len(items))
	for userID, aggregate := range items {
		view := aggregate.view
		if err := c.populateAdminPrincipalIdentity(&view, userID); err != nil {
			return nil, err
		}
		views = append(views, view)
	}

	sortAdminPrincipalViews(views)
	return views, nil
}

func (c *AccessController) AddDatabaseAdmin(userRef string) (AdminPrincipalView, error) {
	if c == nil || c.db == nil {
		return AdminPrincipalView{}, fmt.Errorf("admin access controller requires database")
	}
	if err := c.ensureTable(); err != nil {
		return AdminPrincipalView{}, err
	}

	user, username, err := c.resolveUserReference(userRef)
	if err != nil {
		return AdminPrincipalView{}, err
	}
	if c.hasConfiguredUserID(user.UserID) {
		return AdminPrincipalView{}, ErrAdminPrincipalManagedByConfig
	}

	record := AdminPrincipalRecord{
		UserID: user.UserID,
	}
	if err := c.db.FirstOrCreate(&record, AdminPrincipalRecord{UserID: user.UserID}).Error; err != nil {
		return AdminPrincipalView{}, err
	}

	view := AdminPrincipalView{
		UserID:    user.UserID,
		Username:  username,
		Nickname:  user.Nickname,
		Status:    string(user.Status),
		Sources:   []string{adminPrincipalSourceDatabase},
		Editable:  true,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}
	return view, nil
}

func (c *AccessController) DeleteDatabaseAdmin(userID string) error {
	if c == nil || c.db == nil {
		return fmt.Errorf("admin access controller requires database")
	}
	if err := c.ensureTable(); err != nil {
		return err
	}

	trimmed := strings.TrimSpace(userID)
	if trimmed == "" {
		return ErrAdminPrincipalNotFound
	}
	if c.hasConfiguredUserID(trimmed) {
		return ErrAdminPrincipalManagedByConfig
	}

	result := c.db.Where("user_id = ?", trimmed).Delete(&AdminPrincipalRecord{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrAdminPrincipalNotFound
	}
	return nil
}

func (c *AccessController) resolveUserReference(userRef string) (*auth.User, string, error) {
	if c == nil || c.db == nil {
		return nil, "", fmt.Errorf("admin access controller requires database")
	}
	trimmed := strings.TrimSpace(userRef)
	if trimmed == "" {
		return nil, "", fmt.Errorf("user_id or username is required")
	}

	var user auth.User
	if err := c.db.Where("user_id = ?", trimmed).First(&user).Error; err == nil {
		username, _ := c.lookupUsername(user.UserID)
		return &user, username, nil
	}

	var accountUser auth.AccountUser
	if err := c.db.Where("username = ?", trimmed).First(&accountUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrAdminPrincipalNotFound
		}
		return nil, "", err
	}

	if err := c.db.Where("user_id = ?", accountUser.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrAdminPrincipalNotFound
		}
		return nil, "", err
	}
	return &user, accountUser.Username, nil
}

func (c *AccessController) populateAdminPrincipalIdentity(view *AdminPrincipalView, userID string) error {
	if c == nil || c.db == nil || view == nil {
		return nil
	}

	var user auth.User
	err := c.db.Where("user_id = ?", userID).First(&user).Error
	switch {
	case err == nil:
		view.Nickname = user.Nickname
		view.Status = string(user.Status)
		username, lookupErr := c.lookupUsername(user.UserID)
		if lookupErr != nil {
			return lookupErr
		}
		view.Username = username
	case errors.Is(err, gorm.ErrRecordNotFound):
		view.Status = "missing"
	default:
		return err
	}

	view.Sources = dedupeStrings(view.Sources)
	view.Editable = !containsString(view.Sources, adminPrincipalSourceConfig)
	return nil
}

func (c *AccessController) lookupUsername(userID string) (string, error) {
	if c == nil || c.db == nil {
		return "", nil
	}
	var accountUser auth.AccountUser
	err := c.db.Where("user_id = ?", userID).First(&accountUser).Error
	switch {
	case err == nil:
		return accountUser.Username, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "", nil
	default:
		return "", err
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func sortAdminPrincipalViews(views []AdminPrincipalView) {
	if len(views) < 2 {
		return
	}
	sort.SliceStable(views, func(i, j int) bool {
		left := adminPrincipalSortKey(views[i])
		right := adminPrincipalSortKey(views[j])
		if left == right {
			return views[i].UserID < views[j].UserID
		}
		return left < right
	})
}

func adminPrincipalSortKey(view AdminPrincipalView) string {
	if strings.TrimSpace(view.Username) != "" {
		return strings.ToLower(view.Username)
	}
	if strings.TrimSpace(view.Nickname) != "" {
		return strings.ToLower(view.Nickname)
	}
	return strings.ToLower(view.UserID)
}
