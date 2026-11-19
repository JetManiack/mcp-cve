package storage

import "time"

type ActorKind string

const (
	ActorKindAgent ActorKind = "agent"
	ActorKindHuman ActorKind = "human"
)

type Actor struct {
	ID          string    `gorm:"type:char(36);primaryKey" json:"id"`
	DisplayName string    `gorm:"not null;uniqueIndex" json:"display_name"`
	Kind        ActorKind `gorm:"type:varchar(10);not null;index" json:"kind"`
	CreatedAt   time.Time `json:"created_at"`
}

type AgentCredential struct {
	ID         string     `gorm:"type:char(36);primaryKey" json:"id"`
	ActorID    string     `gorm:"type:char(36);not null;index" json:"actor_id"`
	Label      string     `json:"label"`
	TokenHash  string     `gorm:"type:char(64);not null;uniqueIndex" json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type UserIdentity struct {
	ActorID         string `gorm:"type:char(36);primaryKey"`
	KeycloakSubject string `gorm:"not null;uniqueIndex"`
	Role            string `gorm:"type:varchar(10);not null"`
}

// Session is a server-side OIDC login session. ID is a SHA-256 hex digest (64
// chars), never the raw session identifier which lives only in the browser
// cookie.
type Session struct {
	ID           string `gorm:"type:char(64);primaryKey"`
	Subject      string `gorm:"not null;index"`
	DisplayName  string `gorm:"not null"`
	Role         string `gorm:"type:varchar(10);not null"`
	RefreshToken string `gorm:"not null"`
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type ToolCall struct {
	ID         string    `gorm:"type:char(36);primaryKey" json:"id"`
	ActorID    string    `gorm:"type:char(36);not null;index" json:"actor_id"`
	Tool       string    `gorm:"type:varchar(64);not null;index" json:"tool"`
	InputJSON  string    `gorm:"type:text;not null;default:''" json:"input_json"`
	IsError    bool      `json:"is_error"`
	DurationMS int64     `json:"duration_ms"`
	OutputSize int       `json:"output_size"`
	OutputJSON string    `gorm:"type:text" json:"output_json,omitempty"`
	Truncated  bool      `json:"truncated"`
	CalledAt   time.Time `gorm:"index" json:"called_at"`
}

// CVE is one NVD vulnerability record. ID is the canonical CVE identifier (e.g. "CVE-2024-12345").
type CVE struct {
	ID               string    `gorm:"type:varchar(20);primaryKey" json:"id"`
	SourceIdentifier string    `gorm:"type:varchar(255)" json:"source_identifier"`
	Published        time.Time `gorm:"index" json:"published"`
	LastModified     time.Time `gorm:"index" json:"last_modified"`
	Description      string    `gorm:"type:text" json:"description"`
	Severity         string    `gorm:"type:varchar(10);index" json:"severity"`
	CVSSScore        float64   `json:"cvss_score"`
	// CPEs is a space-separated list of CPE criteria strings extracted from the
	// NVD configurations, stored as a plain text column for substring matching.
	CPEs     string `gorm:"column:cpes;type:text" json:"cpes"`
	RefsJSON string `gorm:"type:text" json:"-"`
	// UpdatedAt is indexed separately for incremental NVD sync queries.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `gorm:"index" json:"updated_at"`
}

// CVEWatch is one actor's subscription to new CVEs matching a vendor/product
// string. When the NVD syncer finds a CVE whose CPEs contain VendorProduct
// (case-insensitive substring), it creates a CVEWatchHit.
type CVEWatch struct {
	ID            string    `gorm:"type:char(36);primaryKey" json:"id"`
	ActorID       string    `gorm:"type:char(36);not null;index" json:"actor_id"`
	VendorProduct string    `gorm:"type:varchar(255);not null" json:"vendor_product"`
	CreatedAt     time.Time `json:"created_at"`
}

// CVEWatchHit records one CVE that matched a watch. SeenAt is nil until the
// actor calls get_watch_hits with mark_seen=true.
type CVEWatchHit struct {
	ID        string     `gorm:"type:char(36);primaryKey" json:"id"`
	WatchID   string     `gorm:"type:char(36);not null;index" json:"watch_id"`
	CVEID     string     `gorm:"type:varchar(20);not null;index" json:"cve_id"`
	SeenAt    *time.Time `json:"seen_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// SyncState tracks the NVD synchronisation state. There is always at most one
// row (ID=1), upserted by the syncer.
type SyncState struct {
	ID                  int        `gorm:"primaryKey"`
	LastFullSync        *time.Time `json:"last_full_sync"`
	LastIncrementalSync *time.Time `json:"last_incremental_sync"`
	TotalCVEs           int        `gorm:"column:total_cves" json:"total_cves"`
	UpdatedAt           time.Time  `json:"updated_at"`
}
