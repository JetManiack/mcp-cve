package storage

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrCVENotFound = errors.New("CVE not found")

// CVEFilter selects and pages a slice of CVE records.
type CVEFilter struct {
	Query    string // keyword search in Description
	Severity string // exact match: CRITICAL HIGH MEDIUM LOW NONE
	Vendor   string // substring match in CPEs
	Since    *time.Time
	Limit    int
	Cursor   string // ID of the last row of the previous page
}

// UpsertCVE inserts or updates one CVE row. Called by the NVD syncer.
func UpsertCVE(db *gorm.DB, cve *CVE) error {
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"source_identifier", "published", "last_modified",
			"description", "severity", "cvss_score",
			"cpes", "refs_json", "updated_at",
		}),
	}).Create(cve).Error
}

// GetCVE returns one CVE by its canonical ID.
func GetCVE(db *gorm.DB, id string) (*CVE, error) {
	var cve CVE
	err := db.First(&cve, "id = ?", strings.ToUpper(id)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCVENotFound
	}
	if err != nil {
		return nil, err
	}
	return &cve, nil
}

const (
	DefaultCVEPageSize = 20
	MaxCVEPageSize     = 100
)

// SearchCVEs returns a page of CVEs matching f, newest-published first.
func SearchCVEs(db *gorm.DB, f CVEFilter) ([]CVE, string, error) {
	limit := f.Limit
	if limit <= 0 || limit > MaxCVEPageSize {
		limit = DefaultCVEPageSize
	}

	q := db.Model(&CVE{})
	if f.Query != "" {
		q = q.Where("LOWER(description) LIKE ?", "%"+strings.ToLower(f.Query)+"%")
	}
	if f.Severity != "" {
		q = q.Where("severity = ?", strings.ToUpper(f.Severity))
	}
	if f.Vendor != "" {
		q = q.Where("LOWER(cpes) LIKE ?", "%"+strings.ToLower(f.Vendor)+"%")
	}
	if f.Since != nil {
		q = q.Where("published >= ?", *f.Since)
	}

	if f.Cursor != "" {
		var after CVE
		err := db.First(&after, "id = ?", f.Cursor).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrUnknownCursor
		}
		if err != nil {
			return nil, "", err
		}
		q = q.Where("(published < ?) OR (published = ? AND id < ?)", after.Published, after.Published, after.ID)
	}

	var cves []CVE
	if err := q.Order("published DESC, id DESC").Limit(limit).Find(&cves).Error; err != nil {
		return nil, "", err
	}

	next := ""
	if len(cves) == limit {
		next = cves[len(cves)-1].ID
	}
	return cves, next, nil
}

// GetRecentCVEs returns CVEs published or modified within the last `hours` hours.
func GetRecentCVEs(db *gorm.DB, hours int, severity string, limit int) ([]CVE, error) {
	if hours <= 0 {
		hours = 24
	}
	if hours > 168 {
		hours = 168
	}
	if limit <= 0 || limit > MaxCVEPageSize {
		limit = DefaultCVEPageSize
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	q := db.Model(&CVE{}).Where("last_modified >= ?", since)
	if severity != "" {
		q = q.Where("severity = ?", strings.ToUpper(severity))
	}

	var cves []CVE
	if err := q.Order("last_modified DESC").Limit(limit).Find(&cves).Error; err != nil {
		return nil, err
	}
	return cves, nil
}

// GetSyncState returns the single SyncState row, or a zero-value if none exists yet.
func GetSyncState(db *gorm.DB) (*SyncState, error) {
	var state SyncState
	err := db.First(&state, "id = 1").Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &SyncState{ID: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

// UpsertSyncState saves the SyncState row (ID=1).
func UpsertSyncState(db *gorm.DB, state *SyncState) error {
	state.ID = 1
	state.UpdatedAt = time.Now()
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"last_full_sync", "last_incremental_sync", "total_cves", "updated_at",
		}),
	}).Create(state).Error
}

// CountCVEs returns the total number of CVE rows in the database.
func CountCVEs(db *gorm.DB) (int64, error) {
	var n int64
	err := db.Model(&CVE{}).Count(&n).Error
	return n, err
}
