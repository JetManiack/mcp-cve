package storage

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrWatchNotFound        = errors.New("watch not found")
	ErrWatchAlreadyExists   = errors.New("watch for this vendor/product already exists")
	ErrEmptyVendorProduct   = errors.New("vendor_product must not be empty")
)

func CreateWatch(db *gorm.DB, actorID, vendorProduct string) (*CVEWatch, error) {
	if strings.TrimSpace(vendorProduct) == "" {
		return nil, ErrEmptyVendorProduct
	}

	watch := &CVEWatch{
		ID:            uuid.NewString(),
		ActorID:       actorID,
		VendorProduct: vendorProduct,
	}
	if err := db.Create(watch).Error; err != nil {
		return nil, err
	}
	return watch, nil
}

func DeleteWatch(db *gorm.DB, actorID, watchID string) error {
	result := db.Where("id = ? AND actor_id = ?", watchID, actorID).Delete(&CVEWatch{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrWatchNotFound
	}
	return nil
}

func ListWatches(db *gorm.DB, actorID string) ([]CVEWatch, error) {
	var watches []CVEWatch
	if err := db.Where("actor_id = ?", actorID).Order("created_at").Find(&watches).Error; err != nil {
		return nil, err
	}
	return watches, nil
}

// ListAllWatches returns all watches across all actors, used by the NVD syncer
// to match new CVEs against active subscriptions.
func ListAllWatches(db *gorm.DB) ([]CVEWatch, error) {
	var watches []CVEWatch
	if err := db.Find(&watches).Error; err != nil {
		return nil, err
	}
	return watches, nil
}

// RecordWatchHit creates a CVEWatchHit linking watchID to cveID. It is a
// no-op if the hit already exists (the syncer may re-process the same CVE on
// an incremental sync).
func RecordWatchHit(db *gorm.DB, watchID, cveID string) error {
	var existing CVEWatchHit
	err := db.Where("watch_id = ? AND cve_id = ?", watchID, cveID).First(&existing).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	hit := &CVEWatchHit{
		ID:      uuid.NewString(),
		WatchID: watchID,
		CVEID:   cveID,
	}
	return db.Create(hit).Error
}

// GetUnseenHits returns all unseen CVEWatchHit rows for actorID (via their
// CVEWatch.ActorID). Non-destructive: nothing is marked seen here.
func GetUnseenHits(db *gorm.DB, actorID string) ([]CVEWatchHit, error) {
	var hits []CVEWatchHit
	err := db.
		Joins("JOIN cve_watches ON cve_watches.id = cve_watch_hits.watch_id").
		Where("cve_watches.actor_id = ? AND cve_watch_hits.seen_at IS NULL", actorID).
		Order("cve_watch_hits.created_at DESC").
		Find(&hits).Error
	return hits, err
}

// GetAllHits returns all CVEWatchHit rows (seen and unseen) for actorID.
func GetAllHits(db *gorm.DB, actorID string) ([]CVEWatchHit, error) {
	var hits []CVEWatchHit
	err := db.
		Joins("JOIN cve_watches ON cve_watches.id = cve_watch_hits.watch_id").
		Where("cve_watches.actor_id = ?", actorID).
		Order("cve_watch_hits.created_at DESC").
		Find(&hits).Error
	return hits, err
}

// MarkHitsSeen sets SeenAt on all unseen hits belonging to actorID.
// Uses a subquery instead of a JOIN so it works on both SQLite and Postgres
// (SQLite does not support JOIN in UPDATE).
func MarkHitsSeen(db *gorm.DB, actorID string) error {
	now := time.Now()
	return db.
		Model(&CVEWatchHit{}).
		Where("watch_id IN (SELECT id FROM cve_watches WHERE actor_id = ?) AND seen_at IS NULL", actorID).
		Update("seen_at", now).Error
}
