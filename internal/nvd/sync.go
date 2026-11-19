package nvd

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

// WatchNotifier is called by the syncer when a newly ingested CVE matches a
// watch, so the mcpserver can push a ResourceUpdated notification to
// subscribed clients. actorID is the owner of the matching watch.
type WatchNotifier func(ctx context.Context, actorID string)

// Syncer manages the initial full load from NVD and ongoing incremental
// updates. It is meant to run in background goroutines started by main.go.
type Syncer struct {
	db       *gorm.DB
	client   *Client
	notifier WatchNotifier
}

// NewSyncer constructs a Syncer. notifier may be nil if watch notifications
// are not needed (e.g. in tests).
func NewSyncer(db *gorm.DB, client *Client, notifier WatchNotifier) *Syncer {
	return &Syncer{db: db, client: client, notifier: notifier}
}

// RunInitialLoad performs a full load of all CVEs from NVD if no full sync
// has been done yet. It is idempotent: calling it again after a successful
// full sync is a no-op.
func (s *Syncer) RunInitialLoad(ctx context.Context) error {
	state, err := storage.GetSyncState(s.db)
	if err != nil {
		return err
	}
	if state.LastFullSync != nil {
		slog.Info("skipping initial load: full sync already completed", "last", *state.LastFullSync)
		return nil
	}

	slog.Info("starting NVD initial full load")
	start := time.Now()

	total, ingested, err := s.loadAllPages(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	state.LastFullSync = &now
	count, _ := storage.CountCVEs(s.db)
	state.TotalCVEs = int(count)
	if err := storage.UpsertSyncState(s.db, state); err != nil {
		return err
	}

	slog.Info("NVD initial full load complete",
		"total_nvd", total, "ingested", ingested, "elapsed", time.Since(start).Round(time.Second))
	return nil
}

// loadAllPages iterates through all NVD pages using startIndex-based
// pagination. Returns (totalResults, ingested, error).
func (s *Syncer) loadAllPages(ctx context.Context) (int, int, error) {
	startIndex := 0
	total := -1
	ingested := 0

	for {
		if err := ctx.Err(); err != nil {
			return total, ingested, err
		}

		page, err := s.client.FetchPage(startIndex)
		if err != nil {
			return total, ingested, err
		}

		if total == -1 {
			total = page.TotalResults
			slog.Info("NVD full load: total CVEs to fetch", "total", total)
		}

		n, err := s.ingestPage(ctx, page)
		if err != nil {
			return total, ingested, err
		}
		ingested += n

		startIndex += len(page.Vulnerabilities)
		slog.Info("NVD full load progress", "done", startIndex, "total", total)

		if startIndex >= page.TotalResults || len(page.Vulnerabilities) == 0 {
			break
		}
	}

	return total, ingested, nil
}

// RunIncrementalSync fetches CVEs modified since the last sync and upserts
// them. Safe to call repeatedly; it records the high-water mark after each run.
func (s *Syncer) RunIncrementalSync(ctx context.Context) error {
	state, err := storage.GetSyncState(s.db)
	if err != nil {
		return err
	}

	// Skip incremental sync if full sync hasn't happened yet.
	if state.LastFullSync == nil {
		return nil
	}

	var since time.Time
	if state.LastIncrementalSync != nil {
		since = *state.LastIncrementalSync
	} else {
		since = *state.LastFullSync
	}

	now := time.Now()
	slog.Info("NVD incremental sync", "since", since, "until", now)

	ingested, err := s.loadModifiedPages(ctx, since, now)
	if err != nil {
		return err
	}

	state.LastIncrementalSync = &now
	count, _ := storage.CountCVEs(s.db)
	state.TotalCVEs = int(count)
	if err := storage.UpsertSyncState(s.db, state); err != nil {
		return err
	}

	slog.Info("NVD incremental sync complete", "ingested", ingested)
	return nil
}

// loadModifiedPages paginates through the lastModStartDate/lastModEndDate
// window using 2-hour sub-windows when needed to stay within the NVD's
// 120-day range limit.
func (s *Syncer) loadModifiedPages(ctx context.Context, since, until time.Time) (int, error) {
	const maxWindow = 119 * 24 * time.Hour

	ingested := 0
	windowStart := since

	for windowStart.Before(until) {
		if err := ctx.Err(); err != nil {
			return ingested, err
		}

		windowEnd := windowStart.Add(maxWindow)
		if windowEnd.After(until) {
			windowEnd = until
		}

		startIndex := 0
		for {
			page, err := s.client.FetchModifiedSince(windowStart, windowEnd, startIndex)
			if err != nil {
				return ingested, err
			}

			n, err := s.ingestPage(ctx, page)
			if err != nil {
				return ingested, err
			}
			ingested += n

			startIndex += len(page.Vulnerabilities)
			if startIndex >= page.TotalResults || len(page.Vulnerabilities) == 0 {
				break
			}
		}

		windowStart = windowEnd
	}

	return ingested, nil
}

// ingestPage upserts all CVEs from one NVD API page and matches them against
// active watches.
func (s *Syncer) ingestPage(ctx context.Context, page *PageResult) (int, error) {
	watches, err := storage.ListAllWatches(s.db)
	if err != nil {
		return 0, err
	}

	for i := range page.Vulnerabilities {
		item := &page.Vulnerabilities[i]
		cve, err := convertCVEItem(item)
		if err != nil {
			slog.Warn("skipping malformed CVE", "id", item.CVE.ID, "error", err)
			continue
		}

		if err := storage.UpsertCVE(s.db, cve); err != nil {
			return i, err
		}

		s.matchWatches(ctx, cve, watches)
	}

	return len(page.Vulnerabilities), nil
}

// matchWatches checks cve against all active watches and creates CVEWatchHit
// rows for any matches, then notifies subscribers.
func (s *Syncer) matchWatches(ctx context.Context, cve *storage.CVE, watches []storage.CVEWatch) {
	if len(watches) == 0 {
		return
	}
	cpeVPs := cpeVendorProducts(cve.CPEs)
	notified := make(map[string]bool)

	for _, watch := range watches {
		// Skip CVEs published before the watch was created — they are
		// historical and would create noise during the initial NVD load.
		if cve.Published.Before(watch.CreatedAt) {
			continue
		}
		q := strings.ToLower(watch.VendorProduct)
		matched := false
		for _, vp := range cpeVPs {
			if strings.Contains(vp, q) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if err := storage.RecordWatchHit(s.db, watch.ID, cve.ID); err != nil {
			slog.Warn("failed to record watch hit", "watch_id", watch.ID, "cve_id", cve.ID, "error", err)
			continue
		}
		if s.notifier != nil && !notified[watch.ActorID] {
			notified[watch.ActorID] = true
			s.notifier(ctx, watch.ActorID)
		}
	}
}

// cpeVendorProducts extracts lowercased "vendor product" strings (space-
// separated) from a space-separated CPE list. Only CPE vendor (field index 3)
// and product (field index 4) are included; version, platform and other
// trailing components are excluded so substring matching stays scoped to
// actual vendor/product values.
func cpeVendorProducts(cpes string) []string {
	fields := strings.Fields(cpes)
	out := make([]string, 0, len(fields))
	for _, cpe := range fields {
		parts := strings.SplitN(cpe, ":", 7)
		if len(parts) >= 5 {
			out = append(out, strings.ToLower(parts[3]+" "+parts[4]))
		}
	}
	return out
}

// convertCVEItem converts an NVD API CVEItem to a storage.CVE.
func convertCVEItem(item *CVEItem) (*storage.CVE, error) {
	pub, err := ParseTime(item.CVE.Published)
	if err != nil {
		return nil, err
	}
	mod, err := ParseTime(item.CVE.LastModified)
	if err != nil {
		return nil, err
	}

	severity, score := ExtractSeverityAndScore(item)

	return &storage.CVE{
		ID:               item.CVE.ID,
		SourceIdentifier: item.CVE.SourceIdentifier,
		Published:        pub,
		LastModified:     mod,
		Description:      ExtractEnglishDescription(item),
		Severity:         severity,
		CVSSScore:        score,
		CPEs:             ExtractCPEs(item),
		RefsJSON:         ExtractRefsJSON(item),
	}, nil
}
