package storage_test

import (
	"testing"
	"time"

	"github.com/JetManiack/mcp-cve/internal/storage"
	"github.com/JetManiack/mcp-cve/internal/testutil"
)

func makeCVE(id, severity, description, cpes string, published time.Time) *storage.CVE {
	return &storage.CVE{
		ID:           id,
		Published:    published,
		LastModified: published,
		Description:  description,
		Severity:     severity,
		CVSSScore:    7.5,
		CPEs:         cpes,
	}
}

// UpsertCVE / GetCVE

func TestUpsertAndGetCVE(t *testing.T) {
	db := testutil.NewTestDB(t)
	cve := makeCVE("CVE-2024-00001", "HIGH", "A test vulnerability", "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", time.Now())

	if err := storage.UpsertCVE(db, cve); err != nil {
		t.Fatalf("UpsertCVE: %v", err)
	}

	got, err := storage.GetCVE(db, "CVE-2024-00001")
	if err != nil {
		t.Fatalf("GetCVE: %v", err)
	}
	if got.ID != "CVE-2024-00001" {
		t.Errorf("ID: got %q, want %q", got.ID, "CVE-2024-00001")
	}
	if got.Severity != "HIGH" {
		t.Errorf("Severity: got %q, want %q", got.Severity, "HIGH")
	}
	if got.CPEs != cve.CPEs {
		t.Errorf("CPEs: got %q, want %q", got.CPEs, cve.CPEs)
	}
}

func TestGetCVE_CaseInsensitiveID(t *testing.T) {
	db := testutil.NewTestDB(t)
	cve := makeCVE("CVE-2024-00002", "LOW", "desc", "", time.Now())
	storage.UpsertCVE(db, cve)

	_, err := storage.GetCVE(db, "cve-2024-00002")
	if err != nil {
		t.Errorf("GetCVE with lowercase id: %v", err)
	}
}

func TestGetCVE_NotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, err := storage.GetCVE(db, "CVE-9999-00000")
	if err != storage.ErrCVENotFound {
		t.Errorf("expected ErrCVENotFound, got %v", err)
	}
}

func TestUpsertCVE_UpdatesExisting(t *testing.T) {
	db := testutil.NewTestDB(t)
	original := makeCVE("CVE-2024-00003", "MEDIUM", "original", "", time.Now())
	storage.UpsertCVE(db, original)

	updated := makeCVE("CVE-2024-00003", "CRITICAL", "updated description", "", time.Now())
	if err := storage.UpsertCVE(db, updated); err != nil {
		t.Fatalf("UpsertCVE update: %v", err)
	}

	got, _ := storage.GetCVE(db, "CVE-2024-00003")
	if got.Severity != "CRITICAL" {
		t.Errorf("Severity after update: got %q, want %q", got.Severity, "CRITICAL")
	}
	if got.Description != "updated description" {
		t.Errorf("Description after update: got %q, want %q", got.Description, "updated description")
	}
}

// SearchCVEs

func TestSearchCVEs_ByKeyword(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00010", "HIGH", "OpenSSL buffer overflow vulnerability", "", now))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00011", "LOW", "Unrelated issue", "", now.Add(-time.Second)))

	cves, _, err := storage.SearchCVEs(db, storage.CVEFilter{Query: "openssl"})
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2024-00010" {
		t.Errorf("expected only CVE-2024-00010, got %v", cveIDs(cves))
	}
}

func TestSearchCVEs_BySeverity(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00020", "CRITICAL", "critical vuln", "", now))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00021", "LOW", "low vuln", "", now.Add(-time.Second)))

	cves, _, err := storage.SearchCVEs(db, storage.CVEFilter{Severity: "CRITICAL"})
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2024-00020" {
		t.Errorf("expected only CVE-2024-00020, got %v", cveIDs(cves))
	}
}

func TestSearchCVEs_ByVendor(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00030", "HIGH", "vuln", "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", now))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00031", "HIGH", "other vuln", "cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*", now.Add(-time.Second)))

	cves, _, err := storage.SearchCVEs(db, storage.CVEFilter{Vendor: "OpenSSL"})
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(cves) != 1 || cves[0].ID != "CVE-2024-00030" {
		t.Errorf("expected only CVE-2024-00030, got %v", cveIDs(cves))
	}
}

func TestSearchCVEs_Pagination(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		id := "CVE-2024-0100" + string(rune('1'+i))
		storage.UpsertCVE(db, makeCVE(id, "HIGH", "vuln", "", now.Add(time.Duration(-i)*time.Second)))
	}

	page1, cursor, err := storage.SearchCVEs(db, storage.CVEFilter{Limit: 2})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1: got %d results, want 2", len(page1))
	}
	if cursor == "" {
		t.Fatal("expected non-empty cursor after first page")
	}

	page2, cursor2, err := storage.SearchCVEs(db, storage.CVEFilter{Limit: 2, Cursor: cursor})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2: got %d results, want 2", len(page2))
	}
	// Results should not overlap
	for _, c1 := range page1 {
		for _, c2 := range page2 {
			if c1.ID == c2.ID {
				t.Errorf("overlap between pages: %q appears in both", c1.ID)
			}
		}
	}
	_ = cursor2
}

func TestSearchCVEs_UnknownCursor(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, _, err := storage.SearchCVEs(db, storage.CVEFilter{Cursor: "nonexistent-id"})
	if err != storage.ErrUnknownCursor {
		t.Errorf("expected ErrUnknownCursor, got %v", err)
	}
}

func TestSearchCVEs_LimitDefaultsTo20(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	for i := 0; i < 25; i++ {
		id := "CVE-2024-20" + paddedInt(i)
		storage.UpsertCVE(db, makeCVE(id, "HIGH", "vuln", "", now.Add(time.Duration(-i)*time.Second)))
	}
	cves, _, err := storage.SearchCVEs(db, storage.CVEFilter{Limit: 0})
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(cves) != storage.DefaultCVEPageSize {
		t.Errorf("got %d results, want %d", len(cves), storage.DefaultCVEPageSize)
	}
}

// GetRecentCVEs

func TestGetRecentCVEs_WithinWindow(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00050", "HIGH", "recent vuln", "", now.Add(-1*time.Hour)))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00051", "HIGH", "old vuln", "", now.Add(-48*time.Hour)))

	cves, err := storage.GetRecentCVEs(db, 24, "", 0)
	if err != nil {
		t.Fatalf("GetRecentCVEs: %v", err)
	}
	for _, c := range cves {
		if c.ID == "CVE-2024-00051" {
			t.Error("old CVE should not appear in 24h window")
		}
	}
	found := false
	for _, c := range cves {
		if c.ID == "CVE-2024-00050" {
			found = true
		}
	}
	if !found {
		t.Error("recent CVE not found in 24h window")
	}
}

func TestGetRecentCVEs_SeverityFilter(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00060", "CRITICAL", "critical recent", "", now.Add(-1*time.Hour)))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00061", "LOW", "low recent", "", now.Add(-2*time.Hour)))

	cves, err := storage.GetRecentCVEs(db, 24, "CRITICAL", 0)
	if err != nil {
		t.Fatalf("GetRecentCVEs: %v", err)
	}
	for _, c := range cves {
		if c.Severity != "CRITICAL" {
			t.Errorf("unexpected severity %q in results", c.Severity)
		}
	}
}

func TestGetRecentCVEs_HoursDefault(t *testing.T) {
	db := testutil.NewTestDB(t)
	// hours <= 0 defaults to 24, so this just shouldn't crash
	_, err := storage.GetRecentCVEs(db, 0, "", 0)
	if err != nil {
		t.Fatalf("GetRecentCVEs with zero hours: %v", err)
	}
}

// SyncState

func TestSyncState_ZeroValueWhenEmpty(t *testing.T) {
	db := testutil.NewTestDB(t)
	state, err := storage.GetSyncState(db)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if state.LastFullSync != nil {
		t.Error("expected nil LastFullSync on empty DB")
	}
	if state.TotalCVEs != 0 {
		t.Errorf("expected 0 TotalCVEs, got %d", state.TotalCVEs)
	}
}

func TestUpsertSyncState_RoundTrip(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now().Truncate(time.Second)
	state := &storage.SyncState{
		ID:           1,
		LastFullSync: &now,
		TotalCVEs:    42,
	}
	if err := storage.UpsertSyncState(db, state); err != nil {
		t.Fatalf("UpsertSyncState: %v", err)
	}

	got, err := storage.GetSyncState(db)
	if err != nil {
		t.Fatalf("GetSyncState: %v", err)
	}
	if got.TotalCVEs != 42 {
		t.Errorf("TotalCVEs: got %d, want 42", got.TotalCVEs)
	}
	if got.LastFullSync == nil || !got.LastFullSync.Equal(now) {
		t.Errorf("LastFullSync: got %v, want %v", got.LastFullSync, now)
	}
}

func TestCountCVEs(t *testing.T) {
	db := testutil.NewTestDB(t)
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00070", "HIGH", "a", "", now))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00071", "HIGH", "b", "", now.Add(-time.Second)))

	n, err := storage.CountCVEs(db)
	if err != nil {
		t.Fatalf("CountCVEs: %v", err)
	}
	if n != 2 {
		t.Errorf("CountCVEs: got %d, want 2", n)
	}
}

// helpers

func cveIDs(cves []storage.CVE) []string {
	ids := make([]string, len(cves))
	for i, c := range cves {
		ids[i] = c.ID
	}
	return ids
}

func paddedInt(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0' + i/10)) + string(rune('0' + i%10))
}
