package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JetManiack/mcp-cve/internal/testutil"
)

func buildPageResult(items []CVEItem) PageResult {
	return PageResult{
		TotalResults:    len(items),
		StartIndex:      0,
		ResultsPerPage:  len(items),
		Vulnerabilities: items,
	}
}

func srvWithPages(pages []PageResult) *httptest.Server {
	var calls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(calls.Add(1)) - 1
		w.Header().Set("Content-Type", "application/json")
		if idx < len(pages) {
			json.NewEncoder(w).Encode(pages[idx])
		} else {
			json.NewEncoder(w).Encode(PageResult{TotalResults: 0})
		}
	}))
}

func newTestSyncer(t *testing.T, serverURL string) (*Syncer, *int32) {
	t.Helper()
	db := testutil.NewTestDB(t)
	client := newTestClient(serverURL)
	var notifyCalls int32
	notifier := WatchNotifier(func(_ context.Context, _ string) {
		atomic.AddInt32(&notifyCalls, 1)
	})
	return NewSyncer(db, client, notifier), &notifyCalls
}

func TestRunInitialLoad_IngestsAllCVEs(t *testing.T) {
	items := []CVEItem{
		minimalCVEItem("CVE-2024-00001"),
		minimalCVEItem("CVE-2024-00002"),
	}
	srv := srvWithPages([]PageResult{buildPageResult(items)})
	defer srv.Close()

	syncer, _ := newTestSyncer(t, srv.URL)
	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("RunInitialLoad: %v", err)
	}

	// Verify sync state was recorded.
	state, err := syncer.db.Raw("SELECT * FROM sync_states WHERE id = 1").Rows()
	if err != nil {
		t.Fatalf("query sync_states: %v", err)
	}
	defer state.Close()
	if !state.Next() {
		t.Fatal("expected one sync_state row")
	}
}

func TestRunInitialLoad_Idempotent(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(buildPageResult([]CVEItem{minimalCVEItem("CVE-2024-00001")}))
	}))
	defer srv.Close()

	syncer, _ := newTestSyncer(t, srv.URL)

	// First load
	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("first RunInitialLoad: %v", err)
	}
	firstCount := atomic.LoadInt32(&requestCount)

	// Second call should be a no-op (LastFullSync already set)
	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("second RunInitialLoad: %v", err)
	}
	secondCount := atomic.LoadInt32(&requestCount)

	if secondCount != firstCount {
		t.Errorf("second RunInitialLoad made %d extra NVD requests, want 0", secondCount-firstCount)
	}
}

func TestRunIncrementalSync_SkipsWhenNoFullSync(t *testing.T) {
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PageResult{TotalResults: 0})
	}))
	defer srv.Close()

	syncer, _ := newTestSyncer(t, srv.URL)
	if err := syncer.RunIncrementalSync(context.Background()); err != nil {
		t.Fatalf("RunIncrementalSync: %v", err)
	}
	if n := atomic.LoadInt32(&requestCount); n != 0 {
		t.Errorf("incremental sync made %d NVD requests before full sync, want 0", n)
	}
}

func TestRunIncrementalSync_RunsAfterFullSync(t *testing.T) {
	items := []CVEItem{minimalCVEItem("CVE-2024-00001")}
	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&requestCount, 1))
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// Initial load response
			json.NewEncoder(w).Encode(buildPageResult(items))
		} else {
			// Incremental sync response - no changes
			json.NewEncoder(w).Encode(PageResult{TotalResults: 0})
		}
	}))
	defer srv.Close()

	syncer, _ := newTestSyncer(t, srv.URL)
	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("RunInitialLoad: %v", err)
	}

	countAfterInitial := atomic.LoadInt32(&requestCount)
	if err := syncer.RunIncrementalSync(context.Background()); err != nil {
		t.Fatalf("RunIncrementalSync: %v", err)
	}
	if atomic.LoadInt32(&requestCount) <= countAfterInitial {
		t.Error("incremental sync made no NVD requests after full sync")
	}
}

func TestMatchWatches_NotifiesOnCPEMatch(t *testing.T) {
	cveItem := minimalCVEItem("CVE-2024-99999")
	cveItem.CVE.Configurations = []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	}{{
		Nodes: []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		}{{
			CPEMatch: []struct {
				Criteria string `json:"criteria"`
			}{{Criteria: "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}},
		}},
	}}

	srv := srvWithPages([]PageResult{buildPageResult([]CVEItem{cveItem})})
	defer srv.Close()

	db := testutil.NewTestDB(t)
	client := newTestClient(srv.URL)

	var notified []string
	syncer := NewSyncer(db, client, func(_ context.Context, actorID string) {
		notified = append(notified, actorID)
	})

	// Create a watch BEFORE the CVE's published date so it fires.
	db.Exec("INSERT INTO actors (id, display_name, kind, created_at) VALUES (?, ?, ?, datetime('now'))",
		"actor-1", "Test Agent", "agent")
	db.Exec("INSERT INTO cve_watches (id, actor_id, vendor_product, created_at) VALUES (?, ?, ?, ?)",
		"watch-1", "actor-1", "openssl", "2023-01-01T00:00:00Z")

	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("RunInitialLoad: %v", err)
	}

	if len(notified) == 0 {
		t.Error("expected notifier to be called for openssl watch, but it was not")
	}
	if len(notified) > 0 && notified[0] != "actor-1" {
		t.Errorf("notified actor: got %q, want %q", notified[0], "actor-1")
	}
}

func TestMatchWatches_NoMatchNoNotify(t *testing.T) {
	cveItem := minimalCVEItem("CVE-2024-11111")
	cveItem.CVE.Configurations = []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	}{{
		Nodes: []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		}{{
			CPEMatch: []struct {
				Criteria string `json:"criteria"`
			}{{Criteria: "cpe:2.3:a:somevendor:someproduct:1.0:*:*:*:*:*:*:*"}},
		}},
	}}

	srv := svrWithSinglePage(cveItem)
	defer srv.Close()

	db := testutil.NewTestDB(t)
	client := newTestClient(srv.URL)

	var notified bool
	syncer := NewSyncer(db, client, func(_ context.Context, _ string) {
		notified = true
	})

	db.Exec("INSERT INTO actors (id, display_name, kind, created_at) VALUES (?, ?, ?, datetime('now'))",
		"actor-2", "Test Agent 2", "agent")
	db.Exec("INSERT INTO cve_watches (id, actor_id, vendor_product, created_at) VALUES (?, ?, ?, datetime('now'))",
		"watch-2", "actor-2", "openssl")

	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("RunInitialLoad: %v", err)
	}
	if notified {
		t.Error("notifier should not be called when no CPE matches the watch")
	}
}

func TestRunInitialLoad_ResumesFromCheckpoint(t *testing.T) {
	// Two-page load. First run fetches only page 1, then "crashes". Second run
	// must skip page 1 (startIndex=2) and fetch only page 2.
	page1 := PageResult{TotalResults: 4, StartIndex: 0, ResultsPerPage: 2,
		Vulnerabilities: []CVEItem{minimalCVEItem("CVE-2024-R001"), minimalCVEItem("CVE-2024-R002")}}
	page2 := PageResult{TotalResults: 4, StartIndex: 2, ResultsPerPage: 2,
		Vulnerabilities: []CVEItem{minimalCVEItem("CVE-2024-R003"), minimalCVEItem("CVE-2024-R004")}}

	var calls []int // records which startIndex values were requested
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		si := 0
		if s := r.URL.Query().Get("startIndex"); s != "" {
			fmt.Sscanf(s, "%d", &si)
		}
		mu.Lock()
		calls = append(calls, si)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if si == 0 {
			json.NewEncoder(w).Encode(page1)
		} else {
			json.NewEncoder(w).Encode(page2)
		}
	}))
	defer srv.Close()

	db := testutil.NewTestDB(t)
	client := newTestClient(srv.URL)

	// Simulate a partial run: pre-seed FullLoadProgress=2 (page 1 already done).
	db.Exec("INSERT INTO sync_states (id, full_load_progress) VALUES (1, 2)")

	syncer := NewSyncer(db, client, nil)
	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("RunInitialLoad: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != 2 {
		t.Errorf("expected exactly one request with startIndex=2, got %v", calls)
	}
}

func svrWithSinglePage(item CVEItem) *httptest.Server {
	return srvWithPages([]PageResult{buildPageResult([]CVEItem{item})})
}

func TestMatchWatches_SkipsHistoricalCVEs(t *testing.T) {
	cveItem := minimalCVEItem("CVE-2024-55555") // published 2024-01-01
	cveItem.CVE.Configurations = []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	}{{Nodes: []struct {
		CPEMatch []struct {
			Criteria string `json:"criteria"`
		} `json:"cpeMatch"`
	}{{CPEMatch: []struct {
		Criteria string `json:"criteria"`
	}{{Criteria: "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}}}}}}

	srv := svrWithSinglePage(cveItem)
	defer srv.Close()

	db := testutil.NewTestDB(t)
	client := newTestClient(srv.URL)

	var notified bool
	syncer := NewSyncer(db, client, func(_ context.Context, _ string) { notified = true })

	db.Exec("INSERT INTO actors (id, display_name, kind, created_at) VALUES (?, ?, ?, datetime('now'))",
		"actor-3", "Test Agent 3", "agent")
	// Watch created AFTER the CVE's published date — should produce no hits.
	db.Exec("INSERT INTO cve_watches (id, actor_id, vendor_product, created_at) VALUES (?, ?, ?, ?)",
		"watch-3", "actor-3", "openssl", "2025-01-01T00:00:00Z")

	if err := syncer.RunInitialLoad(context.Background()); err != nil {
		t.Fatalf("RunInitialLoad: %v", err)
	}
	if notified {
		t.Error("notifier must not fire for CVEs published before the watch was created")
	}
}

func TestCPEVendorProducts(t *testing.T) {
	cases := []struct {
		cpes string
		want []string
	}{
		{"", nil},
		{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", []string{"openssl openssl"}},
		{
			"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:* cpe:2.3:a:lua-openssl_project:lua-openssl:0.7.7-1:*:*:*:*:*:*:*",
			[]string{"openssl openssl", "lua-openssl_project lua-openssl"},
		},
		{"cpe:2.3:a:apache:struts:2.5.33:*:*:*:*:*:*:*", []string{"apache struts"}},
	}
	for _, c := range cases {
		got := cpeVendorProducts(c.cpes)
		if len(got) != len(c.want) {
			t.Errorf("cpeVendorProducts(%q) = %v, want %v", c.cpes, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("cpeVendorProducts(%q)[%d] = %q, want %q", c.cpes, i, got[i], c.want[i])
			}
		}
	}
}
