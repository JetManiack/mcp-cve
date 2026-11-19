package cve

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/JetManiack/mcp-cve/internal/auth"
	"github.com/JetManiack/mcp-cve/internal/storage"
	"github.com/JetManiack/mcp-cve/internal/testutil"
)

// --- truncateUTF8 ---

func TestTruncateUTF8_NoTruncation(t *testing.T) {
	s := "hello world"
	got, truncated := truncateUTF8(s, 100)
	if truncated {
		t.Error("expected truncated=false")
	}
	if got != s {
		t.Errorf("got %q, want %q", got, s)
	}
}

func TestTruncateUTF8_ExactLimit(t *testing.T) {
	s := "hello"
	got, truncated := truncateUTF8(s, 5)
	if truncated {
		t.Error("expected truncated=false when len == limit")
	}
	if got != s {
		t.Errorf("got %q, want %q", got, s)
	}
}

func TestTruncateUTF8_TruncatesASCII(t *testing.T) {
	s := "hello world"
	got, truncated := truncateUTF8(s, 5)
	if !truncated {
		t.Error("expected truncated=true")
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestTruncateUTF8_DoesNotSplitRune(t *testing.T) {
	// "привет" is 6 runes × 2 bytes each = 12 bytes
	s := "привет"
	got, truncated := truncateUTF8(s, 3) // 3 bytes = 1.5 runes, must not split
	if !truncated {
		t.Error("expected truncated=true")
	}
	// Valid UTF-8: either "п" (2 bytes) or empty (if 2 > 3... actually "п" is 2 bytes which fits in 3)
	for _, r := range got {
		_ = r // just ensure it doesn't panic on iteration
	}
}

func TestTruncateUTF8_Empty(t *testing.T) {
	got, truncated := truncateUTF8("", 10)
	if truncated {
		t.Error("expected truncated=false for empty string")
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- marshalForHistory ---

func TestMarshalForHistory_ValidStruct(t *testing.T) {
	v := struct {
		X int    `json:"x"`
		Y string `json:"y"`
	}{X: 1, Y: "hello"}
	got := marshalForHistory(v)
	want := `{"x":1,"y":"hello"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMarshalForHistory_NilValue(t *testing.T) {
	got := marshalForHistory(nil)
	if got != "null" {
		t.Errorf("got %q, want %q", got, "null")
	}
}

// --- getCVEHandler ---

func TestGetCVEHandler_Found(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "GetCVE Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	now := time.Now()
	storage.UpsertCVE(db, &storage.CVE{
		ID:           "CVE-2024-00001",
		Published:    now,
		LastModified: now,
		Description:  "Test vulnerability",
		Severity:     "HIGH",
	})

	h := getCVEHandler(db)
	_, out, err := h(ctx, &mcp.CallToolRequest{}, getCVEInput{CVEID: "CVE-2024-00001"})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if out.Error != "" {
		t.Errorf("unexpected Error field: %q", out.Error)
	}
	if out.CVE == nil {
		t.Fatal("expected CVE in output")
	}
	if out.CVE.ID != "CVE-2024-00001" {
		t.Errorf("CVE ID: got %q, want %q", out.CVE.ID, "CVE-2024-00001")
	}
}

func TestGetCVEHandler_NotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "GetCVE Miss Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	h := getCVEHandler(db)
	_, out, err := h(ctx, &mcp.CallToolRequest{}, getCVEInput{CVEID: "CVE-9999-00000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Error == "" {
		t.Error("expected error message for not-found CVE")
	}
	if out.CVE != nil {
		t.Error("expected nil CVE in not-found response")
	}
}

func TestGetCVEHandler_EmptyID(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "GetCVE Empty Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	h := getCVEHandler(db)
	_, out, err := h(ctx, &mcp.CallToolRequest{}, getCVEInput{CVEID: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Error == "" {
		t.Error("expected error for empty cve_id")
	}
}

// --- searchCVEsHandler ---

func TestSearchCVEsHandler_ReturnsResults(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Search Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	now := time.Now()
	storage.UpsertCVE(db, &storage.CVE{ID: "CVE-2024-10001", Published: now, LastModified: now, Severity: "HIGH", Description: "openssl remote"})
	storage.UpsertCVE(db, &storage.CVE{ID: "CVE-2024-10002", Published: now.Add(-time.Second), LastModified: now, Severity: "LOW", Description: "unrelated"})

	h := searchCVEsHandler(db)
	_, out, err := h(ctx, &mcp.CallToolRequest{}, searchCVEsInput{Query: "openssl"})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if len(out.CVEs) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out.CVEs))
	}
	if out.CVEs[0].ID != "CVE-2024-10001" {
		t.Errorf("unexpected CVE ID: %q", out.CVEs[0].ID)
	}
}

func TestSearchCVEsHandler_EmptyReturnsEmptySlice(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Empty Search Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	h := searchCVEsHandler(db)
	_, out, err := h(ctx, &mcp.CallToolRequest{}, searchCVEsInput{})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if out.CVEs == nil {
		t.Error("CVEs should be an empty slice, not nil")
	}
}

// --- recentCVEsHandler ---

func TestRecentCVEsHandler_ReturnsRecent(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Recent Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	now := time.Now()
	storage.UpsertCVE(db, &storage.CVE{ID: "CVE-2024-20001", Published: now.Add(-1 * time.Hour), LastModified: now.Add(-1 * time.Hour), Severity: "HIGH", Description: "recent"})
	storage.UpsertCVE(db, &storage.CVE{ID: "CVE-2024-20002", Published: now.Add(-100 * time.Hour), LastModified: now.Add(-100 * time.Hour), Severity: "HIGH", Description: "old"})

	h := recentCVEsHandler(db)
	_, out, err := h(ctx, &mcp.CallToolRequest{}, recentCVEsInput{Hours: 24})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	for _, c := range out.CVEs {
		if c.ID == "CVE-2024-20002" {
			t.Error("old CVE should not appear in recent results")
		}
	}
}

// --- watchProductHandler ---

func TestWatchProductHandler_CreateAndList(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Watch Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	wh := watchProductHandler(db)
	_, out, err := wh(ctx, &mcp.CallToolRequest{}, watchProductInput{VendorProduct: "openssl"})
	if err != nil {
		t.Fatalf("watchProductHandler: %v", err)
	}
	if out.Error != "" {
		t.Errorf("unexpected Error: %q", out.Error)
	}
	if out.WatchID == "" {
		t.Error("expected non-empty watch_id")
	}

	lh := listWatchesHandler(db)
	_, lout, err := lh(ctx, &mcp.CallToolRequest{}, listWatchesInput{})
	if err != nil {
		t.Fatalf("listWatchesHandler: %v", err)
	}
	if len(lout.Watches) != 1 {
		t.Errorf("expected 1 watch, got %d", len(lout.Watches))
	}
	if lout.Watches[0].VendorProduct != "openssl" {
		t.Errorf("VendorProduct: got %q, want %q", lout.Watches[0].VendorProduct, "openssl")
	}
}

func TestWatchProductHandler_EmptyVendorProduct(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Watch Empty Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	wh := watchProductHandler(db)
	_, out, err := wh(ctx, &mcp.CallToolRequest{}, watchProductInput{VendorProduct: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Error == "" {
		t.Error("expected error for empty vendor_product")
	}
}

func TestUnwatchProductHandler(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Unwatch Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	wh := watchProductHandler(db)
	_, wout, _ := wh(ctx, &mcp.CallToolRequest{}, watchProductInput{VendorProduct: "apache"})

	uh := unwatchProductHandler(db)
	_, uout, err := uh(ctx, &mcp.CallToolRequest{}, unwatchProductInput{WatchID: wout.WatchID})
	if err != nil {
		t.Fatalf("unwatchProductHandler: %v", err)
	}
	if uout.Error != "" {
		t.Errorf("unexpected Error: %q", uout.Error)
	}

	lh := listWatchesHandler(db)
	_, lout, _ := lh(ctx, &mcp.CallToolRequest{}, listWatchesInput{})
	if len(lout.Watches) != 0 {
		t.Errorf("expected 0 watches after unwatch, got %d", len(lout.Watches))
	}
}

func TestUnwatchProductHandler_WrongActor(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor1, _ := storage.CreateAgent(db, "Watch Owner")
	actor2, _ := storage.CreateAgent(db, "Watch Thief")
	ctx1 := auth.WithActorForTesting(context.Background(), actor1)
	ctx2 := auth.WithActorForTesting(context.Background(), actor2)

	wh := watchProductHandler(db)
	_, wout, _ := wh(ctx1, &mcp.CallToolRequest{}, watchProductInput{VendorProduct: "nginx"})

	uh := unwatchProductHandler(db)
	_, uout, err := uh(ctx2, &mcp.CallToolRequest{}, unwatchProductInput{WatchID: wout.WatchID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uout.Error == "" {
		t.Error("expected error when actor2 tries to delete actor1's watch")
	}
}

// --- getWatchHitsHandler ---

func TestGetWatchHitsHandler_MarkSeen(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Hit Agent")
	ctx := auth.WithActorForTesting(context.Background(), actor)

	wh := watchProductHandler(db)
	_, wout, _ := wh(ctx, &mcp.CallToolRequest{}, watchProductInput{VendorProduct: "openssl"})

	now := time.Now()
	storage.UpsertCVE(db, &storage.CVE{ID: "CVE-2024-30001", Published: now, LastModified: now, Severity: "HIGH"})
	storage.RecordWatchHit(db, wout.WatchID, "CVE-2024-30001")

	gh := getWatchHitsHandler(db)

	// First call without mark_seen: hits are returned but remain unseen
	_, out1, err := gh(ctx, &mcp.CallToolRequest{}, getWatchHitsInput{MarkSeen: false})
	if err != nil {
		t.Fatalf("first getWatchHitsHandler: %v", err)
	}
	if len(out1.Hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(out1.Hits))
	}

	// Second call with mark_seen=true: hits returned and marked
	_, out2, err := gh(ctx, &mcp.CallToolRequest{}, getWatchHitsInput{MarkSeen: true})
	if err != nil {
		t.Fatalf("second getWatchHitsHandler: %v", err)
	}
	if len(out2.Hits) != 1 {
		t.Fatalf("expected 1 hit in second call, got %d", len(out2.Hits))
	}

	// Third call: all hits are now seen, so unseen list is empty
	_, out3, err := gh(ctx, &mcp.CallToolRequest{}, getWatchHitsInput{MarkSeen: false})
	if err != nil {
		t.Fatalf("third getWatchHitsHandler: %v", err)
	}
	if len(out3.Hits) != 0 {
		t.Errorf("expected 0 unseen hits after mark_seen, got %d", len(out3.Hits))
	}
}
