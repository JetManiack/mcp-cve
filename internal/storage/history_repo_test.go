package storage_test

import (
	"testing"
	"time"

	"github.com/JetManiack/mcp-cve/internal/storage"
	"github.com/JetManiack/mcp-cve/internal/testutil"
)

func recordCall(db interface{}, actorID, tool string, isErr bool, calledAt time.Time) *storage.ToolCall {
	return &storage.ToolCall{
		ActorID:    actorID,
		Tool:       tool,
		InputJSON:  `{"x":1}`,
		OutputJSON: `{"y":2}`,
		IsError:    isErr,
		DurationMS: 10,
		CalledAt:   calledAt,
	}
}

func TestRecordToolCall_AssignsID(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "History Agent")
	call := recordCall(nil, actor.ID, "get_cve", false, time.Now())
	call.ActorID = actor.ID

	if err := storage.RecordToolCall(db, call); err != nil {
		t.Fatalf("RecordToolCall: %v", err)
	}
	if call.ID == "" {
		t.Error("expected RecordToolCall to assign an ID")
	}
}

func TestListToolCalls_AllFilter(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "List Agent")
	now := time.Now()
	for i := 0; i < 3; i++ {
		c := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", CalledAt: now.Add(time.Duration(-i) * time.Second)}
		storage.RecordToolCall(db, c)
	}

	calls, _, err := storage.ListToolCalls(db, storage.HistoryFilter{ActorID: actor.ID})
	if err != nil {
		t.Fatalf("ListToolCalls: %v", err)
	}
	if len(calls) != 3 {
		t.Errorf("expected 3 calls, got %d", len(calls))
	}
	// Newest first
	if calls[0].CalledAt.Before(calls[1].CalledAt) {
		t.Error("results should be newest-first")
	}
}

func TestListToolCalls_FilterByTool(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Filter Agent")
	now := time.Now()
	c1 := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", CalledAt: now}
	c2 := &storage.ToolCall{ActorID: actor.ID, Tool: "search_cves", CalledAt: now.Add(-time.Second)}
	storage.RecordToolCall(db, c1)
	storage.RecordToolCall(db, c2)

	calls, _, err := storage.ListToolCalls(db, storage.HistoryFilter{ActorID: actor.ID, Tool: "get_cve"})
	if err != nil {
		t.Fatalf("ListToolCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Tool != "get_cve" {
		t.Errorf("unexpected tool %q", calls[0].Tool)
	}
}

func TestListToolCalls_FilterByError(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Error Filter Agent")
	now := time.Now()
	ok := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", IsError: false, CalledAt: now}
	bad := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", IsError: true, CalledAt: now.Add(-time.Second)}
	storage.RecordToolCall(db, ok)
	storage.RecordToolCall(db, bad)

	isErr := true
	calls, _, err := storage.ListToolCalls(db, storage.HistoryFilter{ActorID: actor.ID, IsError: &isErr})
	if err != nil {
		t.Fatalf("ListToolCalls: %v", err)
	}
	if len(calls) != 1 || !calls[0].IsError {
		t.Errorf("expected 1 error call, got %d", len(calls))
	}
}

func TestListToolCalls_Pagination(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Page Agent")
	now := time.Now()
	for i := 0; i < 5; i++ {
		c := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", CalledAt: now.Add(time.Duration(-i) * time.Second)}
		storage.RecordToolCall(db, c)
	}

	page1, cursor, err := storage.ListToolCalls(db, storage.HistoryFilter{ActorID: actor.ID, Limit: 2})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1))
	}
	if cursor == "" {
		t.Fatal("expected non-empty cursor")
	}

	page2, _, err := storage.ListToolCalls(db, storage.HistoryFilter{ActorID: actor.ID, Limit: 2, Cursor: cursor})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2: got %d, want 2", len(page2))
	}
	for _, c1 := range page1 {
		for _, c2 := range page2 {
			if c1.ID == c2.ID {
				t.Errorf("overlap between pages: %q in both", c1.ID)
			}
		}
	}
}

func TestListToolCalls_UnknownCursor(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, _, err := storage.ListToolCalls(db, storage.HistoryFilter{Cursor: "nonexistent"})
	if err != storage.ErrUnknownCursor {
		t.Errorf("expected ErrUnknownCursor, got %v", err)
	}
}

func TestGetToolCall_Found(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "GetCall Agent")
	call := &storage.ToolCall{ActorID: actor.ID, Tool: "search_cves", CalledAt: time.Now()}
	storage.RecordToolCall(db, call)

	got, err := storage.GetToolCall(db, call.ID)
	if err != nil {
		t.Fatalf("GetToolCall: %v", err)
	}
	if got.ID != call.ID {
		t.Errorf("ID: got %q, want %q", got.ID, call.ID)
	}
}

func TestGetToolCall_NotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, err := storage.GetToolCall(db, "nonexistent-id")
	if err != storage.ErrToolCallNotFound {
		t.Errorf("expected ErrToolCallNotFound, got %v", err)
	}
}

func TestDistinctTools(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Distinct Agent")
	now := time.Now()
	for _, tool := range []string{"get_cve", "search_cves", "get_cve"} {
		c := &storage.ToolCall{ActorID: actor.ID, Tool: tool, CalledAt: now}
		storage.RecordToolCall(db, c)
		now = now.Add(-time.Second)
	}

	tools, err := storage.DistinctTools(db)
	if err != nil {
		t.Fatalf("DistinctTools: %v", err)
	}
	seen := make(map[string]bool)
	for _, tool := range tools {
		if seen[tool] {
			t.Errorf("duplicate tool %q in DistinctTools result", tool)
		}
		seen[tool] = true
	}
	if !seen["get_cve"] || !seen["search_cves"] {
		t.Errorf("missing expected tools; got %v", tools)
	}
}

func TestPruneToolCalls_DeletesOld(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Prune Agent")
	old := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", CalledAt: time.Now().Add(-48 * time.Hour)}
	recent := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", CalledAt: time.Now()}
	storage.RecordToolCall(db, old)
	storage.RecordToolCall(db, recent)

	deleted, err := storage.PruneToolCalls(db, 24*time.Hour)
	if err != nil {
		t.Fatalf("PruneToolCalls: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted: got %d, want 1", deleted)
	}

	_, err = storage.GetToolCall(db, old.ID)
	if err != storage.ErrToolCallNotFound {
		t.Error("old call should have been pruned")
	}
	_, err = storage.GetToolCall(db, recent.ID)
	if err != nil {
		t.Error("recent call should not have been pruned")
	}
}

func TestPruneToolCalls_ZeroRetentionIsNoop(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "NoPrune Agent")
	c := &storage.ToolCall{ActorID: actor.ID, Tool: "get_cve", CalledAt: time.Now().Add(-100 * 24 * time.Hour)}
	storage.RecordToolCall(db, c)

	deleted, err := storage.PruneToolCalls(db, 0)
	if err != nil {
		t.Fatalf("PruneToolCalls: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted with zero retention, got %d", deleted)
	}
}
