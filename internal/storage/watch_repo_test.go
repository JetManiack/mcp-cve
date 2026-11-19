package storage_test

import (
	"testing"
	"time"

	"github.com/JetManiack/mcp-cve/internal/storage"
	"github.com/JetManiack/mcp-cve/internal/testutil"
)

func TestCreateWatch_Success(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent A")

	watch, err := storage.CreateWatch(db, actor.ID, "openssl")
	if err != nil {
		t.Fatalf("CreateWatch: %v", err)
	}
	if watch.ID == "" {
		t.Error("expected non-empty watch ID")
	}
	if watch.VendorProduct != "openssl" {
		t.Errorf("VendorProduct: got %q, want %q", watch.VendorProduct, "openssl")
	}
	if watch.ActorID != actor.ID {
		t.Errorf("ActorID: got %q, want %q", watch.ActorID, actor.ID)
	}
}

func TestCreateWatch_EmptyVendorProduct(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent B")

	_, err := storage.CreateWatch(db, actor.ID, "")
	if err != storage.ErrEmptyVendorProduct {
		t.Errorf("expected ErrEmptyVendorProduct, got %v", err)
	}

	_, err = storage.CreateWatch(db, actor.ID, "   ")
	if err != storage.ErrEmptyVendorProduct {
		t.Errorf("expected ErrEmptyVendorProduct for whitespace, got %v", err)
	}
}

func TestDeleteWatch_Success(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent C")
	watch, _ := storage.CreateWatch(db, actor.ID, "apache")

	if err := storage.DeleteWatch(db, actor.ID, watch.ID); err != nil {
		t.Fatalf("DeleteWatch: %v", err)
	}

	watches, _ := storage.ListWatches(db, actor.ID)
	for _, w := range watches {
		if w.ID == watch.ID {
			t.Error("deleted watch still appears in list")
		}
	}
}

func TestDeleteWatch_WrongActor(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor1, _ := storage.CreateAgent(db, "Agent D1")
	actor2, _ := storage.CreateAgent(db, "Agent D2")
	watch, _ := storage.CreateWatch(db, actor1.ID, "nginx")

	// actor2 tries to delete actor1's watch
	err := storage.DeleteWatch(db, actor2.ID, watch.ID)
	if err != storage.ErrWatchNotFound {
		t.Errorf("expected ErrWatchNotFound, got %v", err)
	}
}

func TestDeleteWatch_NotFound(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent E")

	err := storage.DeleteWatch(db, actor.ID, "00000000-0000-0000-0000-000000000000")
	if err != storage.ErrWatchNotFound {
		t.Errorf("expected ErrWatchNotFound, got %v", err)
	}
}

func TestListWatches_ScopedToActor(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor1, _ := storage.CreateAgent(db, "Agent F1")
	actor2, _ := storage.CreateAgent(db, "Agent F2")
	storage.CreateWatch(db, actor1.ID, "openssl")
	storage.CreateWatch(db, actor1.ID, "apache")
	storage.CreateWatch(db, actor2.ID, "nginx")

	watches, err := storage.ListWatches(db, actor1.ID)
	if err != nil {
		t.Fatalf("ListWatches: %v", err)
	}
	if len(watches) != 2 {
		t.Errorf("actor1 watches: got %d, want 2", len(watches))
	}
	for _, w := range watches {
		if w.ActorID != actor1.ID {
			t.Errorf("unexpected actor_id %q in actor1's watch list", w.ActorID)
		}
	}
}

func TestListAllWatches(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor1, _ := storage.CreateAgent(db, "Agent G1")
	actor2, _ := storage.CreateAgent(db, "Agent G2")
	storage.CreateWatch(db, actor1.ID, "openssl")
	storage.CreateWatch(db, actor2.ID, "apache")

	watches, err := storage.ListAllWatches(db)
	if err != nil {
		t.Fatalf("ListAllWatches: %v", err)
	}
	if len(watches) < 2 {
		t.Errorf("expected at least 2 watches, got %d", len(watches))
	}
}

func TestRecordWatchHit_CreatesAndIdempotent(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent H")
	watch, _ := storage.CreateWatch(db, actor.ID, "openssl")
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00080", "HIGH", "cve", "", now))

	if err := storage.RecordWatchHit(db, watch.ID, "CVE-2024-00080"); err != nil {
		t.Fatalf("first RecordWatchHit: %v", err)
	}
	// Idempotent: same call must not create a duplicate
	if err := storage.RecordWatchHit(db, watch.ID, "CVE-2024-00080"); err != nil {
		t.Fatalf("second RecordWatchHit (idempotent): %v", err)
	}

	hits, _ := storage.GetUnseenHits(db, actor.ID)
	if len(hits) != 1 {
		t.Errorf("expected 1 hit, got %d", len(hits))
	}
}

func TestGetUnseenHits_OnlyUnseen(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent I")
	watch, _ := storage.CreateWatch(db, actor.ID, "openssl")
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00090", "HIGH", "a", "", now))
	storage.UpsertCVE(db, makeCVE("CVE-2024-00091", "HIGH", "b", "", now.Add(-time.Second)))
	storage.RecordWatchHit(db, watch.ID, "CVE-2024-00090")
	storage.RecordWatchHit(db, watch.ID, "CVE-2024-00091")

	// Mark one as seen
	storage.MarkHitsSeen(db, actor.ID)

	// After marking all seen, unseen should be empty
	hits, err := storage.GetUnseenHits(db, actor.ID)
	if err != nil {
		t.Fatalf("GetUnseenHits: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("expected 0 unseen hits after MarkHitsSeen, got %d", len(hits))
	}
}

func TestGetUnseenHits_ScopedToActor(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor1, _ := storage.CreateAgent(db, "Agent J1")
	actor2, _ := storage.CreateAgent(db, "Agent J2")
	watch1, _ := storage.CreateWatch(db, actor1.ID, "openssl")
	watch2, _ := storage.CreateWatch(db, actor2.ID, "openssl")
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00100", "HIGH", "c", "", now))
	storage.RecordWatchHit(db, watch1.ID, "CVE-2024-00100")
	storage.RecordWatchHit(db, watch2.ID, "CVE-2024-00100")

	hits1, _ := storage.GetUnseenHits(db, actor1.ID)
	hits2, _ := storage.GetUnseenHits(db, actor2.ID)

	if len(hits1) != 1 {
		t.Errorf("actor1 unseen hits: got %d, want 1", len(hits1))
	}
	if len(hits2) != 1 {
		t.Errorf("actor2 unseen hits: got %d, want 1", len(hits2))
	}
}

func TestMarkHitsSeen_DoesNotAffectOtherActors(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor1, _ := storage.CreateAgent(db, "Agent K1")
	actor2, _ := storage.CreateAgent(db, "Agent K2")
	watch1, _ := storage.CreateWatch(db, actor1.ID, "openssl")
	watch2, _ := storage.CreateWatch(db, actor2.ID, "openssl")
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00110", "HIGH", "d", "", now))
	storage.RecordWatchHit(db, watch1.ID, "CVE-2024-00110")
	storage.RecordWatchHit(db, watch2.ID, "CVE-2024-00110")

	storage.MarkHitsSeen(db, actor1.ID)

	// actor1 has no unseen; actor2 still has 1
	hits1, _ := storage.GetUnseenHits(db, actor1.ID)
	hits2, _ := storage.GetUnseenHits(db, actor2.ID)

	if len(hits1) != 0 {
		t.Errorf("actor1 should have 0 unseen hits, got %d", len(hits1))
	}
	if len(hits2) != 1 {
		t.Errorf("actor2 should still have 1 unseen hit, got %d", len(hits2))
	}
}

func TestGetAllHits_IncludesSeen(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Agent L")
	watch, _ := storage.CreateWatch(db, actor.ID, "openssl")
	now := time.Now()
	storage.UpsertCVE(db, makeCVE("CVE-2024-00120", "HIGH", "e", "", now))
	storage.RecordWatchHit(db, watch.ID, "CVE-2024-00120")
	storage.MarkHitsSeen(db, actor.ID)

	all, err := storage.GetAllHits(db, actor.ID)
	if err != nil {
		t.Fatalf("GetAllHits: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 hit (including seen), got %d", len(all))
	}
}
