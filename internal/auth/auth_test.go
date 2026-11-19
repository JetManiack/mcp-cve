package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JetManiack/mcp-cve/internal/auth"
	"github.com/JetManiack/mcp-cve/internal/storage"
	"github.com/JetManiack/mcp-cve/internal/testutil"
)

func TestActorFromContext_Present(t *testing.T) {
	actor := &storage.Actor{ID: "test-id", DisplayName: "Test", Kind: storage.ActorKindAgent}
	ctx := auth.WithActorForTesting(t.Context(), actor)
	got, ok := auth.ActorFromContext(ctx)
	if !ok {
		t.Fatal("ActorFromContext: expected ok=true")
	}
	if got.ID != "test-id" {
		t.Errorf("actor ID: got %q, want %q", got.ID, "test-id")
	}
}

func TestActorFromContext_Absent(t *testing.T) {
	_, ok := auth.ActorFromContext(t.Context())
	if ok {
		t.Error("expected ok=false for empty context")
	}
}

func TestRequireBearer_MissingHeader(t *testing.T) {
	db := testutil.NewTestDB(t)
	handler := auth.RequireBearer(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestRequireBearer_InvalidToken(t *testing.T) {
	db := testutil.NewTestDB(t)
	var reached bool
	handler := auth.RequireBearer(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer cve_invalidtoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if reached {
		t.Error("inner handler should not be called with invalid token")
	}
}

func TestRequireBearer_ValidToken(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Bearer Agent")
	raw, _ := storage.IssueAgentToken(db, actor.ID)

	var injectedActor *storage.Actor
	handler := auth.RequireBearer(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injectedActor, _ = auth.ActorFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
	if injectedActor == nil {
		t.Fatal("actor not injected into context")
	}
	if injectedActor.ID != actor.ID {
		t.Errorf("actor ID: got %q, want %q", injectedActor.ID, actor.ID)
	}
}

func TestRequireBearer_NonBearerScheme(t *testing.T) {
	db := testutil.NewTestDB(t)
	handler := auth.RequireBearer(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}
