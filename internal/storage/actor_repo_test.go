package storage_test

import (
	"strings"
	"testing"

	"github.com/JetManiack/mcp-cve/internal/storage"
	"github.com/JetManiack/mcp-cve/internal/testutil"
)

func TestCreateAgent_Success(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, err := storage.CreateAgent(db, "My Agent")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if actor.ID == "" {
		t.Error("expected non-empty ID")
	}
	if actor.DisplayName != "My Agent" {
		t.Errorf("DisplayName: got %q, want %q", actor.DisplayName, "My Agent")
	}
	if actor.Kind != storage.ActorKindAgent {
		t.Errorf("Kind: got %q, want %q", actor.Kind, storage.ActorKindAgent)
	}
}

func TestCreateAgent_EmptyName(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, err := storage.CreateAgent(db, "")
	if err != storage.ErrEmptyDisplayName {
		t.Errorf("expected ErrEmptyDisplayName, got %v", err)
	}
}

func TestIssueAgentToken_HasPrefix(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Token Agent")

	raw, err := storage.IssueAgentToken(db, actor.ID)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}
	if !strings.HasPrefix(raw, storage.TokenPrefix) {
		t.Errorf("token %q does not start with prefix %q", raw, storage.TokenPrefix)
	}
}

func TestAuthenticateAgentToken_ValidToken(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Auth Agent")
	raw, _ := storage.IssueAgentToken(db, actor.ID)

	got, err := storage.AuthenticateAgentToken(db, raw)
	if err != nil {
		t.Fatalf("AuthenticateAgentToken: %v", err)
	}
	if got.ID != actor.ID {
		t.Errorf("actor ID: got %q, want %q", got.ID, actor.ID)
	}
}

func TestAuthenticateAgentToken_InvalidToken(t *testing.T) {
	db := testutil.NewTestDB(t)
	_, err := storage.AuthenticateAgentToken(db, "cve_notavalidtoken")
	if err != storage.ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestAuthenticateAgentToken_RevokedToken(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "Revoke Agent")
	raw, _ := storage.IssueAgentToken(db, actor.ID)

	// Get the credential ID to revoke it
	creds, _ := storage.ListAgentCredentials(db, actor.ID)
	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}
	storage.RevokeAgentToken(db, creds[0].ID)

	_, err := storage.AuthenticateAgentToken(db, raw)
	if err != storage.ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken after revoke, got %v", err)
	}
}

func TestListAgents_OnlyAgents(t *testing.T) {
	db := testutil.NewTestDB(t)
	storage.CreateAgent(db, "Agent 1")
	storage.CreateAgent(db, "Agent 2")

	agents, err := storage.ListAgents(db)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	for _, a := range agents {
		if a.Kind != storage.ActorKindAgent {
			t.Errorf("ListAgents returned actor with Kind=%q", a.Kind)
		}
	}
}

func TestRevokeAllAgentCredentials(t *testing.T) {
	db := testutil.NewTestDB(t)
	actor, _ := storage.CreateAgent(db, "MultiToken Agent")
	raw1, _ := storage.IssueAgentToken(db, actor.ID)
	raw2, _ := storage.IssueAgentToken(db, actor.ID)

	if err := storage.RevokeAllAgentCredentials(db, actor.ID); err != nil {
		t.Fatalf("RevokeAllAgentCredentials: %v", err)
	}

	for _, raw := range []string{raw1, raw2} {
		_, err := storage.AuthenticateAgentToken(db, raw)
		if err != storage.ErrInvalidToken {
			t.Errorf("expected ErrInvalidToken after RevokeAll, got %v", err)
		}
	}
}

func TestActorNamesByID(t *testing.T) {
	db := testutil.NewTestDB(t)
	a1, _ := storage.CreateAgent(db, "Alice")
	a2, _ := storage.CreateAgent(db, "Bob")

	names, err := storage.ActorNamesByID(db, []string{a1.ID, a2.ID, "unknown-id"})
	if err != nil {
		t.Fatalf("ActorNamesByID: %v", err)
	}
	if names[a1.ID] != "Alice" {
		t.Errorf("a1 name: got %q, want %q", names[a1.ID], "Alice")
	}
	if names[a2.ID] != "Bob" {
		t.Errorf("a2 name: got %q, want %q", names[a2.ID], "Bob")
	}
	if v, ok := names["unknown-id"]; ok && v != "" {
		t.Errorf("unknown-id should be absent or empty, got %q", v)
	}
}

func TestActorNamesByID_EmptySlice(t *testing.T) {
	db := testutil.NewTestDB(t)
	names, err := storage.ActorNamesByID(db, nil)
	if err != nil {
		t.Fatalf("ActorNamesByID(nil): %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected empty map, got %v", names)
	}
}

func TestActorsWithActiveToken(t *testing.T) {
	db := testutil.NewTestDB(t)
	a1, _ := storage.CreateAgent(db, "Active Agent")
	a2, _ := storage.CreateAgent(db, "No-Token Agent")
	storage.IssueAgentToken(db, a1.ID)

	active, err := storage.ActorsWithActiveToken(db)
	if err != nil {
		t.Fatalf("ActorsWithActiveToken: %v", err)
	}
	if !active[a1.ID] {
		t.Errorf("a1 should be active")
	}
	if active[a2.ID] {
		t.Errorf("a2 should not be active (no token)")
	}
}
