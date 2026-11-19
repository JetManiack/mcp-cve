package mcpserver

import (
	"testing"
)

func TestWatchResourceURI_RoundTrip(t *testing.T) {
	actorID := "550e8400-e29b-41d4-a716-446655440000"
	uri := watchResourceURI(actorID)

	got, ok := actorIDFromWatchURI(uri)
	if !ok {
		t.Fatalf("actorIDFromWatchURI(%q): ok=false", uri)
	}
	if got != actorID {
		t.Errorf("got %q, want %q", got, actorID)
	}
}

func TestActorIDFromWatchURI_WrongPrefix(t *testing.T) {
	_, ok := actorIDFromWatchURI("https://example.com/watches/actor-id")
	if ok {
		t.Error("expected ok=false for non-watch URI")
	}
}

func TestActorIDFromWatchURI_EmptyActorID(t *testing.T) {
	_, ok := actorIDFromWatchURI(watchResourceURIPrefix)
	if ok {
		t.Error("expected ok=false for URI with empty actor ID segment")
	}
}

func TestWatchResourceURI_Format(t *testing.T) {
	uri := watchResourceURI("my-actor")
	const want = "cve://watches/my-actor"
	if uri != want {
		t.Errorf("got %q, want %q", uri, want)
	}
}
