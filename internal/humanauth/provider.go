// Package humanauth authenticates the humans who access the admin UI, as
// opposed to the agents that call MCP tools (see internal/auth).
package humanauth

import "net/http"

// Identity is the provider-agnostic result of authenticating a request.
type Identity struct {
	Subject     string
	DisplayName string
	Role        string
}

// Provider authenticates an incoming HTTP request and returns the identity
// making it.
type Provider interface {
	Authenticate(r *http.Request) (*Identity, error)
}

// StubProvider always authenticates the same fixed test identity, with NO
// real credential check whatsoever.
//
// ⚠️ It exists only so the app can be run locally without a Keycloak
// instance, and is reachable only via --auth-stub. Never use in production.
type StubProvider struct{}

func (StubProvider) Authenticate(r *http.Request) (*Identity, error) {
	return &Identity{
		Subject:     "stub-user",
		DisplayName: "Local Tester",
		Role:        "admin",
	}, nil
}
