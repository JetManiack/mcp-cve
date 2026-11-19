package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JetManiack/mcp-cve/internal/health"
)

func TestLivez_Always200(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	health.Livez(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Livez: got %d, want 200", rec.Code)
	}
}

func okPing(_ context.Context) error { return nil }

func failPing(_ context.Context) error { return errors.New("db down") }

func TestReadyz_AllReady(t *testing.T) {
	rc := health.ReadyChecker{
		Ping:            okPing,
		MigrationsReady: true,
		OIDCReady:       true,
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	rc.Readyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}

	var body struct {
		Status string `json:"status"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.Status != "ready" {
		t.Errorf("status field: got %q, want %q", body.Status, "ready")
	}
}

func TestReadyz_MigrationsNotReady(t *testing.T) {
	rc := health.ReadyChecker{
		Ping:            okPing,
		MigrationsReady: false,
		OIDCReady:       true,
	}

	rec := httptest.NewRecorder()
	rc.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", rec.Code)
	}
	var body struct {
		Status  string   `json:"status"`
		Failing []string `json:"failing"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.Status != "not_ready" {
		t.Errorf("status field: got %q, want %q", body.Status, "not_ready")
	}
	if !contains(body.Failing, "migrations") {
		t.Errorf("failing should include %q; got %v", "migrations", body.Failing)
	}
}

func TestReadyz_OIDCNotReady(t *testing.T) {
	rc := health.ReadyChecker{
		Ping:            okPing,
		MigrationsReady: true,
		OIDCReady:       false,
	}

	rec := httptest.NewRecorder()
	rc.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", rec.Code)
	}
	var body struct {
		Failing []string `json:"failing"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if !contains(body.Failing, "oidc_discovery") {
		t.Errorf("failing should include %q; got %v", "oidc_discovery", body.Failing)
	}
}

func TestReadyz_DBPingFails(t *testing.T) {
	rc := health.ReadyChecker{
		Ping:            failPing,
		MigrationsReady: true,
		OIDCReady:       true,
	}

	rec := httptest.NewRecorder()
	rc.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", rec.Code)
	}
	var body struct {
		Failing []string `json:"failing"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if !contains(body.Failing, "database") {
		t.Errorf("failing should include %q; got %v", "database", body.Failing)
	}
}

func TestReadyz_MultipleFailures(t *testing.T) {
	rc := health.ReadyChecker{
		Ping:            failPing,
		MigrationsReady: false,
		OIDCReady:       false,
	}

	rec := httptest.NewRecorder()
	rc.Readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", rec.Code)
	}
	var body struct {
		Failing []string `json:"failing"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if len(body.Failing) < 3 {
		t.Errorf("expected at least 3 failing items, got %v", body.Failing)
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
