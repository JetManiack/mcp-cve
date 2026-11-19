package nvd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestClient returns a Client pointed at the given test server URL with
// no rate-limit delay so tests run quickly.
func newTestClient(serverURL string) *Client {
	c := NewClient("")
	c.baseURL = serverURL
	c.minInterval = 0
	return c
}

func singlePageResponse(total int, items []CVEItem) PageResult {
	return PageResult{
		TotalResults:    total,
		StartIndex:      0,
		ResultsPerPage:  len(items),
		Vulnerabilities: items,
	}
}

func minimalCVEItem(id string) CVEItem {
	item := CVEItem{}
	item.CVE.ID = id
	item.CVE.SourceIdentifier = "test@example.com"
	item.CVE.Published = "2024-01-01T00:00:00.000"
	item.CVE.LastModified = "2024-01-02T00:00:00.000"
	item.CVE.Descriptions = []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{{Lang: "en", Value: "Test vulnerability"}}
	return item
}

func TestFetchPage_Success(t *testing.T) {
	page := singlePageResponse(1, []CVEItem{minimalCVEItem("CVE-2024-00001")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	got, err := client.FetchPage(0)
	if err != nil {
		t.Fatalf("FetchPage: %v", err)
	}
	if got.TotalResults != 1 {
		t.Errorf("TotalResults: got %d, want 1", got.TotalResults)
	}
	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("Vulnerabilities count: got %d, want 1", len(got.Vulnerabilities))
	}
	if got.Vulnerabilities[0].CVE.ID != "CVE-2024-00001" {
		t.Errorf("CVE ID: got %q, want %q", got.Vulnerabilities[0].CVE.ID, "CVE-2024-00001")
	}
}

func TestFetchPage_QueryParams(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singlePageResponse(0, nil))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := client.FetchPage(100)
	if err != nil {
		t.Fatalf("FetchPage: %v", err)
	}

	q := capturedQuery
	if q == "" {
		t.Fatal("no query params captured")
	}
	// Should include startIndex=100 and resultsPerPage=2000
	if q != "resultsPerPage=2000&startIndex=100" && q != "startIndex=100&resultsPerPage=2000" {
		// Accept any order; just verify both are present
		if !contains(q, "startIndex=100") {
			t.Errorf("missing startIndex=100 in %q", q)
		}
		if !contains(q, "resultsPerPage=2000") {
			t.Errorf("missing resultsPerPage=2000 in %q", q)
		}
	}
}

func TestFetchModifiedSince_QueryParams(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singlePageResponse(0, nil))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	_, err := client.FetchModifiedSince(start, end, 0)
	if err != nil {
		t.Fatalf("FetchModifiedSince: %v", err)
	}

	if !contains(capturedQuery, "lastModStartDate=") {
		t.Errorf("missing lastModStartDate in %q", capturedQuery)
	}
	if !contains(capturedQuery, "lastModEndDate=") {
		t.Errorf("missing lastModEndDate in %q", capturedQuery)
	}
}

func TestFetchPage_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	client.http.RetryMax = 0 // no retries in tests
	_, err := client.FetchPage(0)
	if err == nil {
		t.Fatal("expected error on non-200 response")
	}
}

func TestFetchPage_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	client.http.RetryMax = 0
	_, err := client.FetchPage(0)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestFetchPage_APIKeyHeader(t *testing.T) {
	var capturedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(singlePageResponse(0, nil))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	client.apiKey = "test-api-key"
	_, err := client.FetchPage(0)
	if err != nil {
		t.Fatalf("FetchPage: %v", err)
	}
	if capturedKey != "test-api-key" {
		t.Errorf("apiKey header: got %q, want %q", capturedKey, "test-api-key")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsString(s, sub))
}

func containsString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
