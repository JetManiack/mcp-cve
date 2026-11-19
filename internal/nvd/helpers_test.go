package nvd

import (
	"testing"
	"time"
)

// ParseTime

func TestParseTime_NVDFormat(t *testing.T) {
	got, err := ParseTime("2024-01-15T12:30:45.000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2024, 1, 15, 12, 30, 45, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTime_NoMillis(t *testing.T) {
	got, err := ParseTime("2024-01-15T12:30:45")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2024, 1, 15, 12, 30, 45, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTime_RFC3339(t *testing.T) {
	got, err := ParseTime("2024-01-15T12:30:45Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2024, 1, 15, 12, 30, 45, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTime_Empty(t *testing.T) {
	got, err := ParseTime("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("expected zero time, got %v", got)
	}
}

func TestParseTime_Invalid(t *testing.T) {
	_, err := ParseTime("not-a-date")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

// ExtractEnglishDescription

func TestExtractEnglishDescription_English(t *testing.T) {
	item := &CVEItem{}
	item.CVE.Descriptions = []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{
		{Lang: "es", Value: "Descripción en español"},
		{Lang: "en", Value: "English description"},
	}
	got := ExtractEnglishDescription(item)
	if got != "English description" {
		t.Errorf("got %q, want %q", got, "English description")
	}
}

func TestExtractEnglishDescription_NoEnglish(t *testing.T) {
	item := &CVEItem{}
	item.CVE.Descriptions = []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{
		{Lang: "fr", Value: "Description en français"},
	}
	got := ExtractEnglishDescription(item)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestExtractEnglishDescription_Empty(t *testing.T) {
	item := &CVEItem{}
	got := ExtractEnglishDescription(item)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ExtractSeverityAndScore

func cvssV31Item(severity string, score float64) *CVEItem {
	item := &CVEItem{}
	item.CVE.Metrics.CVSSMetricV31 = []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	}{{CVSSData: struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	}{BaseScore: score, BaseSeverity: severity}}}
	return item
}

func cvssV2Item(severity string, score float64) *CVEItem {
	item := &CVEItem{}
	item.CVE.Metrics.CVSSMetricV2 = []struct {
		CVSSData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	}{{CVSSData: struct {
		BaseScore float64 `json:"baseScore"`
	}{BaseScore: score}, BaseSeverity: severity}}
	return item
}

func TestExtractSeverityAndScore_V31(t *testing.T) {
	item := cvssV31Item("high", 7.5)
	sev, score := ExtractSeverityAndScore(item)
	if sev != "HIGH" {
		t.Errorf("severity: got %q, want %q", sev, "HIGH")
	}
	if score != 7.5 {
		t.Errorf("score: got %v, want 7.5", score)
	}
}

func TestExtractSeverityAndScore_V30Fallback(t *testing.T) {
	item := &CVEItem{}
	item.CVE.Metrics.CVSSMetricV30 = []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	}{{CVSSData: struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	}{BaseScore: 6.0, BaseSeverity: "medium"}}}
	sev, score := ExtractSeverityAndScore(item)
	if sev != "MEDIUM" {
		t.Errorf("severity: got %q, want %q", sev, "MEDIUM")
	}
	if score != 6.0 {
		t.Errorf("score: got %v, want 6.0", score)
	}
}

func TestExtractSeverityAndScore_V2Fallback(t *testing.T) {
	item := cvssV2Item("LOW", 3.5)
	sev, score := ExtractSeverityAndScore(item)
	if sev != "LOW" {
		t.Errorf("severity: got %q, want %q", sev, "LOW")
	}
	if score != 3.5 {
		t.Errorf("score: got %v, want 3.5", score)
	}
}

func TestExtractSeverityAndScore_NoMetrics(t *testing.T) {
	item := &CVEItem{}
	sev, score := ExtractSeverityAndScore(item)
	if sev != "NONE" {
		t.Errorf("severity: got %q, want %q", sev, "NONE")
	}
	if score != 0 {
		t.Errorf("score: got %v, want 0", score)
	}
}

func TestExtractSeverityAndScore_V31PreferredOverV2(t *testing.T) {
	item := cvssV2Item("LOW", 2.0)
	item.CVE.Metrics.CVSSMetricV31 = []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	}{{CVSSData: struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	}{BaseScore: 9.8, BaseSeverity: "critical"}}}
	sev, score := ExtractSeverityAndScore(item)
	if sev != "CRITICAL" {
		t.Errorf("severity: got %q, want %q", sev, "CRITICAL")
	}
	if score != 9.8 {
		t.Errorf("score: got %v, want 9.8", score)
	}
}

// ExtractCPEs

func TestExtractCPEs_Multiple(t *testing.T) {
	item := &CVEItem{}
	item.CVE.Configurations = []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	}{
		{Nodes: []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		}{
			{CPEMatch: []struct {
				Criteria string `json:"criteria"`
			}{
				{Criteria: "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"},
				{Criteria: "cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*"},
			}},
		}},
	}
	got := ExtractCPEs(item)
	want := "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:* cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractCPEs_Empty(t *testing.T) {
	item := &CVEItem{}
	got := ExtractCPEs(item)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ExtractRefsJSON

func TestExtractRefsJSON_WithTags(t *testing.T) {
	item := &CVEItem{}
	item.CVE.References = []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	}{
		{URL: "https://example.com/advisory", Tags: []string{"Patch", "Vendor Advisory"}},
	}
	got := ExtractRefsJSON(item)
	want := `[{"url":"https://example.com/advisory","tags":["Patch","Vendor Advisory"]}]`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractRefsJSON_Empty(t *testing.T) {
	item := &CVEItem{}
	got := ExtractRefsJSON(item)
	if got != "[]" {
		t.Errorf("expected %q, got %q", "[]", got)
	}
}
