// Package nvd provides a client for the NVD CVE API v2.
package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

const nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDTimeFormat is the format used in NVD API date range parameters.
const NVDTimeFormat = "2006-01-02T15:04:05.000"

// MaxResultsPerPage is the maximum number of results NVD returns per page.
const MaxResultsPerPage = 2000

// CVEItem is one item from the NVD API /cves/2.0 response.
type CVEItem struct {
	CVE struct {
		ID               string `json:"id"`
		SourceIdentifier string `json:"sourceIdentifier"`
		Published        string `json:"published"`
		LastModified     string `json:"lastModified"`
		Descriptions     []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CVSSMetricV31 []struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CVSSMetricV30 []struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV30"`
			CVSSMetricV2 []struct {
				CVSSData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
				BaseSeverity string `json:"baseSeverity"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Criteria string `json:"criteria"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
		References []struct {
			URL    string   `json:"url"`
			Tags   []string `json:"tags"`
		} `json:"references"`
	} `json:"cve"`
}

// PageResult is one page of results from the NVD API.
type PageResult struct {
	TotalResults int       `json:"totalResults"`
	StartIndex   int       `json:"startIndex"`
	ResultsPerPage int     `json:"resultsPerPage"`
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

// Client wraps the NVD API v2 with rate limiting and retries.
type Client struct {
	http     *retryablehttp.Client
	apiKey   string
	baseURL  string // overridable for tests; defaults to nvdAPIBase
	// rateLimiter gates requests to stay within NVD's public rate limit
	// (5 req/30s without key, 50 req/30s with key).
	lastRequest time.Time
	minInterval time.Duration
}

// NewClient constructs a Client. apiKey may be empty; without one the client
// uses a conservative 7-second inter-request delay to stay within the 5/30s
// limit.
func NewClient(apiKey string) *Client {
	rc := retryablehttp.NewClient()
	rc.RetryMax = 3
	rc.RetryWaitMin = 2 * time.Second
	rc.RetryWaitMax = 30 * time.Second
	rc.Logger = nil // suppress retryablehttp's default logger

	minInterval := 7 * time.Second
	if apiKey != "" {
		minInterval = 700 * time.Millisecond
	}

	return &Client{
		http:        rc,
		apiKey:      apiKey,
		baseURL:     nvdAPIBase,
		minInterval: minInterval,
	}
}

// FetchPage fetches one page of CVEs from the NVD API starting at startIndex.
func (c *Client) FetchPage(startIndex int) (*PageResult, error) {
	params := url.Values{}
	params.Set("startIndex", strconv.Itoa(startIndex))
	params.Set("resultsPerPage", strconv.Itoa(MaxResultsPerPage))
	return c.fetch(params)
}

// FetchModifiedSince fetches CVEs last-modified between start and end. The
// NVD API enforces a maximum 120-day range on date parameters; callers must
// split larger ranges into sub-windows.
func (c *Client) FetchModifiedSince(start, end time.Time, startIndex int) (*PageResult, error) {
	params := url.Values{}
	params.Set("lastModStartDate", start.UTC().Format(NVDTimeFormat))
	params.Set("lastModEndDate", end.UTC().Format(NVDTimeFormat))
	params.Set("startIndex", strconv.Itoa(startIndex))
	params.Set("resultsPerPage", strconv.Itoa(MaxResultsPerPage))
	return c.fetch(params)
}

func (c *Client) fetch(params url.Values) (*PageResult, error) {
	c.rateWait()

	reqURL := c.baseURL + "?" + params.Encode()
	req, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build NVD request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("NVD API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result PageResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	return &result, nil
}

// rateWait sleeps until the minimum inter-request interval has elapsed.
func (c *Client) rateWait() {
	if wait := c.minInterval - time.Since(c.lastRequest); wait > 0 {
		time.Sleep(wait)
	}
	c.lastRequest = time.Now()
}

// ParseTime parses an NVD API timestamp string.
func ParseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{NVDTimeFormat, "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse NVD time %q", s)
}

// ExtractEnglishDescription returns the English description from a CVEItem.
func ExtractEnglishDescription(item *CVEItem) string {
	for _, d := range item.CVE.Descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

// ExtractSeverityAndScore returns the highest-available CVSS severity and score.
func ExtractSeverityAndScore(item *CVEItem) (severity string, score float64) {
	// Prefer v3.1 > v3.0 > v2
	if len(item.CVE.Metrics.CVSSMetricV31) > 0 {
		return strings.ToUpper(item.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity),
			item.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(item.CVE.Metrics.CVSSMetricV30) > 0 {
		return strings.ToUpper(item.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity),
			item.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
	}
	if len(item.CVE.Metrics.CVSSMetricV2) > 0 {
		return strings.ToUpper(item.CVE.Metrics.CVSSMetricV2[0].BaseSeverity),
			item.CVE.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
	}
	return "NONE", 0
}

// ExtractCPEs returns a space-separated string of all CPE criteria in a CVEItem.
func ExtractCPEs(item *CVEItem) string {
	var cpes []string
	for _, cfg := range item.CVE.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				cpes = append(cpes, m.Criteria)
			}
		}
	}
	return strings.Join(cpes, " ")
}

// ExtractRefsJSON marshals the reference URLs to a JSON array string.
func ExtractRefsJSON(item *CVEItem) string {
	type ref struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags,omitempty"`
	}
	refs := make([]ref, 0, len(item.CVE.References))
	for _, r := range item.CVE.References {
		refs = append(refs, ref{URL: r.URL, Tags: r.Tags})
	}
	b, _ := json.Marshal(refs)
	return string(b)
}
