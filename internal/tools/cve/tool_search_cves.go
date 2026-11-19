package cve

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)


type searchCVEsInput struct {
	Query    string `json:"query,omitempty"    jsonschema:"Keyword to search in CVE descriptions"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity: CRITICAL HIGH MEDIUM LOW NONE"`
	Vendor   string `json:"vendor,omitempty"   jsonschema:"Filter by vendor or product name in CPE strings"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results returned (default 20 max 100)"`
	Cursor   string `json:"cursor,omitempty"   jsonschema:"Pagination cursor from a previous search response"`
}

type searchCVEsOutput struct {
	CVEs       []storage.CVE `json:"cves"`
	Total      int           `json:"total"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

func searchCVEsHandler(db *gorm.DB) mcp.ToolHandlerFor[searchCVEsInput, searchCVEsOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in searchCVEsInput) (*mcp.CallToolResult, searchCVEsOutput, error) {
		cves, next, err := storage.SearchCVEs(db, storage.CVEFilter{
			Query:    in.Query,
			Severity: in.Severity,
			Vendor:   in.Vendor,
			Limit:    in.Limit,
			Cursor:   in.Cursor,
		})
		if err != nil {
			return nil, searchCVEsOutput{}, err
		}

		if cves == nil {
			cves = []storage.CVE{}
		}
		out := searchCVEsOutput{
			CVEs:       cves,
			Total:      len(cves),
			NextCursor: next,
		}
		return nil, out, nil
	}
}
