package cve

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

type recentCVEsInput struct {
	Hours    int    `json:"hours,omitempty"    jsonschema:"How many hours back to look (default 24 max 168)"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity: CRITICAL HIGH MEDIUM LOW NONE"`
	Limit    int    `json:"limit,omitempty"    jsonschema:"Max results returned (default 20 max 100)"`
}

type recentCVEsOutput struct {
	CVEs  []storage.CVE `json:"cves"`
	Total int           `json:"total"`
}

func recentCVEsHandler(db *gorm.DB) mcp.ToolHandlerFor[recentCVEsInput, recentCVEsOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in recentCVEsInput) (*mcp.CallToolResult, recentCVEsOutput, error) {
		cves, err := storage.GetRecentCVEs(db, in.Hours, in.Severity, in.Limit)
		if err != nil {
			return nil, recentCVEsOutput{}, err
		}

		if cves == nil {
			cves = []storage.CVE{}
		}
		out := recentCVEsOutput{CVEs: cves, Total: len(cves)}
		return nil, out, nil
	}
}
