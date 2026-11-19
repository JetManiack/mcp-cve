package cve

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

type getCVEInput struct {
	CVEID string `json:"cve_id" jsonschema:"CVE identifier e.g. CVE-2024-12345"`
}

type getCVEOutput struct {
	CVE   *storage.CVE `json:"cve,omitempty"`
	Error string       `json:"error,omitempty"`
}

func getCVEHandler(db *gorm.DB) mcp.ToolHandlerFor[getCVEInput, getCVEOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getCVEInput) (*mcp.CallToolResult, getCVEOutput, error) {
		if in.CVEID == "" {
			return nil, getCVEOutput{Error: "cve_id is required"}, nil
		}

		cve, err := storage.GetCVE(db, in.CVEID)
		if errors.Is(err, storage.ErrCVENotFound) {
			return nil, getCVEOutput{Error: fmt.Sprintf("CVE %q not found in local database; the initial sync may still be running", in.CVEID)}, nil
		}
		if err != nil {
			return nil, getCVEOutput{}, err
		}

		return nil, getCVEOutput{CVE: cve}, nil
	}
}
