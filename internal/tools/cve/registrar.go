// Package cve registers all CVE-related MCP tools.
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/auth"
	"github.com/JetManiack/mcp-cve/internal/mcpserver"
	"github.com/JetManiack/mcp-cve/internal/storage"
)

// Registrar implements mcpserver.ToolRegistrar and registers all CVE tools.
type Registrar struct{}

// NewRegistrar constructs a Registrar.
func NewRegistrar() *Registrar { return &Registrar{} }

// Register adds every CVE tool to srv.
func (r *Registrar) Register(srv *mcp.Server, db *gorm.DB) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_cve",
		Description: "Fetch a single CVE record by its identifier (e.g. CVE-2024-12345)",
	}, recorded(db, "get_cve", getCVEHandler(db)))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_cves",
		Description: "Search CVEs by keyword in the description, severity, vendor/product CPE substring, or publication date; paginated",
	}, recorded(db, "search_cves", searchCVEsHandler(db)))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "recent_cves",
		Description: "Get recently published or updated CVEs, optionally filtered by severity",
	}, recorded(db, "recent_cves", recentCVEsHandler(db)))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "watch_product",
		Description: "Subscribe to new CVEs affecting a vendor or product (matched against CPE strings); returns a watch_id",
	}, recorded(db, "watch_product", watchProductHandler(db)))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "unwatch_product",
		Description: "Remove a product watch by its watch_id",
	}, recorded(db, "unwatch_product", unwatchProductHandler(db)))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_watches",
		Description: "List all product watches created by the calling agent",
	}, recorded(db, "list_watches", listWatchesHandler(db)))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_watch_hits",
		Description: "Get CVEs that matched the calling agent's watches; optionally mark them as seen",
	}, recorded(db, "get_watch_hits", getWatchHitsHandler(db)))
}

// recorded wraps a typed tool handler with audit-record persistence.
func recorded[In, Out any](db *gorm.DB, tool string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	rec := mcpserver.DefaultPreviewBytes
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		start := time.Now()
		result, out, err := h(ctx, req, in)
		go func() {
			actor, ok := auth.ActorFromContext(ctx)
			if !ok {
				slog.Warn("tool call not recorded: no authenticated actor in context", "tool", tool)
				return
			}

			call := &storage.ToolCall{
				ID:         uuid.NewString(),
				ActorID:    actor.ID,
				Tool:       tool,
				InputJSON:  marshalForHistory(in),
				DurationMS: time.Since(start).Milliseconds(),
				CalledAt:   start,
			}
			if err != nil {
				call.IsError = true
				call.OutputJSON = marshalForHistory(struct {
					Error string `json:"error"`
				}{Error: err.Error()})
			} else {
				encoded := marshalForHistory(out)
				call.OutputSize = len(encoded)
				call.OutputJSON, call.Truncated = truncateUTF8(encoded, rec)
			}

			if dbErr := storage.RecordToolCall(db, call); dbErr != nil {
				slog.Error("failed to record tool call", "tool", tool, "actor_id", actor.ID, "error", fmt.Sprintf("%v", dbErr))
			}
		}()
		return result, out, err
	}
}

func marshalForHistory(v any) string {
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("{%q:%q}", "history_encoding_error", err.Error())
	}
	return string(encoded)
}

func truncateUTF8(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	cut := s[:limit]
	for len(cut) > 0 {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r == utf8.RuneError && size <= 1 {
			cut = cut[:len(cut)-1]
			continue
		}
		break
	}
	return cut, true
}
