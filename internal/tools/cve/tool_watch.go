package cve

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/auth"
	"github.com/JetManiack/mcp-cve/internal/storage"
)

// --- watch_product ---

type watchProductInput struct {
	VendorProduct string `json:"vendor_product" jsonschema:"Vendor or product name to watch for new CVEs e.g. openssl or apache struts; matched as a case-insensitive substring of the CPE vendor and product fields so openssl also matches lua-openssl and curl also matches libcurl"`
}

type watchProductOutput struct {
	WatchID string `json:"watch_id,omitempty"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

func watchProductHandler(db *gorm.DB) mcp.ToolHandlerFor[watchProductInput, watchProductOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in watchProductInput) (*mcp.CallToolResult, watchProductOutput, error) {
		actor, ok := auth.ActorFromContext(ctx)
		if !ok {
			return nil, watchProductOutput{}, fmt.Errorf("no authenticated actor in context")
		}

		watch, err := storage.CreateWatch(db, actor.ID, in.VendorProduct)
		if errors.Is(err, storage.ErrEmptyVendorProduct) {
			return nil, watchProductOutput{Error: err.Error()}, nil
		}
		if err != nil {
			return nil, watchProductOutput{}, err
		}

		out := watchProductOutput{
			WatchID: watch.ID,
			Message: fmt.Sprintf("Now watching for CVEs matching %q. Watch ID: %s", in.VendorProduct, watch.ID),
		}
		return nil, out, nil
	}
}

// --- unwatch_product ---

type unwatchProductInput struct {
	WatchID string `json:"watch_id" jsonschema:"Watch ID returned by watch_product"`
}

type unwatchProductOutput struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

func unwatchProductHandler(db *gorm.DB) mcp.ToolHandlerFor[unwatchProductInput, unwatchProductOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in unwatchProductInput) (*mcp.CallToolResult, unwatchProductOutput, error) {
		actor, ok := auth.ActorFromContext(ctx)
		if !ok {
			return nil, unwatchProductOutput{}, fmt.Errorf("no authenticated actor in context")
		}

		if in.WatchID == "" {
			return nil, unwatchProductOutput{Error: "watch_id is required"}, nil
		}

		err := storage.DeleteWatch(db, actor.ID, in.WatchID)
		if errors.Is(err, storage.ErrWatchNotFound) {
			return nil, unwatchProductOutput{Error: "watch not found or does not belong to this agent"}, nil
		}
		if err != nil {
			return nil, unwatchProductOutput{}, err
		}

		return nil, unwatchProductOutput{Message: "Watch removed."}, nil
	}
}

// --- list_watches ---

type listWatchesInput struct{}

type listWatchesOutput struct {
	Watches []storage.CVEWatch `json:"watches"`
}

func listWatchesHandler(db *gorm.DB) mcp.ToolHandlerFor[listWatchesInput, listWatchesOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in listWatchesInput) (*mcp.CallToolResult, listWatchesOutput, error) {
		actor, ok := auth.ActorFromContext(ctx)
		if !ok {
			return nil, listWatchesOutput{}, fmt.Errorf("no authenticated actor in context")
		}

		watches, err := storage.ListWatches(db, actor.ID)
		if err != nil {
			return nil, listWatchesOutput{}, err
		}
		if watches == nil {
			watches = []storage.CVEWatch{}
		}

		out := listWatchesOutput{Watches: watches}
		return nil, out, nil
	}
}

// --- get_watch_hits ---

type getWatchHitsInput struct {
	MarkSeen bool `json:"mark_seen,omitempty" jsonschema:"If true mark all returned hits as seen so they don't appear in future calls"`
}

type watchHitDetail struct {
	Hit storage.CVEWatchHit `json:"hit"`
	CVE *storage.CVE        `json:"cve,omitempty"`
}

type getWatchHitsOutput struct {
	Hits  []watchHitDetail `json:"hits"`
	Total int              `json:"total"`
}

func getWatchHitsHandler(db *gorm.DB) mcp.ToolHandlerFor[getWatchHitsInput, getWatchHitsOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in getWatchHitsInput) (*mcp.CallToolResult, getWatchHitsOutput, error) {
		actor, ok := auth.ActorFromContext(ctx)
		if !ok {
			return nil, getWatchHitsOutput{}, fmt.Errorf("no authenticated actor in context")
		}

		hits, err := storage.GetUnseenHits(db, actor.ID)
		if err != nil {
			return nil, getWatchHitsOutput{}, err
		}

		details := make([]watchHitDetail, 0, len(hits))
		for _, hit := range hits {
			d := watchHitDetail{Hit: hit}
			if cve, err := storage.GetCVE(db, hit.CVEID); err == nil {
				d.CVE = cve
			}
			details = append(details, d)
		}

		if in.MarkSeen && len(hits) > 0 {
			if err := storage.MarkHitsSeen(db, actor.ID); err != nil {
				return nil, getWatchHitsOutput{}, err
			}
		}

		if details == nil {
			details = []watchHitDetail{}
		}
		out := getWatchHitsOutput{Hits: details, Total: len(details)}
		return nil, out, nil
	}
}
