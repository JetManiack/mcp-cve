// Package mcpserver exposes the CVE tools over MCP, with bearer-token auth
// and SSE-safe write-deadline clearing.
package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/auth"
)

const ServerName = "mcp-cve"
const fallbackVersion = "dev"

// DefaultPreviewBytes bounds how much of a tool's output is kept in history.
const DefaultPreviewBytes = 64 << 10 // 64 KiB

// ToolRegistrar registers one or more tools onto an MCP server.
type ToolRegistrar interface {
	Register(srv *mcp.Server, db *gorm.DB)
}

// watchResourceURIPrefix is the base of watch resource URIs.
const watchResourceURIPrefix = "cve://watches/"

func watchResourceURI(actorID string) string {
	return watchResourceURIPrefix + actorID
}

func actorIDFromWatchURI(uri string) (string, bool) {
	id, ok := strings.CutPrefix(uri, watchResourceURIPrefix)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// MCPServer wraps the mcp.Server and its HTTP handler together so the caller
// can send ResourceUpdated notifications without holding the *mcp.Server
// directly.
type MCPServer struct {
	srv     *mcp.Server
	handler http.Handler
}

// New builds the full /mcp handler: Streamable HTTP transport with bearer-token
// auth, registered tools, and resource subscribe/unsubscribe handlers for
// cve://watches/{actorID}.
func New(db *gorm.DB, tools []ToolRegistrar) *MCPServer {
	opts := &mcp.ServerOptions{
		SubscribeHandler:   subscribeHandler,
		UnsubscribeHandler: func(_ context.Context, _ *mcp.UnsubscribeRequest) error { return nil },
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: ServerName, Version: fallbackVersion}, opts)

	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		Name:        "watches",
		Description: "An actor's CVE watches and their recent unseen hits; subscribe to get notified when a new hit arrives",
		MIMEType:    "application/json",
		URITemplate: "cve://watches/{actorID}",
	}, watchResourceHandler(db))

	for _, t := range tools {
		t.Register(srv, db)
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	h := clearWriteDeadline(auth.RequireBearer(db, mcpHandler))
	return &MCPServer{srv: srv, handler: h}
}

// Handler returns the http.Handler that serves the /mcp endpoint.
func (m *MCPServer) Handler() http.Handler { return m.handler }

// NotifyWatchHit sends a ResourceUpdated notification to any subscribed
// clients for actorID's watch feed. Called by the NVD syncer on new hits.
func (m *MCPServer) NotifyWatchHit(ctx context.Context, actorID string) {
	if err := m.srv.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{
		URI: watchResourceURI(actorID),
	}); err != nil {
		slog.Warn("failed to send ResourceUpdated", "actor_id", actorID, "error", fmt.Sprintf("%v", err))
	}
}

// subscribeHandler rejects subscriptions to another actor's watch feed.
func subscribeHandler(ctx context.Context, req *mcp.SubscribeRequest) error {
	actor, ok := auth.ActorFromContext(ctx)
	if !ok {
		return fmt.Errorf("no authenticated actor in context")
	}
	targetID, ok := actorIDFromWatchURI(req.Params.URI)
	if !ok {
		return fmt.Errorf("unknown resource %q", req.Params.URI)
	}
	if targetID != actor.ID {
		return fmt.Errorf("cannot subscribe to another actor's watch feed")
	}
	return nil
}

// watchResourceHandler returns a resource read handler for cve://watches/{actorID}.
// Non-destructive: it never marks hits as seen.
func watchResourceHandler(db *gorm.DB) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		actor, ok := auth.ActorFromContext(ctx)
		if !ok {
			return nil, fmt.Errorf("no authenticated actor in context")
		}
		targetID, ok := actorIDFromWatchURI(req.Params.URI)
		if !ok || targetID != actor.ID {
			return nil, fmt.Errorf("cannot read another actor's watch feed")
		}
		return nil, fmt.Errorf("use the get_watch_hits tool to read watch data")
	}
}

// clearWriteDeadline removes the HTTP server's write deadline on the SSE
// stream endpoint. Without this, the server's WriteTimeout closes the
// long-lived SSE connection mid-stream.
func clearWriteDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).SetWriteDeadline(time.Time{})
		next.ServeHTTP(w, r)
	})
}
