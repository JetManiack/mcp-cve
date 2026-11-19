package restapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

type historyListResponse struct {
	Calls      []storage.ToolCall `json:"calls"`
	NextCursor string             `json:"next_cursor,omitempty"`
	Actors     map[string]string  `json:"actors"`
}

func listHistoryHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		limit := 0
		if raw := q.Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New("limit must be an integer"))
				return
			}
			limit = parsed
		}

		var isError *bool
		if isErrStr := q.Get("is_error"); isErrStr != "" {
			if isErrStr != "true" && isErrStr != "false" {
				writeError(w, http.StatusBadRequest, errors.New(`is_error must be "true" or "false"`))
				return
			}
			b := isErrStr == "true"
			isError = &b
		}

		calls, next, err := storage.ListToolCalls(db, storage.HistoryFilter{
			ActorID: q.Get("actor"),
			Tool:    q.Get("tool"),
			IsError: isError,
			Limit:   limit,
			Cursor:  q.Get("cursor"),
		})
		if errors.Is(err, storage.ErrUnknownCursor) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		actorIDs := make([]string, 0, len(calls))
		seen := make(map[string]bool, len(calls))
		for _, call := range calls {
			if !seen[call.ActorID] {
				seen[call.ActorID] = true
				actorIDs = append(actorIDs, call.ActorID)
			}
		}
		names, err := storage.ActorNamesByID(db, actorIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if calls == nil {
			calls = []storage.ToolCall{}
		}
		writeJSON(w, http.StatusOK, historyListResponse{Calls: calls, NextCursor: next, Actors: names})
	}
}

type historyEntryResponse struct {
	Call  storage.ToolCall `json:"call"`
	Actor string           `json:"actor"`
}

func getHistoryEntryHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		call, err := storage.GetToolCall(db, chi.URLParam(r, "id"))
		if errors.Is(err, storage.ErrToolCallNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		names, err := storage.ActorNamesByID(db, []string{call.ActorID})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		writeJSON(w, http.StatusOK, historyEntryResponse{Call: *call, Actor: names[call.ActorID]})
	}
}

func listHistoryToolsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tools, err := storage.DistinctTools(db)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if tools == nil {
			tools = []string{}
		}
		writeJSON(w, http.StatusOK, tools)
	}
}
