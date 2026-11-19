package restapi

import (
	"net/http"

	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

func syncStateHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := storage.GetSyncState(db)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	}
}
