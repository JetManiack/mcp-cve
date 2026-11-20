package restapi

import (
	"net/http"
	"strconv"

	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

type cveListResponse struct {
	CVEs       []storage.CVE `json:"cves"`
	NextCursor string        `json:"next_cursor"`
	Total      int64         `json:"total"`
}

func listCVEsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		f := storage.CVEFilter{
			Query:    q.Get("q"),
			Severity: q.Get("severity"),
			Vendor:   q.Get("vendor"),
			Cursor:   q.Get("cursor"),
			Limit:    limit,
		}
		cves, next, err := storage.SearchCVEs(db, f)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		var total int64
		db.Model(&storage.CVE{}).Count(&total)
		if cves == nil {
			cves = []storage.CVE{}
		}
		writeJSON(w, http.StatusOK, cveListResponse{CVEs: cves, NextCursor: next, Total: total})
	}
}
