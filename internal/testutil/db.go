// Package testutil provides shared helpers for unit tests.
package testutil

import (
	"testing"

	"gorm.io/gorm"

	"github.com/JetManiack/mcp-cve/internal/storage"
)

// NewTestDB opens an in-memory SQLite database and runs all migrations.
// The database is discarded when the test ends.
func NewTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	return db
}
