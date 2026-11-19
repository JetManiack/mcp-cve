// Package storage holds the persistence layer: GORM models and repository
// functions over them, behind a single Open(dsn) that selects SQLite or
// Postgres from the DSN.
package storage

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// Open opens a database at dsn, applies backend-specific setup, and migrates
// the schema. A postgres:// or postgresql:// prefix selects Postgres;
// anything else (a file path or ":memory:") selects SQLite.
func Open(dsn string) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	if IsPostgresDSN(dsn) {
		db, err = openPostgres(dsn)
	} else {
		db, err = openSQLite(dsn)
	}
	if err != nil {
		return nil, err
	}

	migrate := func() error {
		if err := db.AutoMigrate(
			&Actor{},
			&AgentCredential{},
			&UserIdentity{},
			&Session{},
			&ToolCall{},
			&CVE{},
			&CVEWatch{},
			&CVEWatchHit{},
			&SyncState{},
		); err != nil {
			return fmt.Errorf("automigrate: %w", err)
		}
		return nil
	}

	if db.Dialector.Name() == "postgres" {
		if err := withMigrationLock(db, migrate); err != nil {
			return nil, err
		}
	} else if err := migrate(); err != nil {
		return nil, err
	}

	return db, nil
}

// IsPostgresDSN reports whether dsn selects the Postgres backend.
func IsPostgresDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}
