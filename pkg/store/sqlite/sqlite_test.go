package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"testing/fstest"
	"time"

	"github.com/clawvisor/clawvisor/pkg/store"
)

func TestRunMigrationsFSIsTransactional(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", t.TempDir()+"/migrations.db")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrations := fstest.MapFS{
		"migrations/001_broken.sql": &fstest.MapFile{
			Data: []byte(`
				CREATE TABLE atomic_test (id INTEGER PRIMARY KEY);
				INSERT INTO missing_table(id) VALUES (1);
			`),
		},
	}
	if err := runMigrationsFS(ctx, db, migrations); err == nil {
		t.Fatal("expected migration failure")
	}

	var tableCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'atomic_test'`).Scan(&tableCount); err != nil {
		t.Fatalf("QueryRowContext(sqlite_master): %v", err)
	}
	if tableCount != 0 {
		t.Fatalf("expected failed migration table creation to roll back, count=%d", tableCount)
	}

	var migrationCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("QueryRowContext(schema_migrations): %v", err)
	}
	if migrationCount != 0 {
		t.Fatalf("expected failed migration to remain unrecorded, count=%d", migrationCount)
	}
}

func TestUpdateAuditFiltersApplied(t *testing.T) {
	ctx := context.Background()
	db, err := New(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	st := NewStore(db)
	t.Cleanup(func() { _ = st.Close() })

	user, err := st.CreateUser(ctx, "user-1@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	entry := &store.AuditEntry{
		ID:         "audit-filter-1",
		UserID:     user.ID,
		RequestID:  "req-1",
		Timestamp:  time.Now(),
		Service:    "google.gmail",
		Action:     "get_message",
		ParamsSafe: json.RawMessage(`{}`),
		Decision:   "execute",
		Outcome:    "pending",
	}
	if err := st.LogAudit(ctx, entry); err != nil {
		t.Fatalf("LogAudit: %v", err)
	}
	filters := json.RawMessage(`{"gateway_hooks":{"GatewayPostToolCall":[{"name":"privacy-filter"}]}}`)
	if err := st.UpdateAuditFiltersApplied(ctx, entry.ID, filters); err != nil {
		t.Fatalf("UpdateAuditFiltersApplied: %v", err)
	}
	got, err := st.GetAuditEntry(ctx, entry.ID, entry.UserID)
	if err != nil {
		t.Fatalf("GetAuditEntry: %v", err)
	}
	if string(got.FiltersApplied) != string(filters) {
		t.Fatalf("FiltersApplied = %s, want %s", got.FiltersApplied, filters)
	}
}
