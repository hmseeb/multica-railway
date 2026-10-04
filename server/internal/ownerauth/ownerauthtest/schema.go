// Modified for Railway owner-password authentication.

// Package ownerauthtest gives owner-password tests a throwaway PostgreSQL
// schema. Tests run only when MULTICA_OWNER_TEST_DATABASE_URL points at a
// database already migrated with `migrate up`; otherwise they skip.
package ownerauthtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const EnvDatabaseURL = "MULTICA_OWNER_TEST_DATABASE_URL"

// Schema is an isolated schema holding empty copies of "user" and workspace
// (LIKE the migrated public tables) plus the owner tables created by the real
// 535 migration. Unqualified names resolve here first, then to public.
type Schema struct {
	Name string
	url  string
}

func New(t testing.TB) *Schema {
	t.Helper()
	url := os.Getenv(EnvDatabaseURL)
	if url == "" {
		t.Skip(EnvDatabaseURL + " not set; skipping owner-password PostgreSQL test")
	}
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	s := &Schema{Name: "owner_test_" + hex.EncodeToString(buf), url: url}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect %s: %v", EnvDatabaseURL, err)
	}
	defer admin.Close()
	var migrated bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public."user"') IS NOT NULL AND to_regclass('public.workspace') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatalf("%s must point at a migrated database (run `go run ./cmd/migrate up` first)", EnvDatabaseURL)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+s.Name+`;
		CREATE TABLE `+s.Name+`."user" (LIKE public."user" INCLUDING ALL);
		CREATE TABLE `+s.Name+`.workspace (LIKE public.workspace INCLUDING ALL);`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, err := pgxpool.New(context.Background(), url); err == nil {
			_, _ = c.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+s.Name+` CASCADE`)
			c.Close()
		}
	})

	pool := s.Pool(t)
	if _, err := pool.Exec(ctx, MigrationSQL(t, "up")); err != nil {
		t.Fatalf("apply 535 migration in test schema: %v", err)
	}
	return s
}

// MigrationSQL returns the real 535 migration file for direction "up"/"down".
func MigrationSQL(t testing.TB, direction string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	sql, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "migrations", "535_owner_password_auth."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	return string(sql)
}

// Pool opens a new pool bound to the schema. Opening a second pool simulates
// a server restart against the same database.
func (s *Schema) Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(s.url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = s.Name + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
