// Modified for Railway owner-password authentication.

package ownerauth_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multica-ai/multica/server/internal/ownerauth"
	"github.com/multica-ai/multica/server/internal/ownerauth/ownerauthtest"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const (
	ownerEmail    = "Owner@Example.com"
	ownerPassword = "correct horse battery staple"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	h1, err := ownerauth.HashPassword(ownerPassword)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := ownerauth.HashPassword(ownerPassword)
	if h1 == h2 {
		t.Fatal("two hashes of one password share a salt")
	}
	if !strings.HasPrefix(h1, "pbkdf2-sha256$600000$") {
		t.Fatalf("unexpected hash format %q", h1)
	}
	if !ownerauth.VerifyPassword(h1, ownerPassword) {
		t.Fatal("correct password rejected")
	}
	if ownerauth.VerifyPassword(h1, ownerPassword+"x") {
		t.Fatal("wrong password accepted")
	}
	weakened := strings.Replace(h1, "$600000$", "$1000$", 1)
	for _, bad := range []string{"", "plain", weakened, strings.Replace(h1, "pbkdf2-sha256", "md5", 1)} {
		if ownerauth.VerifyPassword(bad, ownerPassword) {
			t.Fatalf("malformed or weakened hash %q verified", bad)
		}
	}
}

func TestValidation(t *testing.T) {
	if got, err := ownerauth.NormalizeEmail("  Owner@Example.COM "); err != nil || got != "owner@example.com" {
		t.Fatalf("NormalizeEmail = %q, %v", got, err)
	}
	for _, bad := range []string{"", "owner", "Owner <owner@example.com>", "a@b@c", strings.Repeat("a", 250) + "@x.io"} {
		if _, err := ownerauth.NormalizeEmail(bad); err == nil {
			t.Fatalf("NormalizeEmail(%q) accepted", bad)
		}
	}
	if err := ownerauth.ValidatePassword(strings.Repeat("a", 14)); err == nil {
		t.Fatal("14-character password accepted")
	}
	if err := ownerauth.ValidatePassword(strings.Repeat("é", 15)); err != nil {
		t.Fatalf("15 multibyte characters rejected: %v", err)
	}
	if err := ownerauth.ValidatePassword(strings.Repeat("a", ownerauth.MaxPasswordBytes+1)); err == nil {
		t.Fatal("over-long password accepted")
	}
}

func countUsers(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM "user"`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBootstrapCreatesOwnerOnceAndRedeployIsNoop(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	ctx := context.Background()

	res, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Outcome != ownerauth.OutcomeOwnerCreated || res.Email != "owner@example.com" {
		t.Fatalf("first bootstrap = %+v", res)
	}
	row, err := db.New(pool).GetOwnerBootstrap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.New(pool).GetUser(ctx, row.UserID)
	if err != nil || user.Email != "owner@example.com" {
		t.Fatalf("owner user = %+v, %v", user, err)
	}
	if strings.Contains(row.PasswordHash.String, ownerPassword) || !ownerauth.VerifyPassword(row.PasswordHash.String, ownerPassword) {
		t.Fatal("stored credential is not a verifying hash")
	}

	// Redeploy with changed values: nothing is rewritten.
	res, err = ownerauth.Bootstrap(ctx, pool, "attacker@example.com", "another long password!!")
	if err != nil || res.Created || res.Outcome != ownerauth.OutcomeOwnerCreated {
		t.Fatalf("redeploy bootstrap = %+v, %v", res, err)
	}
	// Redeploy with invalid values is still a no-op, not a crash.
	if _, err := ownerauth.Bootstrap(ctx, pool, "bad", "short"); err != nil {
		t.Fatalf("redeploy with invalid env failed: %v", err)
	}
	after, _ := db.New(pool).GetOwnerBootstrap(ctx)
	if after.PasswordHash != row.PasswordHash || after.Email != row.Email || after.UserID != row.UserID {
		t.Fatal("redeploy changed the stored credential")
	}
	if countUsers(t, pool) != 1 {
		t.Fatal("redeploy created another user")
	}
}

func TestBootstrapWithoutEnvDoesNothing(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	res, err := ownerauth.Bootstrap(context.Background(), pool, "", "")
	if err != nil || res.Outcome != "" || res.Created {
		t.Fatalf("bootstrap without env = %+v, %v", res, err)
	}
	if countUsers(t, pool) != 0 {
		t.Fatal("bootstrap without env created a user")
	}
}

func TestBootstrapRejectsInvalidEnvWithoutWriting(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	ctx := context.Background()
	_, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, "too-short-pass")
	if err == nil || strings.Contains(err.Error(), "too-short-pass") {
		t.Fatalf("short password error = %v", err)
	}
	if _, err := ownerauth.Bootstrap(ctx, pool, "not-an-email", ownerPassword); err == nil {
		t.Fatal("invalid email accepted")
	}
	if _, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, ""); err == nil {
		t.Fatal("missing password accepted")
	}
	if _, err := db.New(pool).GetOwnerBootstrap(ctx); err == nil {
		t.Fatal("invalid env wrote a marker")
	}
	if countUsers(t, pool) != 0 {
		t.Fatal("invalid env created a user")
	}
}

func TestBootstrapConcurrentStartsCreateOneOwner(t *testing.T) {
	schema := ownerauthtest.New(t)
	ctx := context.Background()
	const starts = 6
	var wg sync.WaitGroup
	results := make([]ownerauth.Result, starts)
	errs := make([]error, starts)
	for i := range starts {
		pool := schema.Pool(t) // one pool per simulated replica
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword+strings.Repeat("!", i))
		}()
	}
	wg.Wait()
	created := 0
	for i := range starts {
		if errs[i] != nil {
			t.Fatalf("start %d: %v", i, errs[i])
		}
		if results[i].Outcome != ownerauth.OutcomeOwnerCreated {
			t.Fatalf("start %d outcome %q", i, results[i].Outcome)
		}
		if results[i].Created {
			created++
		}
	}
	pool := schema.Pool(t)
	if created != 1 || countUsers(t, pool) != 1 {
		t.Fatalf("created=%d users=%d, want 1/1", created, countUsers(t, pool))
	}
}

func TestBootstrapDeniesPreExistingDatabaseForever(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	ctx := context.Background()
	// The pre-existing account even has the owner's email: no password may be
	// attached to it.
	existing, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Name: "owner", Email: "owner@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword)
	if err != nil || res.Outcome != ownerauth.OutcomeExistingData || !res.Created {
		t.Fatalf("bootstrap on populated db = %+v, %v", res, err)
	}
	row, _ := db.New(pool).GetOwnerBootstrap(ctx)
	if row.PasswordHash.Valid || row.UserID.Valid || row.Email.Valid {
		t.Fatalf("existing_data marker carries a credential: %+v", row)
	}

	// Deleting every user must not reopen initialization.
	if _, err := pool.Exec(ctx, `DELETE FROM "user" WHERE id = $1`, existing.ID); err != nil {
		t.Fatal(err)
	}
	res, err = ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword)
	if err != nil || res.Created || res.Outcome != ownerauth.OutcomeExistingData {
		t.Fatalf("bootstrap after deleting users = %+v, %v", res, err)
	}
	if countUsers(t, pool) != 0 {
		t.Fatal("bootstrap reopened after user deletion")
	}
}

func TestBootstrapDeniesWorkspaceOnlyDatabase(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO workspace (name, slug, issue_prefix) VALUES ('w', 'w', 'W')`); err != nil {
		t.Fatal(err)
	}
	res, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword)
	if err != nil || res.Outcome != ownerauth.OutcomeExistingData {
		t.Fatalf("bootstrap on workspace-only db = %+v, %v", res, err)
	}
}

func TestOwnerDeletionDoesNotReopenBootstrap(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	ctx := context.Background()
	if _, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM "user"`); err != nil {
		t.Fatal(err)
	}
	res, err := ownerauth.Bootstrap(ctx, pool, "new@example.com", "a brand new long password")
	if err != nil || res.Created {
		t.Fatalf("bootstrap after owner deletion = %+v, %v", res, err)
	}
	if countUsers(t, pool) != 0 {
		t.Fatal("owner deletion reopened bootstrap")
	}
}

func TestBootstrapIgnoresMalformedEnvOnPreExistingDatabase(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	ctx := context.Background()
	if _, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Name: "a", Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	// Partial / malformed values on a populated database close bootstrap
	// permanently instead of failing startup.
	res, err := ownerauth.Bootstrap(ctx, pool, "not-an-email", "")
	if err != nil || !res.Created || res.Outcome != ownerauth.OutcomeExistingData {
		t.Fatalf("malformed env on populated db = %+v, %v", res, err)
	}
	res, err = ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword)
	if err != nil || res.Created || res.Outcome != ownerauth.OutcomeExistingData {
		t.Fatalf("valid env after closure = %+v, %v", res, err)
	}
	if countUsers(t, pool) != 1 {
		t.Fatal("closed database gained a user")
	}
}

func TestDownMigrationRefusesToDropMarker(t *testing.T) {
	ctx := context.Background()
	down := ownerauthtest.MigrationSQL(t, "down")
	tableExists := func(t *testing.T, pool *pgxpool.Pool, schema string) bool {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, schema+".owner_bootstrap").Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	for _, tc := range []struct {
		name     string
		populate bool
	}{{"owner_created", false}, {"existing_data", true}} {
		t.Run(tc.name, func(t *testing.T) {
			schema := ownerauthtest.New(t)
			pool := schema.Pool(t)
			if tc.populate {
				if _, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Name: "a", Email: "a@example.com"}); err != nil {
					t.Fatal(err)
				}
			}
			if res, err := ownerauth.Bootstrap(ctx, pool, ownerEmail, ownerPassword); err != nil || res.Outcome != tc.name {
				t.Fatalf("bootstrap = %+v, %v", res, err)
			}
			_, err := pool.Exec(ctx, down)
			if err == nil || !strings.Contains(err.Error(), "refusing to roll back 9000_owner_password_auth") {
				t.Fatalf("down migration error = %v", err)
			}
			if !tableExists(t, pool, schema.Name) {
				t.Fatal("refused rollback still dropped owner_bootstrap")
			}
			if _, err := db.New(pool).GetOwnerBootstrap(ctx); err != nil {
				t.Fatalf("marker lost after refused rollback: %v", err)
			}
		})
	}

	t.Run("no marker rolls back", func(t *testing.T) {
		schema := ownerauthtest.New(t)
		pool := schema.Pool(t)
		if _, err := pool.Exec(ctx, down); err != nil {
			t.Fatalf("down migration without marker: %v", err)
		}
		if tableExists(t, pool, schema.Name) {
			t.Fatal("down migration left owner_bootstrap")
		}
	})
}
