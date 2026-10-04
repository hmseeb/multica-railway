// Modified for Railway owner-password authentication.

// Package ownerauth bootstraps the single owner email/password credential of
// a fresh self-hosted database and hashes/verifies that password.
//
// MULTICA_OWNER_EMAIL / MULTICA_OWNER_PASSWORD are consumed only by Bootstrap,
// once, before the HTTP server starts. Login never reads the environment: it
// verifies against the durable owner_bootstrap row.
package ownerauth

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const (
	// Iterations follows the OWASP PBKDF2-HMAC-SHA256 recommendation.
	Iterations       = 600_000
	MinPasswordChars = 15
	MaxPasswordBytes = 1024
	MaxEmailBytes    = 254

	OutcomeOwnerCreated = "owner_created"
	OutcomeExistingData = "existing_data"

	hashScheme = "pbkdf2-sha256"
	saltBytes  = 16
	keyBytes   = 32
)

// Result reports what Bootstrap did.
type Result struct {
	// Outcome is the durable marker's outcome, or "" when Bootstrap was not
	// configured and no marker exists.
	Outcome string
	// Created is true only when this call wrote the marker.
	Created bool
	Email   string
}

// NormalizeEmail lowercases/trims and requires a bare, valid address.
func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > MaxEmailBytes {
		return "", errors.New("owner email must be a valid address of at most 254 bytes")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", errors.New("owner email must be a bare valid address such as owner@example.com")
	}
	return email, nil
}

// ValidatePassword enforces the bootstrap password policy.
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return errors.New("owner password must be valid UTF-8")
	}
	if utf8.RuneCountInString(password) < MinPasswordChars {
		return fmt.Errorf("owner password must be at least %d characters", MinPasswordChars)
	}
	if len(password) > MaxPasswordBytes {
		return fmt.Errorf("owner password must be at most %d bytes", MaxPasswordBytes)
	}
	return nil
}

// HashPassword returns "pbkdf2-sha256$<iterations>$<salt>$<key>" (raw base64url).
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, Iterations, keyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return hashScheme + "$" + strconv.Itoa(Iterations) + "$" + enc.EncodeToString(salt) + "$" + enc.EncodeToString(key), nil
}

// VerifyPassword runs the full derivation for any well-formed stored hash and
// compares in constant time. Malformed or weakened hashes never verify.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < Iterations || iter > 10*Iterations {
		return false
	}
	enc := base64.RawURLEncoding
	salt, err := enc.DecodeString(parts[2])
	if err != nil || len(salt) < saltBytes {
		return false
	}
	want, err := enc.DecodeString(parts[3])
	if err != nil || len(want) != keyBytes {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, keyBytes)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Bootstrap creates the owner user and credential exactly once, and only on an
// empty database (no users and no workspaces). Once any marker row exists the
// environment is ignored: redeploys with changed values are no-ops, and a
// pre-existing database is permanently marked existing_data so a password is
// never attached to an existing account and initialization never reopens.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, rawEmail, password string) (Result, error) {
	if rawEmail == "" && password == "" {
		row, err := db.New(pool).GetOwnerBootstrap(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, nil
		}
		if err != nil {
			return Result{}, fmt.Errorf("read owner bootstrap marker: %w", err)
		}
		return Result{Outcome: row.Outcome, Email: row.Email.String}, nil
	}

	// Fast path without locks for every restart after the first.
	if row, err := db.New(pool).GetOwnerBootstrap(ctx); err == nil {
		return Result{Outcome: row.Outcome, Email: row.Email.String}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Result{}, fmt.Errorf("read owner bootstrap marker: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '30s'`); err != nil {
		return Result{}, err
	}
	// SHARE ROW EXCLUSIVE conflicts with itself and with row writes, so
	// concurrent starts serialize here and no user/workspace can be inserted
	// between the emptiness check and owner creation.
	if _, err := tx.Exec(ctx, `LOCK TABLE owner_bootstrap, "user", workspace IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Result{}, fmt.Errorf("lock for owner bootstrap: %w", err)
	}
	q := db.New(tx)
	if row, err := q.GetOwnerBootstrap(ctx); err == nil {
		return Result{Outcome: row.Outcome, Email: row.Email.String}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Result{}, fmt.Errorf("read owner bootstrap marker: %w", err)
	}

	hasData, err := q.HasUsersOrWorkspaces(ctx)
	if err != nil {
		return Result{}, err
	}
	// A pre-existing database is closed for good before the values are even
	// validated: partial or malformed credentials are ignored, not fatal.
	if hasData {
		if err := q.CreateOwnerBootstrap(ctx, db.CreateOwnerBootstrapParams{Outcome: OutcomeExistingData}); err != nil {
			return Result{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Result{}, err
		}
		return Result{Outcome: OutcomeExistingData, Created: true}, nil
	}

	email, err := NormalizeEmail(rawEmail)
	if err != nil {
		return Result{}, fmt.Errorf("MULTICA_OWNER_EMAIL: %w", err)
	}
	if err := ValidatePassword(password); err != nil {
		return Result{}, fmt.Errorf("MULTICA_OWNER_PASSWORD: %w", err)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return Result{}, err
	}
	name := email
	if at := strings.Index(email, "@"); at > 0 {
		name = email[:at]
	}
	user, err := q.CreateUser(ctx, db.CreateUserParams{Name: name, Email: email})
	if err != nil {
		return Result{}, fmt.Errorf("create owner user: %w", err)
	}
	if err := q.CreateOwnerBootstrap(ctx, db.CreateOwnerBootstrapParams{
		Outcome:      OutcomeOwnerCreated,
		UserID:       user.ID,
		Email:        pgtype.Text{String: email, Valid: true},
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	}); err != nil {
		return Result{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	return Result{Outcome: OutcomeOwnerCreated, Created: true, Email: email}, nil
}
