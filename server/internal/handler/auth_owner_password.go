// Modified for Railway owner-password authentication.

package handler

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/logger"
	"github.com/multica-ai/multica/server/internal/ownerauth"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const (
	ownerPasswordMaxBodyBytes = 4096
	ownerPasswordWindow       = 5 * time.Minute
	// Per-client and instance-wide attempt caps per window. The global cap
	// bounds guessing even when client IPs rotate or forwarded headers are
	// spoofable; the 15+ character policy makes that bound ample.
	ownerPasswordClientLimit = 10
	ownerPasswordGlobalLimit = 100

	ownerPasswordInvalidCredentials = "invalid email or password"
)

type PasswordLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ownerCredential returns the durable owner credential, or ok=false when this
// database was never bootstrapped with an owner password.
func (h *Handler) ownerCredential(ctx context.Context) (db.OwnerBootstrap, bool, error) {
	if h.Queries == nil {
		return db.OwnerBootstrap{}, false, nil
	}
	row, err := h.Queries.GetOwnerBootstrap(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.OwnerBootstrap{}, false, nil
	}
	if err != nil {
		return db.OwnerBootstrap{}, false, err
	}
	return row, row.Outcome == ownerauth.OutcomeOwnerCreated && row.PasswordHash.Valid, nil
}

// emailLoginEnabled reports whether email-code sign-in is offered. Legacy
// deployments without an owner credential keep their previous behavior
// (including the stdout code fallback); owner-password production deployments
// refuse the stdout fallback and require real email delivery.
func (h *Handler) emailLoginEnabled(ownerPasswordMode bool) bool {
	if !ownerPasswordMode || !isProductionEnv() {
		return true
	}
	return h.EmailService.DeliveryConfigured()
}

// rejectUndeliverableEmailLogin writes an actionable error and returns true
// when email-code sign-in must not run. A failed credential lookup fails
// closed only when the stdout fallback would otherwise be used.
func (h *Handler) rejectUndeliverableEmailLogin(w http.ResponseWriter, r *http.Request) bool {
	if !isProductionEnv() || h.EmailService.DeliveryConfigured() {
		return false
	}
	_, ownerMode, err := h.ownerCredential(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "sign-in is temporarily unavailable")
		return true
	}
	if h.emailLoginEnabled(ownerMode) {
		return false
	}
	writeFeatureDisabled(w, "email_login_not_configured",
		"Email sign-in is not configured on this server. Sign in with the owner email and password, or set RESEND_API_KEY or SMTP_HOST to enable email codes.")
	return true
}

func (h *Handler) ownerPasswordOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients. Browsers always send Origin on POST, and the
		// required JSON content type forces a CORS preflight cross-origin.
		return true
	}
	for _, allowed := range h.cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

// allowOwnerPasswordAttempt counts the attempt in PostgreSQL before any
// password hashing. Errors fail closed.
func (h *Handler) allowOwnerPasswordAttempt(ctx context.Context, r *http.Request) (bool, error) {
	client := "unknown"
	if addr, err := netip.ParseAddr(h.clientIPForRateLimit(r)); err == nil {
		client = addr.Unmap().String()
	}
	window := int32(ownerPasswordWindow / time.Second)
	buckets := []struct {
		key   string
		limit int32
	}{
		{"ip:" + client, ownerPasswordClientLimit},
		{"global", ownerPasswordGlobalLimit},
	}
	for _, b := range buckets {
		n, err := h.Queries.RecordOwnerPasswordLoginAttempt(ctx, db.RecordOwnerPasswordLoginAttemptParams{
			Bucket:        b.key,
			WindowSeconds: window,
		})
		if err != nil {
			return false, err
		}
		if n > b.limit {
			return false, nil
		}
	}
	// Best effort: drop counters idle for a day.
	_ = h.Queries.DeleteStaleOwnerPasswordLoginAttempts(ctx, 24*60*60)
	return true, nil
}

// PasswordLogin signs in the bootstrapped owner with email and password and
// returns the same token, cookies and body as verify-code.
func (h *Handler) PasswordLogin(w http.ResponseWriter, r *http.Request) {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	if !h.ownerPasswordOriginAllowed(r) {
		writeError(w, http.StatusForbidden, "origin not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, ownerPasswordMaxBodyBytes)
	var req PasswordLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	owner, ok, err := h.ownerCredential(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "sign-in is temporarily unavailable")
		return
	}
	if !ok {
		writeFeatureDisabled(w, "owner_password_login_not_configured", "Owner password sign-in is not configured on this server")
		return
	}

	allowed, err := h.allowOwnerPasswordAttempt(ctx, r)
	if err != nil {
		slog.Error("owner password login: attempt limiter unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "sign-in is temporarily unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(ownerPasswordWindow/time.Second)))
		writeError(w, http.StatusTooManyRequests, "too many sign-in attempts, try again later")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	inBounds := req.Password != "" && len(req.Password) <= ownerauth.MaxPasswordBytes && len(email) <= ownerauth.MaxEmailBytes
	emailOK := subtle.ConstantTimeCompare([]byte(email), []byte(owner.Email.String)) == 1
	// The hash runs whenever the input is in bounds, whether or not the email
	// matched, so a wrong email costs the same as a wrong password.
	passwordOK := inBounds && ownerauth.VerifyPassword(owner.PasswordHash.String, req.Password)
	if !emailOK || !passwordOK {
		slog.Warn("owner password login failed", logger.RequestAttrs(r)...)
		writeErrorCode(w, http.StatusUnauthorized, "invalid_credentials", ownerPasswordInvalidCredentials)
		return
	}

	user, err := h.Queries.GetUser(ctx, owner.UserID)
	if err != nil {
		// A deleted owner never reopens bootstrap and cannot sign in.
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorCode(w, http.StatusUnauthorized, "invalid_credentials", ownerPasswordInvalidCredentials)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "sign-in is temporarily unavailable")
		return
	}
	h.writeLoginSuccess(w, r, user)
}

// writeLoginSuccess issues the JWT, sets the auth/CSRF and CloudFront cookies,
// and writes the LoginResponse shared by email-code and password sign-in.
func (h *Handler) writeLoginSuccess(w http.ResponseWriter, r *http.Request, user db.User) {
	tokenString, err := h.issueJWT(user)
	if err != nil {
		if errors.Is(err, auth.ErrTemporarilyDisabledUser) {
			writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
			return
		}
		slog.Warn("login failed", append(logger.RequestAttrs(r), "error", err, "user_id", uuidToString(user.ID))...)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Set HttpOnly auth cookie (browser clients) + CSRF cookie.
	if err := auth.SetAuthCookies(w, tokenString); err != nil {
		slog.Warn("failed to set auth cookies", "error", err)
	}

	// Set CloudFront signed cookies for CDN access.
	if h.CFSigner != nil {
		for _, cookie := range h.CFSigner.SignedCookies(time.Now().Add(auth.AuthTokenTTL())) {
			http.SetCookie(w, cookie)
		}
	}

	slog.Info("user logged in", append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)
	writeJSON(w, http.StatusOK, LoginResponse{
		Token: tokenString,
		User:  h.userToResponse(user),
	})
}
