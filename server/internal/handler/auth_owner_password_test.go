// Modified for Railway owner-password authentication.

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multica-ai/multica/server/internal/analytics"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/ownerauth"
	"github.com/multica-ai/multica/server/internal/ownerauth/ownerauthtest"
	"github.com/multica-ai/multica/server/internal/realtime"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const (
	testOwnerEmail    = "owner@example.com"
	testOwnerPassword = "correct horse battery staple"
	testAppOrigin     = "https://app.example.test"
)

func newOwnerPasswordHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(db.New(pool), pool, realtime.NewHub(), events.New(), service.NewEmailService(),
		nil, nil, analytics.NoopClient{}, Config{AllowSignup: false, AllowedOrigins: []string{testAppOrigin}})
}

// ownerPasswordFixture returns a handler over a schema bootstrapped with the
// test owner, plus the schema for simulating restarts.
func ownerPasswordFixture(t *testing.T) (*Handler, *ownerauthtest.Schema) {
	t.Helper()
	t.Setenv("RESEND_API_KEY", "")
	t.Setenv("SMTP_HOST", "")
	schema := ownerauthtest.New(t)
	pool := schema.Pool(t)
	if _, err := ownerauth.Bootstrap(context.Background(), pool, testOwnerEmail, testOwnerPassword); err != nil {
		t.Fatal(err)
	}
	return newOwnerPasswordHandler(t, pool), schema
}

func passwordRequest(email, password, remote string) *http.Request {
	req := testutil.JSONRequest(http.MethodPost, "/auth/password", map[string]string{"email": email, "password": password})
	req.Header.Set("Origin", testAppOrigin)
	req.RemoteAddr = remote + ":5555"
	return req
}

func TestPasswordLoginIssuesSessionCookiesAndCSRF(t *testing.T) {
	h, _ := ownerPasswordFixture(t)
	resp := testutil.Call(t, h.PasswordLogin, passwordRequest(" Owner@Example.com ", testOwnerPassword, "198.51.100.1")).Want(http.StatusOK)

	var body LoginResponse
	resp.JSON(&body)
	if body.Token == "" || body.User.Email != testOwnerEmail {
		t.Fatalf("login body = %+v", body)
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range resp.Result().Cookies() {
		cookies[c.Name] = c
	}
	authCookie := cookies[auth.AuthCookieName]
	if authCookie == nil || !authCookie.HttpOnly || authCookie.Value != body.Token {
		t.Fatalf("auth cookie = %+v", authCookie)
	}
	csrf := cookies[auth.SessionCSRFCookieName]
	if csrf == nil || csrf.HttpOnly || cookies[auth.CSRFCookieName] == nil {
		t.Fatalf("csrf cookies = %+v", cookies)
	}

	// The cookie authenticates through the real auth middleware.
	me := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	me.AddCookie(authCookie)
	rec := httptest.NewRecorder()
	middleware.Auth(h.Queries, nil, nil, nil)(http.HandlerFunc(h.GetMe)).ServeHTTP(rec, me)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), testOwnerEmail) {
		t.Fatalf("GET /api/me with cookie = %d %s", rec.Code, rec.Body.String())
	}

	// Unsafe cookie requests need the CSRF header.
	write := httptest.NewRequest(http.MethodPost, "/api/anything", nil)
	write.AddCookie(authCookie)
	if auth.ValidateCSRF(write) {
		t.Fatal("cookie write without CSRF header passed")
	}
	write.Header.Set(auth.CSRFHeaderName, csrf.Value)
	if !auth.ValidateCSRF(write) {
		t.Fatal("cookie write with issued CSRF token rejected")
	}
}

func TestPasswordLoginWrongCredentialsAreGeneric(t *testing.T) {
	h, _ := ownerPasswordFixture(t)
	wrongPassword := testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword+"x", "198.51.100.2")).Want(http.StatusUnauthorized)
	wrongEmail := testutil.Call(t, h.PasswordLogin, passwordRequest("someone@example.com", testOwnerPassword, "198.51.100.2")).Want(http.StatusUnauthorized)
	if wrongPassword.Text() != wrongEmail.Text() {
		t.Fatalf("wrong email and wrong password differ: %q vs %q", wrongEmail.Text(), wrongPassword.Text())
	}
	if !strings.Contains(wrongEmail.Text(), `"invalid_credentials"`) {
		t.Fatalf("unexpected body %q", wrongEmail.Text())
	}
	if len(wrongPassword.Result().Cookies()) != 0 || len(wrongEmail.Result().Cookies()) != 0 {
		t.Fatal("failed login set cookies")
	}
}

func TestPasswordLoginRequestGuards(t *testing.T) {
	h, _ := ownerPasswordFixture(t)

	req := passwordRequest(testOwnerEmail, testOwnerPassword, "198.51.100.3")
	req.Header.Set("Content-Type", "text/plain")
	testutil.Call(t, h.PasswordLogin, req).Want(http.StatusUnsupportedMediaType)

	req = passwordRequest(testOwnerEmail, testOwnerPassword, "198.51.100.3")
	req.Header.Set("Origin", "https://evil.example")
	testutil.Call(t, h.PasswordLogin, req).Want(http.StatusForbidden)

	big := testutil.JSONRequest(http.MethodPost, "/auth/password", `{"email":"`+strings.Repeat("a", 5000)+`"}`)
	testutil.Call(t, h.PasswordLogin, big).Want(http.StatusRequestEntityTooLarge)

	testutil.Call(t, h.PasswordLogin, testutil.JSONRequest(http.MethodPost, "/auth/password", "{")).Want(http.StatusBadRequest)

	// No Origin (CLI / scripts) is allowed.
	req = passwordRequest(testOwnerEmail, testOwnerPassword, "198.51.100.3")
	req.Header.Del("Origin")
	testutil.Call(t, h.PasswordLogin, req).Want(http.StatusOK)
}

func TestPasswordLoginDisabledWithoutBootstrap(t *testing.T) {
	pool := ownerauthtest.New(t).Pool(t)
	h := newOwnerPasswordHandler(t, pool)
	resp := testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "198.51.100.4")).Want(http.StatusForbidden)
	if !strings.Contains(resp.Text(), "owner_password_login_not_configured") {
		t.Fatalf("unexpected body %q", resp.Text())
	}
}

func TestPasswordLoginRateLimitSurvivesRestartAndFailsClosed(t *testing.T) {
	h, schema := ownerPasswordFixture(t)
	tooLong := strings.Repeat("x", ownerauth.MaxPasswordBytes+1) // skips hashing, still counted
	for i := 0; i < ownerPasswordClientLimit; i++ {
		testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, tooLong, "203.0.113.7")).Want(http.StatusUnauthorized)
	}
	// Even the correct password is refused once the cap is hit.
	resp := testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "203.0.113.7")).Want(http.StatusTooManyRequests)
	if resp.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}

	// A restarted server (new pool + handler) still enforces the cap.
	restarted := newOwnerPasswordHandler(t, schema.Pool(t))
	testutil.Call(t, restarted.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "203.0.113.7")).Want(http.StatusTooManyRequests)
	// Other clients are unaffected.
	testutil.Call(t, restarted.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "203.0.113.8")).Want(http.StatusOK)

	// The window expires.
	pool := schema.Pool(t)
	if _, err := pool.Exec(context.Background(), `UPDATE owner_password_login_attempt SET window_start = now() - interval '6 minutes'`); err != nil {
		t.Fatal(err)
	}
	testutil.Call(t, restarted.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "203.0.113.7")).Want(http.StatusOK)

	// A broken limiter fails closed. (Renaming a column, not dropping the
	// table, keeps the name from resolving to public.)
	if _, err := pool.Exec(context.Background(), `ALTER TABLE `+schema.Name+`.owner_password_login_attempt RENAME COLUMN attempts TO attempts_broken`); err != nil {
		t.Fatal(err)
	}
	testutil.Call(t, restarted.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "203.0.113.9")).Want(http.StatusServiceUnavailable)
}

func TestPasswordLoginGlobalCap(t *testing.T) {
	h, _ := ownerPasswordFixture(t)
	tooLong := strings.Repeat("x", ownerauth.MaxPasswordBytes+1)
	for i := 0; i < ownerPasswordGlobalLimit; i++ {
		ip := "192.0.2." + string(rune('0'+i/ownerPasswordClientLimit))
		testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, tooLong, ip)).Want(http.StatusUnauthorized)
	}
	testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "192.0.2.200")).Want(http.StatusTooManyRequests)
}

func TestPasswordLoginDeletedOwnerCannotSignIn(t *testing.T) {
	h, schema := ownerPasswordFixture(t)
	if _, err := schema.Pool(t).Exec(context.Background(), `DELETE FROM "user"`); err != nil {
		t.Fatal(err)
	}
	testutil.Call(t, h.PasswordLogin, passwordRequest(testOwnerEmail, testOwnerPassword, "198.51.100.5")).Want(http.StatusUnauthorized)
}

func TestConfigExposesLoginCapabilitiesWithoutSecrets(t *testing.T) {
	h, schema := ownerPasswordFixture(t)
	read := func(h *Handler) (AppConfig, string) {
		resp := testutil.Call(t, h.GetConfig, httptest.NewRequest(http.MethodGet, "/api/config", nil)).Want(http.StatusOK)
		var cfg AppConfig
		if err := json.Unmarshal(resp.Body.Bytes(), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg, resp.Text()
	}

	t.Setenv("APP_ENV", "production")
	cfg, raw := read(h)
	if !cfg.OwnerPasswordLoginEnabled || cfg.EmailLoginEnabled {
		t.Fatalf("owner mode without email delivery: %+v", cfg)
	}
	for _, secret := range []string{testOwnerEmail, testOwnerPassword, "pbkdf2"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("/api/config leaks %q", secret)
		}
	}

	t.Setenv("RESEND_API_KEY", "re_test_key")
	withEmail := newOwnerPasswordHandler(t, schema.Pool(t))
	if cfg, _ := read(withEmail); !cfg.OwnerPasswordLoginEnabled || !cfg.EmailLoginEnabled {
		t.Fatalf("owner mode with email delivery: %+v", cfg)
	}
	t.Setenv("RESEND_API_KEY", "")

	legacy := newOwnerPasswordHandler(t, ownerauthtest.New(t).Pool(t))
	if cfg, _ := read(legacy); cfg.OwnerPasswordLoginEnabled || !cfg.EmailLoginEnabled {
		t.Fatalf("legacy deployment: %+v", cfg)
	}
}

func TestEmailCodeStdoutFallbackRejectedInOwnerMode(t *testing.T) {
	h, _ := ownerPasswordFixture(t)
	t.Setenv("APP_ENV", "production")
	resp := testutil.Call(t, h.SendCode, testutil.JSONRequest(http.MethodPost, "/auth/send-code", map[string]string{"email": testOwnerEmail})).Want(http.StatusForbidden)
	if !strings.Contains(resp.Text(), "email_login_not_configured") || !strings.Contains(resp.Text(), "RESEND_API_KEY") {
		t.Fatalf("unexpected send-code body %q", resp.Text())
	}
	testutil.Call(t, h.VerifyCode, testutil.JSONRequest(http.MethodPost, "/auth/verify-code", map[string]string{"email": testOwnerEmail, "code": "123456"})).Want(http.StatusForbidden)

	// Outside production the existing dev behavior is preserved.
	t.Setenv("APP_ENV", "")
	if h.rejectUndeliverableEmailLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/send-code", nil)) {
		t.Fatal("dev deployment rejected email login")
	}
	// Legacy production deployments (no owner credential) keep the fallback.
	t.Setenv("APP_ENV", "production")
	legacy := newOwnerPasswordHandler(t, ownerauthtest.New(t).Pool(t))
	if legacy.rejectUndeliverableEmailLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/send-code", nil)) {
		t.Fatal("legacy production deployment rejected email login")
	}
}
