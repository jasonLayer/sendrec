package capture

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/sendrec/sendrec/internal/auth"
)

const (
	testJWTSecret     = "test-jwt-secret-key"
	testCaptureSecret = "test-capture-secret"
)

func newTestHandler(t *testing.T) (*Handler, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("create pgxmock pool: %v", err)
	}
	t.Cleanup(mock.Close)
	return NewHandler(mock, testJWTSecret, testCaptureSecret, "https://parent.example"), mock
}

func validClaims() *Claims {
	return &Claims{
		UserID:     "parent-user-1",
		CustomerID: "parent-customer-1",
		Email:      "alice@example.com",
		Name:       "Alice",
		ExpiresAt:  time.Now().Add(time.Minute).Unix(),
	}
}

func mintFor(t *testing.T, c *Claims) string {
	t.Helper()
	token, err := Mint(testCaptureSecret, c)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return token
}

func redeem(t *testing.T, h *Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/capture"
	if token != "" {
		target += "?token=" + token
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.Redeem(rec, req)
	return rec
}

// expectIdentityHit resolves the parent user to an identity that already exists.
func expectIdentityHit(mock pgxmock.PgxPoolIface, externalID, userID string) {
	mock.ExpectQuery(`SELECT user_id FROM external_identities`).
		WithArgs(Provider, externalID).
		WillReturnRows(pgxmock.NewRows([]string{"user_id"}).AddRow(userID))
}

func expectIdentityMiss(mock pgxmock.PgxPoolIface, externalID string) {
	mock.ExpectQuery(`SELECT user_id FROM external_identities`).
		WithArgs(Provider, externalID).
		WillReturnError(pgx.ErrNoRows)
}

func expectUserByEmail(mock pgxmock.PgxPoolIface, email, userID string, verified bool) {
	mock.ExpectQuery(`SELECT id, email_verified FROM users`).
		WithArgs(email).
		WillReturnRows(pgxmock.NewRows([]string{"id", "email_verified"}).AddRow(userID, verified))
}

func expectNoUserByEmail(mock pgxmock.PgxPoolIface, email string) {
	mock.ExpectQuery(`SELECT id, email_verified FROM users`).
		WithArgs(email).
		WillReturnError(pgx.ErrNoRows)
}

func expectLinkIdentity(mock pgxmock.PgxPoolIface, userID, externalID, email string) {
	mock.ExpectExec(`INSERT INTO external_identities`).
		WithArgs(userID, Provider, externalID, email).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func expectCreateUser(mock pgxmock.PgxPoolIface, email, name, userID string) {
	mock.ExpectQuery(`INSERT INTO users`).
		WithArgs(email, "", name).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(userID))
}

func expectIssueTokens(mock pgxmock.PgxPoolIface, userID string) {
	mock.ExpectExec(`INSERT INTO refresh_tokens`).
		WithArgs(pgxmock.AnyArg(), userID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "refresh_token" && cookie.Path == "/" {
			return cookie
		}
	}
	return nil
}

// The whole point of the route: a valid token becomes a session the embedded
// recorder can actually use, and the browser lands on the recorder.
func TestRedeem_EstablishesACrossSiteSession(t *testing.T) {
	handler, mock := newTestHandler(t)

	expectIdentityHit(mock, "parent-user-1", "local-user-1")
	expectIssueTokens(mock, "local-user-1")

	rec := redeem(t, handler, mintFor(t, validClaims()))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	// The recorder IS the root route, behind ProtectedRoute. There is no
	// /record page to send anyone to.
	if location := rec.Header().Get("Location"); location != "/" {
		t.Errorf("expected a redirect to /, got %q", location)
	}

	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("expected a refresh_token cookie")
	}
	if cookie.SameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSite=None — a Strict cookie is never sent from inside the frame; got %v", cookie.SameSite)
	}
	if !cookie.Secure || !cookie.Partitioned || !cookie.HttpOnly {
		t.Errorf("expected Secure+Partitioned+HttpOnly, got secure=%v partitioned=%v httponly=%v",
			cookie.Secure, cookie.Partitioned, cookie.HttpOnly)
	}

	claims, err := auth.ValidateToken(testJWTSecret, cookie.Value)
	if err != nil {
		t.Fatalf("the cookie is not a valid session token: %v", err)
	}
	if claims.UserID != "local-user-1" {
		t.Errorf("expected the resolved local user, got %q", claims.UserID)
	}
	if claims.TokenType != "refresh" {
		t.Errorf("expected a refresh token, got %q", claims.TokenType)
	}
	if !claims.CrossSite {
		t.Error("expected the session to be marked cross-site, or the first rotation downgrades it")
	}

	// A response that both sets a session and redirects must not be cached by
	// anything between us and the browser.
	if store := rec.Header().Get("Cache-Control"); store != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", store)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet database expectations: %v", err)
	}
}

// The recorder is handed a targetOrigin only when the claim survives the
// allowlist. Everything else arrives as nothing, and the recorder stays silent
// rather than announcing a share token to whoever asked.
func TestRedeem_CarriesOnlyAValidatedParentOrigin(t *testing.T) {
	cases := []struct {
		name     string
		claimed  string
		location string
	}{
		{"allowed", "https://parent.example", "/?capture_parent=https%3A%2F%2Fparent.example"},
		{"absent", "", "/"},
		{"unknown origin", "https://evil.example", "/"},
		{"prefix impostor", "https://parent.example.evil.test", "/"},
		{"suffix impostor", "https://evil.test/https://parent.example", "/"},
		{"scheme downgrade", "http://parent.example", "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, mock := newTestHandler(t)
			expectIdentityHit(mock, "parent-user-1", "local-user-1")
			expectIssueTokens(mock, "local-user-1")

			target := "/capture?token=" + mintFor(t, validClaims())
			if tc.claimed != "" {
				target += "&" + ParentParam + "=" + url.QueryEscape(tc.claimed)
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			handler.Redeem(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
			}
			if location := rec.Header().Get("Location"); location != tc.location {
				t.Errorf("expected Location %q, got %q", tc.location, location)
			}
			// A refused parent claim must not refuse the hand-off itself:
			// someone who opened the recorder directly still gets a session.
			if sessionCookie(t, rec) == nil {
				t.Error("expected a session regardless of the parent claim")
			}
		})
	}
}

// Every rejection must be silent about WHY and must leave no session behind.
func TestRedeem_RefusesBadTokens(t *testing.T) {
	expired := validClaims()
	expired.ExpiresAt = time.Now().Add(-time.Second).Unix()

	tooLong := validClaims()
	tooLong.ExpiresAt = time.Now().Add(MaxLifetime + time.Minute).Unix()

	noEmail := validClaims()
	noEmail.Email = ""

	cases := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"absent", func(*testing.T) string { return "" }},
		{"garbage", func(*testing.T) string { return "not-a-token" }},
		{"wrong secret", func(t *testing.T) string {
			token, err := Mint("some-other-secret", validClaims())
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			return token
		}},
		{"expired", func(t *testing.T) string { return mintFor(t, expired) }},
		{"lifetime beyond the ceiling", func(t *testing.T) string { return mintFor(t, tooLong) }},
		{"missing claims", func(t *testing.T) string { return mintFor(t, noEmail) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, mock := newTestHandler(t)

			rec := redeem(t, handler, tc.token(t))

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", rec.Code)
			}
			if cookie := sessionCookie(t, rec); cookie != nil {
				t.Error("a refused hand-off must not leave a session cookie")
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("a refused hand-off must not redirect, got %q", location)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a refused hand-off must not touch the database: %v", err)
			}
		})
	}
}

// An unconfigured secret must not mean "accept anything". The MAC of an empty
// key is computable by anyone.
func TestRedeem_RefusesWhenNoSecretIsConfigured(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("create pgxmock pool: %v", err)
	}
	defer mock.Close()
	handler := NewHandler(mock, testJWTSecret, "", "https://parent.example")

	token, err := Mint("", validClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := redeem(t, handler, token)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no configured secret, got %d", rec.Code)
	}
	if cookie := sessionCookie(t, rec); cookie != nil {
		t.Error("expected no session cookie")
	}
}

// First sight of a person who has no account here at all.
func TestRedeem_ProvisionsAnUnknownUser(t *testing.T) {
	handler, mock := newTestHandler(t)

	expectIdentityMiss(mock, "parent-user-1")
	expectNoUserByEmail(mock, "alice@example.com")
	expectCreateUser(mock, "alice@example.com", "Alice", "local-user-new")
	expectLinkIdentity(mock, "local-user-new", "parent-user-1", "alice@example.com")
	expectIssueTokens(mock, "local-user-new")

	rec := redeem(t, handler, mintFor(t, validClaims()))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet database expectations: %v", err)
	}
}

// A name is optional in the token but NOT NULL in the table. Falling back to the
// email beats a failed hand-off, and beats a library full of blank authors.
func TestRedeem_FallsBackToTheEmailWhenTheNameIsAbsent(t *testing.T) {
	handler, mock := newTestHandler(t)

	claims := validClaims()
	claims.Name = ""

	expectIdentityMiss(mock, "parent-user-1")
	expectNoUserByEmail(mock, "alice@example.com")
	expectCreateUser(mock, "alice@example.com", "alice@example.com", "local-user-new")
	expectLinkIdentity(mock, "local-user-new", "parent-user-1", "alice@example.com")
	expectIssueTokens(mock, "local-user-new")

	rec := redeem(t, handler, mintFor(t, claims))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet database expectations: %v", err)
	}
}

// Someone already here under the same address, with that address proven.
func TestRedeem_LinksToAnExistingVerifiedAccount(t *testing.T) {
	handler, mock := newTestHandler(t)

	expectIdentityMiss(mock, "parent-user-1")
	expectUserByEmail(mock, "alice@example.com", "local-user-existing", true)
	expectLinkIdentity(mock, "local-user-existing", "parent-user-1", "alice@example.com")
	expectIssueTokens(mock, "local-user-existing")

	rec := redeem(t, handler, mintFor(t, validClaims()))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet database expectations: %v", err)
	}
}

// PRE-HIJACK DEFENCE. An unverified local row proves nothing about who owns that
// address — someone may have registered it here precisely to be handed a real
// person's session. Linking to it would give the squatter, who knows the
// password, everything the real person records.
func TestRedeem_RefusesToLinkToAnUnverifiedAccount(t *testing.T) {
	handler, mock := newTestHandler(t)

	expectIdentityMiss(mock, "parent-user-1")
	expectUserByEmail(mock, "alice@example.com", "squatter-user", false)
	// The rest of the hand-off is fully primed, so deleting the verification
	// check produces a working 302 rather than an incidental failure against an
	// unconfigured mock. Only the check itself stands between here and a session.
	expectLinkIdentity(mock, "squatter-user", "parent-user-1", "alice@example.com")
	expectIssueTokens(mock, "squatter-user")

	rec := redeem(t, handler, mintFor(t, validClaims()))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if cookie := sessionCookie(t, rec); cookie != nil {
		t.Error("expected no session cookie for a refused link")
	}
	// Unmet expectations are the assertion: nothing was linked, nothing issued.
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Error("expected the hand-off to stop before linking or issuing anything")
	}
}

// The token names the parent's user id. Two different parent users must never
// collapse into one local account just because a lookup was written loosely.
func TestRedeem_KeepsParentIdentitiesDistinct(t *testing.T) {
	handler, mock := newTestHandler(t)

	other := validClaims()
	other.UserID = "parent-user-2"
	other.Email = "bob@example.com"
	other.Name = "Bob"

	expectIdentityHit(mock, "parent-user-2", "local-user-2")
	expectIssueTokens(mock, "local-user-2")

	rec := redeem(t, handler, mintFor(t, other))

	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("expected a refresh_token cookie")
	}
	claims, err := auth.ValidateToken(testJWTSecret, cookie.Value)
	if err != nil {
		t.Fatalf("validate session token: %v", err)
	}
	if claims.UserID != "local-user-2" {
		t.Errorf("expected local-user-2, got %q", claims.UserID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet database expectations: %v", err)
	}
}
