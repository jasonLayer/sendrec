package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A cross-site session cookie must carry SameSite=None. This is THE bug that
// makes an embedded recorder fail silently: the session is valid, the cookie is
// stored, and the browser simply never sends it back from inside the frame.
func TestSetCrossSiteRefreshTokenCookie_SameSiteNone(t *testing.T) {
	rec := httptest.NewRecorder()
	SetCrossSiteRefreshTokenCookie(rec, "the-token")

	cookie := findCookieWithPath(rec.Result().Cookies(), "refresh_token", "/")
	if cookie == nil {
		t.Fatal("expected a refresh_token cookie at /")
	}
	if cookie.SameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSite=None, got %v", cookie.SameSite)
	}
	// SameSite=None without Secure is rejected outright by every current
	// browser, so Secure is not a deployment choice here — it is a requirement
	// of the mode itself, and must hold even where normal cookies are insecure.
	if !cookie.Secure {
		t.Error("expected Secure to be forced on for a SameSite=None cookie")
	}
	// Without CHIPS the cookie is an ordinary third-party cookie and dies under
	// third-party cookie blocking. Partitioned keeps it working, scoped to the
	// embedding top-level site.
	if !cookie.Partitioned {
		t.Error("expected Partitioned (CHIPS) so third-party cookie blocking does not kill the session")
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly")
	}
	if cookie.Value != "the-token" {
		t.Errorf("expected the token as the value, got %q", cookie.Value)
	}
}

// The ordinary login cookie must stay Strict. Widening it for everyone would
// trade the whole application's CSRF posture for one embedded surface.
func TestSetRefreshTokenCookie_StaysStrict(t *testing.T) {
	rec := httptest.NewRecorder()
	SetRefreshTokenCookie(rec, "the-token", true)

	cookie := findCookieWithPath(rec.Result().Cookies(), "refresh_token", "/")
	if cookie == nil {
		t.Fatal("expected a refresh_token cookie at /")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=Strict for a normal login, got %v", cookie.SameSite)
	}
	if cookie.Partitioned {
		t.Error("a first-party login cookie must not be partitioned")
	}
}

// A cross-site refresh token must be recognisable as one after a round trip.
// The flag lives in the token rather than in a companion cookie so that it
// cannot be set, cleared or forged by anything that is not us.
func TestGenerateCrossSiteRefreshToken_CarriesTheFlag(t *testing.T) {
	token, err := GenerateCrossSiteRefreshToken(testSecret, "user-uuid-1", "rt-1")
	if err != nil {
		t.Fatalf("generate cross-site refresh token: %v", err)
	}
	claims, err := ValidateToken(testSecret, token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !claims.CrossSite {
		t.Error("expected CrossSite to survive the round trip")
	}
	if claims.TokenType != "refresh" {
		t.Errorf("expected a refresh token, got %q", claims.TokenType)
	}
}

func TestGenerateRefreshToken_IsNotCrossSite(t *testing.T) {
	token, err := GenerateRefreshToken(testSecret, "user-uuid-1", "rt-1")
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	claims, err := ValidateToken(testSecret, token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.CrossSite {
		t.Error("an ordinary refresh token must not claim to be cross-site")
	}
}

// THE ROTATION TRAP. Refresh re-issues the cookie on every call. If it re-issues
// a cross-site session as Strict, the hand-off works exactly once and then the
// session evaporates on the next reload — with no error anywhere.
func TestRefresh_PreservesCrossSiteCookieMode(t *testing.T) {
	handler, mock := newTestHandler(t)
	defer mock.Close()

	tokenID := "rt-xs"
	refreshToken, err := GenerateCrossSiteRefreshToken(testSecret, "user-uuid-1", tokenID)
	if err != nil {
		t.Fatalf("generate cross-site refresh token: %v", err)
	}

	expectRefreshValidation(mock, tokenID, "user-uuid-1", time.Now().Add(RefreshTokenDuration), false)
	expectInsertRefreshToken(mock, "user-uuid-1")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()

	handler.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	cookie := findCookieWithPath(rec.Result().Cookies(), "refresh_token", "/")
	if cookie == nil {
		t.Fatal("expected a rotated refresh_token cookie")
	}
	if cookie.SameSite != http.SameSiteNoneMode {
		t.Errorf("rotation downgraded the cookie to %v — the session dies on the next load", cookie.SameSite)
	}
	if !cookie.Partitioned {
		t.Error("rotation dropped the CHIPS partition")
	}

	// The NEW token must carry the flag too, or the session degrades one
	// rotation later instead of immediately.
	claims, err := ValidateToken(testSecret, cookie.Value)
	if err != nil {
		t.Fatalf("validate rotated token: %v", err)
	}
	if !claims.CrossSite {
		t.Error("the rotated refresh token lost the cross-site flag")
	}
}

func TestRefresh_KeepsStrictForAnOrdinarySession(t *testing.T) {
	handler, mock := newTestHandler(t)
	defer mock.Close()

	tokenID := "rt-normal"
	refreshToken, err := GenerateRefreshToken(testSecret, "user-uuid-1", tokenID)
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	expectRefreshValidation(mock, tokenID, "user-uuid-1", time.Now().Add(RefreshTokenDuration), false)
	expectInsertRefreshToken(mock, "user-uuid-1")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	rec := httptest.NewRecorder()

	handler.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	cookie := findCookieWithPath(rec.Result().Cookies(), "refresh_token", "/")
	if cookie == nil {
		t.Fatal("expected a rotated refresh_token cookie")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected Strict for an ordinary session, got %v", cookie.SameSite)
	}
}

// SameSite=Strict was carrying the CSRF defence for this endpoint. Dropping it
// for capture sessions has to be paid for, and Sec-Fetch-Site is the payment:
// the browser sets it, page script cannot.
func TestRefresh_RejectsCrossSiteSessionFromAForeignInitiator(t *testing.T) {
	for _, site := range []string{"cross-site", "same-site", "none"} {
		t.Run(site, func(t *testing.T) {
			handler, mock := newTestHandler(t)
			defer mock.Close()

			refreshToken, err := GenerateCrossSiteRefreshToken(testSecret, "user-uuid-1", "rt-xs")
			if err != nil {
				t.Fatalf("generate cross-site refresh token: %v", err)
			}

			// EVERY OTHER REASON TO REFUSE IS REMOVED. The token is valid, the
			// stored row is live, and the rotation would succeed — so a 200 here
			// means the initiator check is the only thing that was holding, and
			// deleting it turns this test red instead of leaving it green
			// against an unconfigured mock.
			expectRefreshValidation(mock, "rt-xs", "user-uuid-1", time.Now().Add(RefreshTokenDuration), false)
			expectInsertRefreshToken(mock, "user-uuid-1")

			req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
			req.Header.Set("Sec-Fetch-Site", site)
			rec := httptest.NewRecorder()

			handler.Refresh(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 for a %s initiator, got %d", site, rec.Code)
			}
			// Nothing may be rotated or revoked on the way to that refusal, or
			// the forgery is still a denial of service against the real session.
			// Unmet expectations are the proof: the database was never reached.
			if err := mock.ExpectationsWereMet(); err == nil {
				t.Error("expected the request to be refused before any database work")
			}
		})
	}
}

// An ordinary session is unaffected by the header — its cookie could not have
// been sent cross-site in the first place, and a native client that sends no
// Sec-Fetch-Site at all must keep working.
func TestRefresh_OrdinarySessionIgnoresSecFetchSite(t *testing.T) {
	handler, mock := newTestHandler(t)
	defer mock.Close()

	refreshToken, err := GenerateRefreshToken(testSecret, "user-uuid-1", "rt-normal")
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	expectRefreshValidation(mock, "rt-normal", "user-uuid-1", time.Now().Add(RefreshTokenDuration), false)
	expectInsertRefreshToken(mock, "user-uuid-1")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	handler.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRefresh_CrossSiteAllowedWhenSecFetchSiteIsAbsent(t *testing.T) {
	handler, mock := newTestHandler(t)
	defer mock.Close()

	refreshToken, err := GenerateCrossSiteRefreshToken(testSecret, "user-uuid-1", "rt-xs")
	if err != nil {
		t.Fatalf("generate cross-site refresh token: %v", err)
	}

	expectRefreshValidation(mock, "rt-xs", "user-uuid-1", time.Now().Add(RefreshTokenDuration), false)
	expectInsertRefreshToken(mock, "user-uuid-1")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	rec := httptest.NewRecorder()

	handler.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when the browser sends no Sec-Fetch-Site, got %d", rec.Code)
	}
}
