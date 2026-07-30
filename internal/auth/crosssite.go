package auth

// CROSS-SITE SESSIONS — a MajorGTM fork addition.
//
// THE PROBLEM. This recorder runs as an iframe on another origin. The session
// cookie upstream issues is `SameSite=Strict`, which by definition is never sent
// on a cross-site request — so inside that frame the browser holds a perfectly
// valid session and never presents it. The failure has no error to find: the
// refresh call returns 401, ProtectedRoute redirects to /login, and a signed-in
// person is shown a login form. Every layer behaves exactly as written.
//
// So a session established through the capture hand-off needs `SameSite=None`,
// and ONLY that session. Widening the cookie for everyone would trade the whole
// application's CSRF posture for one embedded surface.
//
// WHERE THE FLAG LIVES. In the refresh token itself, not in a companion cookie
// and not in a column. Refresh rotates the cookie on every call, so it has to
// know which kind of session it is rotating BEFORE it writes the new one — and
// the token is the one thing already in its hand that nothing but this service
// can write. A companion cookie would be a second thing to keep in sync and a
// second thing to spoof.
//
// WHAT `None` COSTS AND HOW IT IS PAID. SameSite=Strict was doing double duty as
// the CSRF defence for /api/auth/refresh. Cross-site sessions give that up, so
// they pay for it with `Sec-Fetch-Site`: the browser sets that header, page
// script cannot, and the only legitimate refresh for a capture session is the
// sidecar's own first-party fetch. See requireFirstPartyInitiator.

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sendrec/sendrec/internal/database"
)

// GenerateCrossSiteRefreshToken mints a refresh token marked as belonging to a
// cross-site session.
func GenerateCrossSiteRefreshToken(secret string, userID string, tokenID string) (string, error) {
	return generateToken(secret, userID, "refresh", RefreshTokenDuration, tokenID, true)
}

// SetCrossSiteRefreshTokenCookie writes the session cookie for a capture
// session.
//
// `Secure` is forced rather than taken from configuration: SameSite=None
// without Secure is rejected outright by every current browser, so an insecure
// cross-site cookie is not a weaker cookie, it is no cookie at all. The
// practical consequence is that capture requires HTTPS even in development —
// which is true regardless, since the mode itself requires it.
//
// `Partitioned` (CHIPS) keys the cookie to the embedding top-level site. Without
// it this is an ordinary third-party cookie and dies wherever third-party
// cookies are blocked; with it the browser keeps it, scoped to the parent that
// legitimately embedded us. Partitioning is not a compromise here — a capture
// session only ever exists under that one parent.
func SetCrossSiteRefreshTokenCookie(w http.ResponseWriter, token string) {
	// Clear the legacy /api/auth cookie for symmetry with the first-party
	// setter; a stale duplicate at the narrower path shadows this one.
	http.SetCookie(w, &http.Cookie{
		Name:        "refresh_token",
		Value:       "",
		Path:        "/api/auth",
		HttpOnly:    true,
		Secure:      true,
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
		MaxAge:      -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:        "refresh_token",
		Value:       token,
		Path:        "/",
		HttpOnly:    true,
		Secure:      true,
		SameSite:    http.SameSiteNoneMode,
		Partitioned: true,
		MaxAge:      int(RefreshTokenDuration / time.Second),
	})
}

// IssueCrossSiteTokens is IssueTokens for a session that will live in a frame.
func IssueCrossSiteTokens(ctx context.Context, db database.DBTX, jwtSecret, userID string) (accessToken, refreshToken string, err error) {
	return issueTokensScoped(ctx, db, jwtSecret, userID, true)
}

func issueTokensScoped(ctx context.Context, db database.DBTX, jwtSecret, userID string, crossSite bool) (accessToken, refreshToken string, err error) {
	tokenID, err := NewTokenID()
	if err != nil {
		return "", "", fmt.Errorf("generate token id: %w", err)
	}

	expiresAt := time.Now().Add(RefreshTokenDuration)
	if _, err := db.Exec(ctx, "INSERT INTO refresh_tokens (token_id, user_id, expires_at, revoked) VALUES ($1, $2, $3, false)", tokenID, userID, expiresAt); err != nil {
		return "", "", fmt.Errorf("store refresh token: %w", err)
	}

	accessToken, err = GenerateAccessToken(jwtSecret, userID)
	if err != nil {
		return "", "", fmt.Errorf("generate access token: %w", err)
	}

	if crossSite {
		refreshToken, err = GenerateCrossSiteRefreshToken(jwtSecret, userID, tokenID)
	} else {
		refreshToken, err = GenerateRefreshToken(jwtSecret, userID, tokenID)
	}
	if err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// requireFirstPartyInitiator reports whether a cross-site session may refresh on
// this request.
//
// `Sec-Fetch-Site` describes the relationship between whoever initiated the
// request and its target. The sidecar's own script calls /api/auth/refresh from
// a document on the sidecar's origin, so the only legitimate value is
// `same-origin` — being embedded does not change that. Anything else is someone
// else's page driving the victim's cookie.
//
// An ABSENT header is allowed. Clients that are not browsers never send it, and
// refusing them would break API access to trade for nothing: the header is a
// hardening measure over a request whose response an attacker still cannot read.
func requireFirstPartyInitiator(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}
