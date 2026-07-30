package capture

// THE REDEMPTION ROUTE. token.go proves a hand-off token is genuine; this turns
// a genuine one into a session and gets out of the way.
//
// WHERE IT SENDS PEOPLE. To `/`. The recorder is the root route behind
// ProtectedRoute — there is no /record page, and the redirect target is a
// literal, never anything derived from the request, so this cannot be turned
// into an open redirect.
//
// WHAT IT DOES NOT DO. It does not render anything, it does not touch the
// frontend, and it does not ask the recorder to change. A session cookie and a
// redirect are the entire mechanism.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sendrec/sendrec/internal/auth"
	"github.com/sendrec/sendrec/internal/database"
	"github.com/sendrec/sendrec/internal/httputil"
)

// Provider is the name these hand-offs are recorded under in
// external_identities, alongside the SSO providers. It names the ISSUER of the
// identity — the parent application — because that is what the row means: this
// local user is that application's user.
const Provider = "majorgtm"

// EnvSecret names the signing secret. Deliberately NOT the webhook secret: that
// one only lets its holder deliver a transcript, this one lets its holder become
// any user of this deployment. Different power, different blast radius, separate
// rotation.
const EnvSecret = "CAPTURE_TOKEN_SECRET"

// errUnverifiedLocalAccount is the pre-hijack refusal. See resolveUser.
var errUnverifiedLocalAccount = errors.New("a local account exists for this address but has never been verified")

type Handler struct {
	db        database.DBTX
	jwtSecret string
	secret    string
}

func NewHandler(db database.DBTX, jwtSecret, secret string) *Handler {
	return &Handler{db: db, jwtSecret: jwtSecret, secret: secret}
}

// Redeem exchanges a hand-off token for a session.
//
// Failures are deliberately uninformative to the caller and specific in the log.
// Someone probing this endpoint learns only that it said no; an operator reading
// the logs learns which of the several possible "no"s it was.
func (h *Handler) Redeem(w http.ResponseWriter, r *http.Request) {
	// This response both mints a session and redirects. Nothing between here and
	// the browser may keep a copy of either.
	w.Header().Set("Cache-Control", "no-store")

	claims, err := Verify(h.secret, r.URL.Query().Get("token"), time.Now())
	if err != nil {
		slog.Warn("capture: refused a hand-off token", "reason", err)
		httputil.WriteError(w, http.StatusUnauthorized, "invalid capture token")
		return
	}

	userID, err := h.resolveUser(r.Context(), claims)
	if err != nil {
		if errors.Is(err, errUnverifiedLocalAccount) {
			slog.Warn("capture: refused to link a hand-off to an unverified local account",
				"external_id", claims.UserID, "customer_id", claims.CustomerID)
			httputil.WriteError(w, http.StatusForbidden, "this address already has an unverified account here")
			return
		}
		slog.Error("capture: failed to resolve the user", "external_id", claims.UserID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to establish a session")
		return
	}

	// Only the refresh token is used. The access token lives in memory in the
	// SPA, which asks for one on load — handing it over in a URL would put a
	// bearer credential in history and in every proxy log on the way.
	_, refreshToken, err := auth.IssueCrossSiteTokens(r.Context(), h.db, h.jwtSecret, userID)
	if err != nil {
		slog.Error("capture: failed to issue tokens", "user_id", userID, "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to establish a session")
		return
	}

	auth.SetCrossSiteRefreshTokenCookie(w, refreshToken)
	slog.Info("capture: session established",
		"user_id", userID, "external_id", claims.UserID, "customer_id", claims.CustomerID)

	http.Redirect(w, r, "/", http.StatusFound)
}

// resolveUser maps the parent's user onto a local one, provisioning as needed.
//
// The order is the same as the SSO path's, and for the same reasons:
//
//  1. An existing identity link is the answer, full stop. It survives the person
//     changing their email on either side.
//
//  2. Otherwise a VERIFIED local account with that address is adopted and
//     linked, so a person who already had an account here keeps their library
//     rather than acquiring a second, empty one.
//
//  3. An UNVERIFIED local account with that address is refused. Nobody proved
//     they own that address, so it may have been registered specifically to
//     receive somebody else's hand-off — and whoever registered it knows a
//     password for the account the hand-off would land in. Refusing strands one
//     person until an operator intervenes; linking hands over everything they
//     ever record. Disable registration on this deployment and the case cannot
//     arise at all.
//
//  4. Otherwise create the account. The password column is NOT NULL and gets an
//     empty string, which no bcrypt comparison can ever match — the account is
//     reachable through the hand-off and through nothing else.
func (h *Handler) resolveUser(ctx context.Context, c *Claims) (string, error) {
	var userID string
	err := h.db.QueryRow(ctx,
		"SELECT user_id FROM external_identities WHERE provider = $1 AND external_id = $2",
		Provider, c.UserID,
	).Scan(&userID)
	if err == nil {
		return userID, nil
	}

	var emailVerified bool
	err = h.db.QueryRow(ctx,
		"SELECT id, email_verified FROM users WHERE email = $1", c.Email,
	).Scan(&userID, &emailVerified)
	if err == nil {
		if !emailVerified {
			return "", errUnverifiedLocalAccount
		}
		if err := h.linkIdentity(ctx, userID, c); err != nil {
			return "", err
		}
		return userID, nil
	}

	// A person is more use in a shared library as their name than as a uuid; the
	// token does not require one, so the address is the fallback.
	name := c.Name
	if name == "" {
		name = c.Email
	}

	err = h.db.QueryRow(ctx,
		"INSERT INTO users (email, password, name, email_verified) VALUES ($1, $2, $3, true) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id",
		c.Email, "", name,
	).Scan(&userID)
	if err != nil {
		return "", err
	}

	if err := h.linkIdentity(ctx, userID, c); err != nil {
		return "", err
	}
	return userID, nil
}

// linkIdentity records the parent identity. DO NOTHING on conflict because two
// hand-offs for the same person can race on first sight, and the second one
// arriving is not an error — the link it wanted already exists.
func (h *Handler) linkIdentity(ctx context.Context, userID string, c *Claims) error {
	_, err := h.db.Exec(ctx,
		"INSERT INTO external_identities (user_id, provider, external_id, email) VALUES ($1, $2, $3, $4) ON CONFLICT (provider, external_id) DO NOTHING",
		userID, Provider, c.UserID, c.Email,
	)
	return err
}
