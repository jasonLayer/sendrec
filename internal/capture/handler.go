package capture

// THE REDEMPTION ROUTE. token.go proves a hand-off token is genuine; this turns
// a genuine one into a session and gets out of the way.
//
// WHERE IT SENDS PEOPLE. To `/`. The recorder is the root route behind
// ProtectedRoute — there is no /record page, and the redirect target is a
// literal, never anything derived from the request, so this cannot be turned
// into an open redirect.
//
// WHAT IT DOES NOT DO. It renders nothing and asks the recorder to change
// nothing about how it records. A session cookie and a redirect are the entire
// mechanism; the only thing it tells the frontend is which origin, if any, is
// entitled to hear that a recording finished — see parent.go.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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

// EnvOrgMap optionally maps the parent's customer id claim to SendRec's
// organization id. When configured, an unmapped customer is refused: otherwise
// recordings would fall back to personal history and the parent app could not
// safely finalize them.
const EnvOrgMap = "CAPTURE_ORG_MAP"

// errUnverifiedLocalAccount is the pre-hijack refusal. See resolveUser.
var errUnverifiedLocalAccount = errors.New("a local account exists for this address but has never been verified")

// ParentParam is the origin the embedding application claims for itself, and
// ParentQuery is the validated origin handed on to the recorder. See parent.go.
const (
	ParentParam  = "parent"
	ParentQuery  = "capture_parent"
	OrgQuery     = "capture_org"
	SessionQuery = "capture_session"
)

type Handler struct {
	db             database.DBTX
	jwtSecret      string
	secret         string
	allowedParents []string
	orgMap         map[string]string
}

func NewHandler(db database.DBTX, jwtSecret, secret, allowedFrameAncestors string) *Handler {
	return NewHandlerWithOrgMap(db, jwtSecret, secret, allowedFrameAncestors, "")
}

func NewHandlerWithOrgMap(db database.DBTX, jwtSecret, secret, allowedFrameAncestors, orgMapJSON string) *Handler {
	return &Handler{
		db:             db,
		jwtSecret:      jwtSecret,
		secret:         secret,
		allowedParents: ParseAllowedParents(allowedFrameAncestors),
		orgMap:         ParseOrgMap(orgMapJSON),
	}
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

	orgID := h.orgMap[claims.CustomerID]
	if len(h.orgMap) > 0 && orgID == "" {
		slog.Warn("capture: refused an unmapped customer", "external_id", claims.UserID, "customer_id", claims.CustomerID)
		httputil.WriteError(w, http.StatusForbidden, "customer is not configured for capture")
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

	if orgID != "" {
		if err := h.ensureOrgMembership(r.Context(), orgID, userID); err != nil {
			slog.Error("capture: failed to attach the user to the capture organization",
				"user_id", userID, "customer_id", claims.CustomerID, "org_id", orgID, "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "failed to establish a session")
			return
		}
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

	// The recorder needs a targetOrigin to announce completion to, and it cannot
	// discover one for itself. Carrying the VALIDATED origin here means the SPA
	// never has to decide whom to trust — an unrecognised claim simply arrives
	// as nothing, and the recorder stays silent.
	parent := resolveParent(h.allowedParents, r.URL.Query().Get(ParentParam))
	destination := "/"
	values := url.Values{}
	if orgID != "" {
		values.Set(OrgQuery, orgID)
	}
	if parent != "" {
		values.Set(ParentQuery, parent)
	}
	values.Set(SessionQuery, "1")
	destination = "/?" + values.Encode()

	slog.Info("capture: session established",
		"user_id", userID, "external_id", claims.UserID,
		"customer_id", claims.CustomerID, "org_id", orgID, "parent", parent)

	http.Redirect(w, r, destination, http.StatusFound)
}

func ParseOrgMap(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		slog.Error("capture: failed to parse capture organization map", "error", err)
		return nil
	}
	cleaned := make(map[string]string, len(parsed))
	for customerID, orgID := range parsed {
		customerID = strings.TrimSpace(customerID)
		orgID = strings.TrimSpace(orgID)
		if customerID != "" && orgID != "" {
			cleaned[customerID] = orgID
		}
	}
	return cleaned
}

func (h *Handler) ensureOrgMembership(ctx context.Context, orgID, userID string) error {
	_, err := h.db.Exec(ctx,
		"INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING",
		orgID, userID,
	)
	return err
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
