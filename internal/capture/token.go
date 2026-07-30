// Package capture verifies the short-lived, signed hand-off token that lets an
// application authenticated in ITS OWN system open the recorder without a second
// login — a MajorGTM fork addition.
//
// THE PROBLEM. This recorder is embedded as a cross-origin iframe. The parent
// application has already authenticated the person, but none of that is visible
// here: cookies and localStorage do not cross an origin boundary, and this
// service has its own users table, its own JWT and its own login. Left alone, a
// signed-in user meets a login screen inside the frame.
//
// SSO would solve it with a visible second login and no mapping back to the
// parent's tenant. This solves it with none: the parent mints a token naming the
// person and the tenant, signs it with a shared secret, and this package verifies
// it. The parent remains the identity authority; this service simply trusts a
// signature it can check.
//
// THE SHAPE is `base64url(json).hex(hmac-sha256)` — deliberately not a JWT. A JWT
// brings an algorithm field, and an algorithm field brings `alg: none` and the
// family of confusion attacks that follow. There is exactly one algorithm here
// and it is not negotiable by the sender.
//
// EVERYTHING FAILS CLOSED: no secret, no signature, a mismatched signature, a
// missing claim, an expired window, or a window longer than MaxLifetime is "no".
package capture

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// MaxLifetime caps how long a hand-off token may be valid, ENFORCED HERE rather
// than trusted from the minter.
//
// The minter lives in another repository and can drift; a bug there that issued
// year-long tokens would otherwise turn a hand-off credential into a permanent
// one. Two minutes is ample — the token is redeemed immediately on iframe load
// and never reused.
const MaxLifetime = 2 * time.Minute

var (
	ErrMalformed = errors.New("capture token malformed")
	ErrSignature = errors.New("capture token signature invalid")
	ErrExpired   = errors.New("capture token expired")
	ErrClaims    = errors.New("capture token missing required claims")
	ErrLifetime  = errors.New("capture token lifetime exceeds the maximum")
	ErrNoSecret  = errors.New("capture token secret not configured")
)

// Claims is the hand-off payload.
//
// Email and Name are carried because this service provisions the user on first
// sight — there is no other channel to learn them, and a recorder whose author
// shows as an opaque uuid is worse than useless in a shared library.
type Claims struct {
	// UserID is the PARENT's user id, stored as the external identity. Not this
	// service's own id, which may not exist yet.
	UserID     string `json:"uid"`
	CustomerID string `json:"cid"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	ExpiresAt  int64  `json:"exp"`
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Mint produces a token. Present so the contract has one implementation and the
// tests exercise the real verifier rather than a hand-rolled fixture; the
// production minter is the parent application.
func Mint(secret string, c *Claims) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + sign(secret, []byte(encoded)), nil
}

// Verify checks a presented token and returns its claims.
//
// `now` is injected so expiry is testable without sleeping and without depending
// on the wall clock.
func Verify(secret, token string, now time.Time) (*Claims, error) {
	// An empty secret must never verify anything: the MAC of the empty key is a
	// value any caller can compute, so "unconfigured" would mean "wide open".
	if secret == "" {
		return nil, ErrNoSecret
	}
	encoded, presented, found := strings.Cut(token, ".")
	if !found || encoded == "" || presented == "" {
		return nil, ErrMalformed
	}
	// A second separator means the shape is not what we think it is; refuse
	// rather than silently parse a prefix.
	if strings.Contains(presented, ".") {
		return nil, ErrMalformed
	}

	presentedMAC, err := hex.DecodeString(presented)
	if err != nil {
		return nil, ErrMalformed
	}
	expectedMAC, err := hex.DecodeString(sign(secret, []byte(encoded)))
	if err != nil {
		return nil, ErrMalformed
	}
	// Constant time: a byte-wise comparison leaks how much of a forged signature
	// was right, which is enough to build one.
	if !hmac.Equal(presentedMAC, expectedMAC) {
		return nil, ErrSignature
	}

	// Only AFTER the signature is proven do we parse — the bytes are untrusted
	// input until then, and parsing first would widen the attack surface to the
	// JSON decoder for anyone who can reach this endpoint.
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrMalformed
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, ErrMalformed
	}

	if c.UserID == "" || c.CustomerID == "" || c.Email == "" || c.ExpiresAt == 0 {
		return nil, ErrClaims
	}
	exp := time.Unix(c.ExpiresAt, 0).UTC()
	if !now.UTC().Before(exp) {
		return nil, ErrExpired
	}
	if exp.Sub(now.UTC()) > MaxLifetime {
		return nil, ErrLifetime
	}
	return &c, nil
}
