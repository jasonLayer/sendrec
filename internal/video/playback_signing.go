package video

// SIGNED PLAYBACK — a MajorGTM fork addition.
//
// Upstream's sharing model is "a share token IS the credential": anyone holding
// /watch/{shareToken} can watch, optionally gated behind a share password. That is
// the right default for a Loom-style product where sharing a link is the point.
//
// It is not sufficient when the recorder is a sidecar for an application that
// hands playback URLs to a whole tenant. There the share token travels through an
// API response, a rendered page, and browser history, and it never expires — so
// possession of a URL from six months ago is still possession of the recording.
//
// This adds a SECOND, time-bounded credential in front of that model:
//
//     ?exp=<unix seconds>&sig=<hex HMAC-SHA256(secret, shareToken + "." + exp)>
//
// and, when PLAYBACK_REQUIRE_SIGNED is on, refuses playback without it. The share
// token then addresses the recording rather than authorising it.
//
// WHY REUSE h.hmacSecret rather than take a new one: it is the same trust domain
// and the same rotation event (both are "the secret that proves this server minted
// a playback credential"), and one secret to rotate is one fewer to get wrong. The
// scheme is deliberately the same shape as signWatchCookie for the same reason.
//
// EVERYTHING HERE FAILS CLOSED. No secret, no params, a malformed exp, a signature
// for a different token, an expired window — every one of those is "no".

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Query parameters carrying the credential.
const (
	playbackExpParam = "exp"
	playbackSigParam = "sig"
)

// EnvRequireSignedPlayback turns the requirement on. Off by default so a stock
// self-hosted deployment keeps upstream's sharing behaviour unchanged — this is
// an added restriction, and one that silently appeared would break every existing
// share link.
const EnvRequireSignedPlayback = "PLAYBACK_REQUIRE_SIGNED"

// isSignedPlaybackRequired reports whether unsigned playback must be refused.
func isSignedPlaybackRequired() bool {
	return strings.TrimSpace(os.Getenv(EnvRequireSignedPlayback)) == "true"
}

// playbackBasestring is what gets signed.
//
// The share token is INSIDE the signed material, which is the property that stops
// a signature minted for one recording from playing another: swap the token and
// the MAC no longer matches. The separator is a character that cannot occur in
// either field, so no pair of (token, exp) values can produce the same basestring
// as a different pair.
func playbackBasestring(shareToken string, exp int64) string {
	return shareToken + "." + strconv.FormatInt(exp, 10)
}

// signPlaybackToken mints the signature for a (shareToken, expiry) pair.
func signPlaybackToken(hmacSecret, shareToken string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(playbackBasestring(shareToken, exp)))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignedPlaybackQuery returns the query string granting playback of `shareToken`
// until `expiresAt`, e.g. "exp=1700000000&sig=abc…".
//
// Exported because the URL is minted by whatever hands playback to a client, not
// by the watch handler that checks it.
func SignedPlaybackQuery(hmacSecret, shareToken string, expiresAt time.Time) string {
	exp := expiresAt.UTC().Unix()
	return playbackExpParam + "=" + strconv.FormatInt(exp, 10) +
		"&" + playbackSigParam + "=" + signPlaybackToken(hmacSecret, shareToken, exp)
}

// verifyPlaybackSignature checks a presented credential.
//
// Pure: `now` is injected, so expiry behaviour is testable without sleeping and
// without depending on the wall clock.
func verifyPlaybackSignature(hmacSecret, shareToken, expParam, sigParam string, now time.Time) bool {
	// An empty secret must never verify anything. Without this an unconfigured
	// deployment would accept the signature of an empty key — the worst possible
	// reading of "no secret set".
	if hmacSecret == "" || shareToken == "" || expParam == "" || sigParam == "" {
		return false
	}
	exp, err := strconv.ParseInt(strings.TrimSpace(expParam), 10, 64)
	if err != nil {
		return false
	}
	// Expiry is checked BEFORE the compare, but both run regardless of order: the
	// MAC is over the exp too, so a client cannot extend a window without
	// invalidating its own signature.
	if now.UTC().Unix() >= exp {
		return false
	}
	presented, err := hex.DecodeString(strings.TrimSpace(sigParam))
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(signPlaybackToken(hmacSecret, shareToken, exp))
	if err != nil {
		return false
	}
	// Constant time: a byte-by-byte comparison leaks how much of a forged
	// signature was correct, which is enough to construct one.
	return hmac.Equal(presented, expected)
}

// hasValidPlaybackSignature reads the credential off the request.
func hasValidPlaybackSignature(r *http.Request, hmacSecret, shareToken string) bool {
	q := r.URL.Query()
	return verifyPlaybackSignature(
		hmacSecret, shareToken,
		q.Get(playbackExpParam), q.Get(playbackSigParam),
		time.Now(),
	)
}

// playbackAllowed is the gate the watch entry points call.
//
// Returns true when the request may proceed to upstream's own share-password
// logic. When the requirement is off this is always true, so upstream behaviour
// is untouched unless an operator opts in.
func (h *Handler) playbackAllowed(r *http.Request, shareToken string) bool {
	if !isSignedPlaybackRequired() {
		return true
	}
	return hasValidPlaybackSignature(r, h.hmacSecret, shareToken)
}
