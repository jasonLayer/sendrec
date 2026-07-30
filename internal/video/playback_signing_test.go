package video

// The security properties, each asserted on its own so a failure names which one
// broke. Every case here is a way in that must stay shut.

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testPlaybackSecret = "playback-signing-secret"

var testNow = time.Unix(1_700_000_000, 0).UTC()

func futureExp(d time.Duration) int64 { return testNow.Add(d).Unix() }

func TestVerifyPlaybackSignatureAcceptsAFreshCredential(t *testing.T) {
	exp := futureExp(10 * time.Minute)
	sig := signPlaybackToken(testPlaybackSecret, "tok_a", exp)
	if !verifyPlaybackSignature(testPlaybackSecret, "tok_a", strconv.FormatInt(exp, 10), sig, testNow) {
		t.Fatal("a correctly signed, unexpired credential was refused")
	}
}

func TestVerifyPlaybackSignatureRejectsAnExpiredCredential(t *testing.T) {
	// The whole point of the scheme: possession of an old URL is not access.
	exp := testNow.Add(-time.Second).Unix()
	sig := signPlaybackToken(testPlaybackSecret, "tok_a", exp)
	if verifyPlaybackSignature(testPlaybackSecret, "tok_a", strconv.FormatInt(exp, 10), sig, testNow) {
		t.Fatal("an expired credential was accepted")
	}
}

func TestVerifyPlaybackSignatureRejectsExpiryExactlyNow(t *testing.T) {
	// Boundary: `exp` is the instant it STOPS working, not the last instant it does.
	exp := testNow.Unix()
	sig := signPlaybackToken(testPlaybackSecret, "tok_a", exp)
	if verifyPlaybackSignature(testPlaybackSecret, "tok_a", strconv.FormatInt(exp, 10), sig, testNow) {
		t.Fatal("a credential expiring exactly now was accepted")
	}
}

func TestVerifyPlaybackSignatureIsBoundToItsShareToken(t *testing.T) {
	// The share token is inside the signed material, so a credential minted for
	// one recording must not play another. Without this the scheme would be a
	// global "any video until exp" pass.
	exp := futureExp(10 * time.Minute)
	sigForA := signPlaybackToken(testPlaybackSecret, "tok_a", exp)
	if verifyPlaybackSignature(testPlaybackSecret, "tok_b", strconv.FormatInt(exp, 10), sigForA, testNow) {
		t.Fatal("a signature minted for tok_a played tok_b")
	}
}

func TestVerifyPlaybackSignatureRejectsAnExtendedWindow(t *testing.T) {
	// A client that edits `exp` upward invalidates its own signature, because the
	// MAC covers exp. This is why expiry needs no separate integrity check.
	exp := futureExp(1 * time.Minute)
	sig := signPlaybackToken(testPlaybackSecret, "tok_a", exp)
	stretched := strconv.FormatInt(futureExp(90*24*time.Hour), 10)
	if verifyPlaybackSignature(testPlaybackSecret, "tok_a", stretched, sig, testNow) {
		t.Fatal("moving exp forward extended access")
	}
}

func TestVerifyPlaybackSignatureRejectsAnotherSecret(t *testing.T) {
	exp := futureExp(10 * time.Minute)
	sig := signPlaybackToken("some-other-deployments-secret", "tok_a", exp)
	if verifyPlaybackSignature(testPlaybackSecret, "tok_a", strconv.FormatInt(exp, 10), sig, testNow) {
		t.Fatal("a signature from a different secret was accepted")
	}
}

func TestVerifyPlaybackSignatureNeverVerifiesWithAnEmptySecret(t *testing.T) {
	// An unconfigured deployment must refuse everything, not accept the MAC of an
	// empty key — which is a computable value any caller could present.
	exp := futureExp(10 * time.Minute)
	sig := signPlaybackToken("", "tok_a", exp)
	if verifyPlaybackSignature("", "tok_a", strconv.FormatInt(exp, 10), sig, testNow) {
		t.Fatal("an empty secret verified a signature")
	}
}

func TestVerifyPlaybackSignatureRejectsMalformedInput(t *testing.T) {
	exp := futureExp(10 * time.Minute)
	expStr := strconv.FormatInt(exp, 10)
	good := signPlaybackToken(testPlaybackSecret, "tok_a", exp)

	cases := []struct{ name, token, exp, sig string }{
		{"absent exp and sig", "tok_a", "", ""},
		{"absent sig", "tok_a", expStr, ""},
		{"absent exp", "tok_a", "", good},
		{"empty share token", "", expStr, good},
		{"non-numeric exp", "tok_a", "not-a-number", good},
		{"exp as a float", "tok_a", "1700000600.5", good},
		{"sig is not hex", "tok_a", expStr, "zzzz"},
		{"sig truncated", "tok_a", expStr, good[:len(good)-2]},
		{"sig padded", "tok_a", expStr, good + "00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if verifyPlaybackSignature(testPlaybackSecret, c.token, c.exp, c.sig, testNow) {
				t.Fatalf("%s was accepted", c.name)
			}
		})
	}
}

func TestVerifyPlaybackSignatureIsHexCaseInsensitive(t *testing.T) {
	// Not a hole: hex decoding is case-insensitive, so an upper-cased signature
	// decodes to the SAME bytes and is the same credential. Asserted rather than
	// left implicit, because "case changed it" would otherwise look like a bug the
	// next reader should go fix.
	exp := futureExp(10 * time.Minute)
	sig := signPlaybackToken(testPlaybackSecret, "tok_a", exp)
	if !verifyPlaybackSignature(
		testPlaybackSecret, "tok_a", strconv.FormatInt(exp, 10), strings.ToUpper(sig), testNow,
	) {
		t.Fatal("upper-cased hex was refused; it decodes to identical bytes")
	}
}

func TestSignedPlaybackQueryRoundTrips(t *testing.T) {
	// What the minting side produces must be what the checking side accepts —
	// these are the two halves that drift apart if the param names diverge.
	// time.Now(), not testNow: hasValidPlaybackSignature reads the real clock, so a
	// credential minted against the fixture instant is legitimately expired.
	q := SignedPlaybackQuery(testPlaybackSecret, "tok_a", time.Now().Add(5*time.Minute))
	req := httptest.NewRequest("GET", "/watch/tok_a?"+q, nil)
	if !hasValidPlaybackSignature(req, testPlaybackSecret, "tok_a") {
		t.Fatalf("a freshly minted query did not verify: %s", q)
	}
	// And it is bound to its token here too, through the real request path.
	if hasValidPlaybackSignature(req, testPlaybackSecret, "tok_b") {
		t.Fatal("a minted query verified against a different share token")
	}
}

func TestPlaybackAllowedIsOffByDefault(t *testing.T) {
	// Upstream behaviour must be untouched unless an operator opts in: turning
	// this on silently would break every share link already in the wild.
	t.Setenv(EnvRequireSignedPlayback, "")
	h := &Handler{hmacSecret: testPlaybackSecret}
	req := httptest.NewRequest("GET", "/watch/tok_a", nil)
	if !h.playbackAllowed(req, "tok_a") {
		t.Fatal("unsigned playback was refused while the requirement was off")
	}
}

func TestPlaybackAllowedEnforcesWhenRequired(t *testing.T) {
	t.Setenv(EnvRequireSignedPlayback, "true")
	h := &Handler{hmacSecret: testPlaybackSecret}

	unsigned := httptest.NewRequest("GET", "/watch/tok_a", nil)
	if h.playbackAllowed(unsigned, "tok_a") {
		t.Fatal("unsigned playback was allowed while the requirement was on")
	}

	q := SignedPlaybackQuery(testPlaybackSecret, "tok_a", time.Now().Add(5*time.Minute))
	signed := httptest.NewRequest("GET", "/watch/tok_a?"+q, nil)
	if !h.playbackAllowed(signed, "tok_a") {
		t.Fatal("a validly signed request was refused while the requirement was on")
	}
}

func TestPlaybackAllowedTreatsAnyNonTrueValueAsOff(t *testing.T) {
	// "1", "yes" and "TRUE" are the classic near-misses. Matching upstream's own
	// `== "true"` convention means an operator who writes one of those gets the
	// documented default rather than a half-enabled gate.
	for _, v := range []string{"1", "yes", "TRUE", "on", " "} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(EnvRequireSignedPlayback, v)
			h := &Handler{hmacSecret: testPlaybackSecret}
			req := httptest.NewRequest("GET", "/watch/tok_a", nil)
			if !h.playbackAllowed(req, "tok_a") {
				t.Fatalf("%q enabled the gate; only the exact string \"true\" should", v)
			}
		})
	}
}
