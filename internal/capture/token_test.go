package capture

// The trust boundary. This token is the ONLY thing standing between an anonymous
// internet visitor and a recording session, so every case below is a way in that
// must stay shut, asserted individually so a failure names which one opened.

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

const secret = "capture-signing-secret"

var now = time.Unix(1_700_000_000, 0).UTC()

func claims(mut func(*Claims)) *Claims {
	c := &Claims{
		UserID:     "11111111-1111-4111-8111-111111111111",
		CustomerID: "cust-1",
		Email:      "rep@example.com",
		Name:       "Ada Lovelace",
		ExpiresAt:  now.Add(1 * time.Minute).Unix(),
	}
	if mut != nil {
		mut(c)
	}
	return c
}

func signed(t *testing.T, c *Claims) string {
	t.Helper()
	tok, err := Mint(secret, c)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestVerifyAcceptsAFreshToken(t *testing.T) {
	got, err := Verify(secret, signed(t, claims(nil)), now)
	if err != nil {
		t.Fatalf("a correctly signed, unexpired token was refused: %v", err)
	}
	if got.UserID != "11111111-1111-4111-8111-111111111111" || got.CustomerID != "cust-1" {
		t.Fatalf("claims did not round-trip: %+v", got)
	}
	if got.Email != "rep@example.com" || got.Name != "Ada Lovelace" {
		t.Fatalf("identity claims did not round-trip: %+v", got)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	// The window is the whole point: a token captured from a URL, a log, or a
	// referrer must stop working quickly.
	tok := signed(t, claims(func(c *Claims) { c.ExpiresAt = now.Add(-time.Second).Unix() }))
	if _, err := Verify(secret, tok, now); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestVerifyRejectsExpiryExactlyNow(t *testing.T) {
	tok := signed(t, claims(func(c *Claims) { c.ExpiresAt = now.Unix() }))
	if _, err := Verify(secret, tok, now); err == nil {
		t.Fatal("a token expiring exactly now was accepted")
	}
}

func TestVerifyRejectsAWindowBeyondTheMaximum(t *testing.T) {
	// A caller that mints a year-long token has defeated the scheme. The ceiling
	// is enforced by the VERIFIER, not just by the minter, because the minter
	// lives in another repo and could drift.
	tok := signed(t, claims(func(c *Claims) { c.ExpiresAt = now.Add(MaxLifetime + time.Minute).Unix() }))
	if _, err := Verify(secret, tok, now); err == nil {
		t.Fatalf("a token with a lifetime beyond %s was accepted", MaxLifetime)
	}
}

func TestVerifyRejectsATamperedClaim(t *testing.T) {
	// Swapping the customer id is the attack that matters: it would put a
	// recording into another tenant's account.
	tok := signed(t, claims(nil))
	body, sig, _ := strings.Cut(tok, ".")

	// Tamper the DECODED claims and re-encode, keeping the original signature.
	// String-replacing inside the base64 text would be a no-op — the plaintext
	// never appears there — and would make this test pass for the wrong reason.
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c.CustomerID = "cust-2"
	altered, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tampered := base64.RawURLEncoding.EncodeToString(altered)
	if tampered == body {
		t.Fatal("tampering produced an identical body; the test would prove nothing")
	}
	if _, err := Verify(secret, tampered+"."+sig, now); err == nil {
		t.Fatal("a token with an altered customer id was accepted")
	}
}

func TestVerifyRejectsAnotherSecret(t *testing.T) {
	tok, err := Mint("some-other-deployments-secret", claims(nil))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := Verify(secret, tok, now); err == nil {
		t.Fatal("a token signed with a different secret was accepted")
	}
}

func TestVerifyNeverAcceptsWithAnEmptySecret(t *testing.T) {
	// An unconfigured deployment must refuse everything rather than verify
	// against the empty key, which anyone can compute.
	tok, _ := Mint("", claims(nil))
	if _, err := Verify("", tok, now); err == nil {
		t.Fatal("an empty secret verified a token")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	good := signed(t, claims(nil))
	body, sig, _ := strings.Cut(good, ".")

	cases := []struct{ name, tok string }{
		{"empty", ""},
		{"no separator", body + sig},
		{"body only", body},
		{"signature only", "." + sig},
		{"empty signature", body + "."},
		{"signature not hex", body + ".zzzz"},
		{"signature truncated", body + "." + sig[:len(sig)-2]},
		{"body not base64", "!!!not-base64!!!." + sig},
		{"extra separator", body + "." + sig + ".extra"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Verify(secret, c.tok, now); err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
		})
	}
}

func TestVerifyRejectsMissingRequiredClaims(t *testing.T) {
	// A token with no user or no customer cannot be turned into a session
	// without inventing one, and inventing one is how a recording ends up
	// attributed to nobody or to the wrong tenant.
	for _, c := range []struct {
		name string
		mut  func(*Claims)
	}{
		{"no user id", func(c *Claims) { c.UserID = "" }},
		{"no customer id", func(c *Claims) { c.CustomerID = "" }},
		{"no email", func(c *Claims) { c.Email = "" }},
		{"no expiry", func(c *Claims) { c.ExpiresAt = 0 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Verify(secret, signed(t, claims(c.mut)), now); err == nil {
				t.Fatalf("a token with %s was accepted", c.name)
			}
		})
	}
}

func TestMintProducesADistinctSignaturePerClaimSet(t *testing.T) {
	// Guards against a signature computed over something constant — which would
	// verify for every token ever issued.
	a := signed(t, claims(nil))
	b := signed(t, claims(func(c *Claims) { c.UserID = "22222222-2222-4222-8222-222222222222" }))
	_, sigA, _ := strings.Cut(a, ".")
	_, sigB, _ := strings.Cut(b, ".")
	if sigA == sigB {
		t.Fatal("two different claim sets produced the same signature")
	}
}

func TestExpiryIsCoveredBySignature(t *testing.T) {
	// Editing exp upward must invalidate the token, which is why expiry needs no
	// separate integrity check.
	tok := signed(t, claims(nil))
	body, sig, _ := strings.Cut(tok, ".")
	stretched := strings.Replace(
		body,
		strconv.FormatInt(now.Add(1*time.Minute).Unix(), 10),
		strconv.FormatInt(now.Add(2*time.Minute).Unix(), 10),
		1,
	)
	if stretched != body {
		if _, err := Verify(secret, stretched+"."+sig, now); err == nil {
			t.Fatal("extending exp did not invalidate the signature")
		}
	}
}
