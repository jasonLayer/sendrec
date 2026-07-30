package capture

// CROSS-REPO CONTRACT TEST.
//
// The minter lives in another repository (MajorGTM, at
// supabase/functions/_shared/updates/capture_token.ts) and is written in a
// different language against a different crypto library. Two implementations
// that each pass their own tests prove nothing about whether they agree — and
// when they disagree the production symptom is a login screen inside an iframe,
// with a 401 nobody sees and no error in either log that names the cause.
//
// So the agreement itself is the thing under test. The token below was produced
// by that TypeScript minter and is pinned there too, byte for byte, in
// capture_token_test.ts. Either both files change together or one of them goes
// red.

import (
	"testing"
	"time"
)

const (
	// Identical to SECRET in capture_token_test.ts.
	interopSecret = "capture_test_secret"

	// Produced by mintCaptureToken() in that repo, pasted verbatim.
	interopToken = "eyJ1aWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJjaWQiOiJjdXN0b21lci1hYmMiLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwibmFtZSI6IkFsaWNlIEV4YW1wbGUiLCJleHAiOjE3ODU0MTI4OTB9.f22d76eb7f1a64e9f18ca41e0189d5fe0305be9339a088f8cf1e4c371c352b82"

	// The `exp` inside that token: 2026-07-30T12:01:30Z.
	interopExpiry = 1785412890
)

// interopNow is a moment inside the token's window. Injected rather than taken
// from the clock, so this test does not start failing in 2027.
func interopNow() time.Time {
	return time.Unix(interopExpiry-30, 0).UTC()
}

func TestVerify_AcceptsATokenMintedByTheParentApplication(t *testing.T) {
	claims, err := Verify(interopSecret, interopToken, interopNow())
	if err != nil {
		t.Fatalf("the parent's token was refused — the two implementations have drifted: %v", err)
	}

	if claims.UserID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("uid = %q", claims.UserID)
	}
	if claims.CustomerID != "customer-abc" {
		t.Errorf("cid = %q", claims.CustomerID)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email = %q", claims.Email)
	}
	if claims.Name != "Alice Example" {
		t.Errorf("name = %q", claims.Name)
	}
	if claims.ExpiresAt != interopExpiry {
		t.Errorf("exp = %d", claims.ExpiresAt)
	}
}

// The minter's TTL is 90 seconds against this package's 120-second ceiling. That
// margin is what absorbs clock skew between Supabase's Edge runtime and this
// service, so it is worth asserting rather than assuming: a minter that drifted
// past the ceiling would refuse every capture, not merely a skewed one.
func TestVerify_TheParentsLifetimeFitsInsideTheCeiling(t *testing.T) {
	issued := time.Unix(interopExpiry-90, 0).UTC()

	if _, err := Verify(interopSecret, interopToken, issued); err != nil {
		t.Fatalf("a freshly minted token was refused at the moment of issue: %v", err)
	}

	// And it really does expire — the window is short, not absent.
	if _, err := Verify(interopSecret, interopToken, time.Unix(interopExpiry, 0).UTC()); err == nil {
		t.Error("expected the token to be expired at its own exp")
	}
}

// Our secret is the only thing that makes that token ours.
func TestVerify_RefusesTheParentsTokenUnderAnotherSecret(t *testing.T) {
	if _, err := Verify("a-different-secret", interopToken, interopNow()); err == nil {
		t.Error("expected a signature failure under a different secret")
	}
}
