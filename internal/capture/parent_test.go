package capture

import (
	"slices"
	"testing"
)

func TestParseAllowedParents(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty", "", nil},
		{"one", "https://app.majorgtm.com", []string{"https://app.majorgtm.com"}},
		{
			"the live value",
			"https://majorgtm.vercel.app https://app.majorgtm.com",
			[]string{"https://majorgtm.vercel.app", "https://app.majorgtm.com"},
		},
		{"ragged whitespace", "  https://a.example   https://b.example \t", []string{"https://a.example", "https://b.example"}},
		// 'self' is this deployment. It is never the cross-origin parent, and
		// naming it as a postMessage recipient would be meaningless.
		{"csp keywords dropped", "'self' https://app.majorgtm.com", []string{"https://app.majorgtm.com"}},
		{"'none' dropped", "'none'", nil},
		// A wildcard is a legitimate CSP source and an illegitimate targetOrigin.
		{"wildcards dropped", "* https://app.majorgtm.com", []string{"https://app.majorgtm.com"}},
		{"subdomain wildcard dropped", "https://*.majorgtm.com", nil},
		{"trailing slash normalised", "https://app.majorgtm.com/", []string{"https://app.majorgtm.com"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseAllowedParents(tc.input)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveParent(t *testing.T) {
	allowed := ParseAllowedParents("'self' https://majorgtm.vercel.app https://app.majorgtm.com")

	cases := []struct {
		name    string
		claimed string
		want    string
	}{
		{"allowed", "https://app.majorgtm.com", "https://app.majorgtm.com"},
		{"the other allowed one", "https://majorgtm.vercel.app", "https://majorgtm.vercel.app"},
		{"trailing slash", "https://app.majorgtm.com/", "https://app.majorgtm.com"},
		{"absent", "", ""},
		{"unknown", "https://evil.example", ""},
		// Every one of these passes a sloppy prefix, suffix or substring test.
		{"suffix impostor", "https://evil.com/https://app.majorgtm.com", ""},
		{"prefix impostor", "https://app.majorgtm.com.evil.example", ""},
		{"scheme downgrade", "http://app.majorgtm.com", ""},
		{"port added", "https://app.majorgtm.com:8443", ""},
		{"substring", "app.majorgtm.com", ""},
		// 'self' survives nothing: it was dropped from the allowlist, so a
		// caller literally claiming it must not match.
		{"claiming a csp keyword", "'self'", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveParent(allowed, tc.claimed); got != tc.want {
				t.Errorf("resolveParent(%q) = %q, want %q", tc.claimed, got, tc.want)
			}
		})
	}
}

func TestResolveParent_NothingAllowed(t *testing.T) {
	if got := resolveParent(nil, "https://app.majorgtm.com"); got != "" {
		t.Errorf("with no allowlist nothing may resolve, got %q", got)
	}
}
