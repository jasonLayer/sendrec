package capture

// THE PARENT ORIGIN, AND WHY THE SERVER DECIDES IT.
//
// When a recording finishes, the embedded recorder has to tell the application
// that embedded it — and a postMessage needs an explicit targetOrigin. `'*'`
// would hand the share token to whoever happens to be framing us, which is the
// one thing a targetOrigin exists to prevent.
//
// The frame cannot work the origin out for itself. `Referrer-Policy:
// no-referrer` is set on every response, so document.referrer is empty;
// `ancestorOrigins` does not exist in Firefox; and a `postMessage` from the
// parent saying "I am X" is a claim from the party we are trying to
// authenticate.
//
// So the parent declares its origin in the capture URL and THIS package decides
// whether to believe it, against the same allowlist that CSP `frame-ancestors`
// is built from. One env var, one source of truth: an origin that could not have
// framed us cannot be named as the recipient either. An unrecognised or absent
// claim is not an error — the hand-off proceeds and the recorder simply
// announces nothing, which is the correct behaviour for someone who opened the
// recorder directly rather than through the parent.

import "strings"

// ParseAllowedParents splits an ALLOWED_FRAME_ANCESTORS value into origins.
//
// The value is a CSP source list, so it is whitespace-separated and may carry
// keywords like 'self'. Keywords are dropped rather than resolved: 'self' means
// this deployment, which is never the parent in a cross-origin embed, and
// wildcards have no business naming a postMessage recipient.
func ParseAllowedParents(allowedFrameAncestors string) []string {
	var parents []string
	for _, field := range strings.Fields(allowedFrameAncestors) {
		if strings.HasPrefix(field, "'") || strings.Contains(field, "*") {
			continue
		}
		parents = append(parents, strings.TrimSuffix(field, "/"))
	}
	return parents
}

// resolveParent returns the claimed origin if it is one we allow to frame us,
// and "" otherwise.
//
// Matching is exact. An origin is scheme + host + port and nothing else, so a
// prefix or suffix comparison here would accept `https://app.majorgtm.com.evil`
// or `https://evil/https://app.majorgtm.com`.
func resolveParent(allowed []string, claimed string) string {
	if claimed == "" {
		return ""
	}
	claimed = strings.TrimSuffix(claimed, "/")
	for _, origin := range allowed {
		if origin == claimed {
			return claimed
		}
	}
	return ""
}
