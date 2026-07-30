package webhook

// INSTANCE-LEVEL WEBHOOKS — a MajorGTM fork addition.
//
// Upstream's webhook feature is PER USER: Dispatch() takes a URL and secret that
// LookupConfig resolves from the signed-in user's row, and every delivery is
// logged against that user id. That is the right model for "let a customer wire
// their own automation to their own videos".
//
// It is the wrong model for a sidecar. This deployment is a single-tenant
// recorder owned by one application, and that application needs EVERY
// transcription — regardless of which user's session produced the recording, and
// including recordings whose user never configured anything. Making the
// integration depend on per-user setup would mean a recorder that works and a
// pipeline that silently receives nothing.
//
// So the destination comes from the environment instead, and is the same for the
// whole instance. Everything cryptographic is reused from webhook.go: the MAC is
// SignPayload, the header is X-Webhook-Signature, and the body is signed as the
// exact bytes that go on the wire.
//
// WHY NOT REUSE Dispatch(): its Event envelope nests the payload under "data"
// (`{"event":…,"timestamp":…,"data":{…}}`). The consumer reads its fields at the
// TOP level, so routing through Dispatch would produce a delivery that verifies
// correctly, returns 200, and drops every transcript — the failure would look
// like the pipeline simply never firing. The shape below is flat on purpose and
// is pinned by the consumer's own tests.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Env vars naming the instance-level destination. Both must be set; one alone is
// treated as unconfigured, because a URL with no secret would send unsigned
// recordings to an endpoint that must reject them anyway.
const (
	EnvInstanceWebhookURL    = "WEBHOOK_TRANSCRIPTION_URL"
	EnvInstanceWebhookSecret = "WEBHOOK_TRANSCRIPTION_SECRET"
)

// InstanceTarget is the configured instance-level destination.
type InstanceTarget struct {
	URL    string
	Secret string
}

// LookupInstanceTarget reads the instance-level destination from the
// environment. `ok` is false when the integration is not configured, which is
// the ordinary state for a stock self-hosted deployment — callers no-op rather
// than erroring.
func LookupInstanceTarget() (InstanceTarget, bool) {
	url := strings.TrimSpace(os.Getenv(EnvInstanceWebhookURL))
	secret := strings.TrimSpace(os.Getenv(EnvInstanceWebhookSecret))
	if url == "" || secret == "" {
		return InstanceTarget{}, false
	}
	return InstanceTarget{URL: url, Secret: secret}, true
}

// PostSigned delivers a caller-built body to the instance target, signed the
// same way every other webhook in this codebase is.
//
// The body is passed in already marshalled and is written to the wire verbatim.
// That is load-bearing: the MAC covers these exact bytes, and re-marshalling
// anywhere between signing and sending would change key order or whitespace and
// invalidate a signature the receiver computes over what it actually got.
//
// Retries mirror Dispatch's schedule. Delivery is NOT logged to
// webhook_deliveries: that table is keyed by user id and these deliveries have
// no user. Failures are logged and swallowed — the caller's work has already
// been committed, and the consumer is expected to have a poll backstop for the
// deliveries that never arrive.
func (c *Client) PostSigned(ctx context.Context, target InstanceTarget, body []byte) error {
	signature := SignPayload(target.Secret, body)
	delays := append([]time.Duration{0}, c.retryDelays...)

	var lastErr error
	for attempt, delay := range delays {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(body))
		if err != nil {
			// A malformed URL will not fix itself on a retry.
			return fmt.Errorf("build instance webhook request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Webhook-Signature", signature)

		res, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			slog.Warn("instance-webhook: delivery failed",
				"attempt", attempt+1, "of", len(delays), "error", err)
			continue
		}
		status := res.StatusCode
		_ = res.Body.Close()

		if status >= 200 && status < 300 {
			return nil
		}
		lastErr = fmt.Errorf("instance webhook returned %d", status)
		// 4xx other than 429 is a contract problem — a bad secret, a rejected
		// shape — and retrying an unchanged body cannot resolve it.
		if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
			slog.Error("instance-webhook: rejected, not retrying", "status", status)
			return lastErr
		}
		slog.Warn("instance-webhook: delivery returned a retryable status",
			"attempt", attempt+1, "of", len(delays), "status", status)
	}
	return lastErr
}
