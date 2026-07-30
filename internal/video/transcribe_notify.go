package video

// The transcription-complete notification — a MajorGTM fork addition.
//
// Upstream finishes a transcription by writing `transcript_status` and returning.
// Nothing is pushed anywhere, so an application embedding this recorder has only
// two options: poll every video it is waiting on, or never find out. This closes
// that by emitting one signed delivery per terminal transcription outcome.
//
// THE PAYLOAD IS FLAT, and that is a contract, not a style choice. The consumer
// reads `videoId`, `shareToken` and `segments` at the top level of the body; the
// webhook.Event envelope used by the per-user feature nests them under "data",
// which would verify, return 200, and deliver nothing usable. See
// internal/webhook/instance.go for why this does not route through Dispatch.
//
// FAILURE IS NON-FATAL, BY DESIGN. The transcript is already committed before any
// of this runs, so a failed delivery costs the consumer latency (it falls back to
// polling) rather than data. Nothing here returns an error to the worker: an
// unreachable webhook must never mark a completed transcription as failed.

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/sendrec/sendrec/internal/database"
	"github.com/sendrec/sendrec/internal/webhook"
)

// The event name the consumer switches on. One event, not a family: the
// consumer's endpoint acknowledges anything else without acting on it, so
// inventing new names here silently does nothing.
const transcriptionCompleteEvent = "transcription.complete"

// transcriptionCompletePayload is the wire shape. Field names and nesting are
// fixed by the consumer and pinned by transcribe_notify_test.go.
type transcriptionCompletePayload struct {
	Event      string              `json:"event"`
	VideoID    string              `json:"videoId"`
	ShareToken string              `json:"shareToken"`
	Status     string              `json:"status"`
	Segments   []TranscriptSegment `json:"segments"`
	Timestamp  time.Time           `json:"timestamp"`
}

// buildTranscriptionCompleteBody marshals the delivery body.
//
// Split from the sending so the shape can be asserted without a server: this is
// the piece that silently breaks the integration if it drifts.
//
// `segments` is normalised to a non-nil slice so the JSON carries `[]` rather
// than `null` for a no-audio recording. The consumer treats an empty list as "we
// transcribed it and there was nothing said" and parks the update accordingly; a
// `null` would be indistinguishable from a field the fork forgot to send.
func buildTranscriptionCompleteBody(
	videoID, shareToken, status string,
	segments []TranscriptSegment,
	now time.Time,
) ([]byte, error) {
	if segments == nil {
		segments = []TranscriptSegment{}
	}
	return json.Marshal(transcriptionCompletePayload{
		Event:      transcriptionCompleteEvent,
		VideoID:    videoID,
		ShareToken: shareToken,
		Status:     status,
		Segments:   segments,
		Timestamp:  now.UTC(),
	})
}

// notifyTranscriptionComplete delivers one terminal transcription outcome.
//
// Called for EVERY terminal state, not only success. A no-audio recording is a
// finished recording: the consumer is waiting on it either way, and staying
// silent means it waits out a timeout before concluding the same thing this call
// could have told it immediately.
//
// A separate context is used rather than the worker's: the worker's may already
// be cancelled during shutdown, and a completed transcription still deserves its
// delivery attempt.
// The client is built here from `db` rather than threaded through the worker: it
// is cheap, it is used once per completed transcription (minutes apart), and
// widening processTranscription's signature would churn every existing caller and
// test for a dependency only this path has.
func notifyTranscriptionComplete(
	db database.DBTX,
	videoID, shareToken, status string,
	segments []TranscriptSegment,
) {
	target, ok := webhook.LookupInstanceTarget()
	if !ok {
		return // not configured — the ordinary self-hosted case
	}

	body, err := buildTranscriptionCompleteBody(videoID, shareToken, status, segments, time.Now())
	if err != nil {
		slog.Error("transcribe-notify: failed to marshal payload", "video_id", videoID, "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := webhook.New(db).PostSigned(ctx, target, body); err != nil {
		// Logged, never propagated: the transcript is already stored, and the
		// consumer's poll backstop exists for exactly this.
		slog.Error("transcribe-notify: delivery failed",
			"video_id", videoID, "status", status, "segments", len(segments), "error", err)
		return
	}
	slog.Info("transcribe-notify: delivered",
		"video_id", videoID, "status", status, "segments", len(segments))
}
