package video

// These tests pin the WIRE SHAPE, because that is the part of this integration
// that fails silently. A wrong signature gets a 403 an operator can find; a
// correctly-signed body with the payload one level too deep gets a 200 and
// delivers nothing, and the only symptom is transcripts that never arrive.
//
// So the assertions below are deliberately about JSON keys and nesting rather
// than about Go structs: the consumer reads keys, and a struct rename that keeps
// the same tags must not fail while a tag change must.

import (
	"encoding/json"
	"testing"
	"time"
)

func decodeBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("payload is not a JSON object: %v", err)
	}
	return out
}

func TestTranscriptionCompleteBodyIsFlat(t *testing.T) {
	// THE regression this file exists for. Routing through webhook.Event would
	// nest these under "data"; the consumer reads them at the top level.
	body, err := buildTranscriptionCompleteBody(
		"vid_1", "tok_1", "ready",
		[]TranscriptSegment{{Start: 0, End: 1.5, Text: "we closed Acme", Speaker: "Jason"}},
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := decodeBody(t, body)

	if _, nested := got["data"]; nested {
		t.Fatal("payload carries a \"data\" envelope — the consumer reads top-level keys")
	}
	for _, key := range []string{"event", "videoId", "shareToken", "status", "segments", "timestamp"} {
		if _, ok := got[key]; !ok {
			t.Errorf("payload is missing top-level %q", key)
		}
	}
	if got["event"] != "transcription.complete" {
		t.Errorf("event = %v, want transcription.complete (the only name the consumer acts on)", got["event"])
	}
	if got["videoId"] != "vid_1" || got["shareToken"] != "tok_1" {
		t.Errorf("identity fields wrong: videoId=%v shareToken=%v", got["videoId"], got["shareToken"])
	}
}

func TestTranscriptionCompleteSegmentKeys(t *testing.T) {
	// The consumer reads `text` and `speaker` off each segment. `start`/`end` are
	// sent because they are free and a future consumer may want them.
	body, err := buildTranscriptionCompleteBody(
		"vid_1", "tok_1", "ready",
		[]TranscriptSegment{{Start: 2, End: 4, Text: "hello", Speaker: "Ada"}},
		time.Unix(0, 0),
	)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	segs, ok := decodeBody(t, body)["segments"].([]any)
	if !ok || len(segs) != 1 {
		t.Fatalf("segments did not decode as a 1-element array: %#v", decodeBody(t, body)["segments"])
	}
	seg, ok := segs[0].(map[string]any)
	if !ok {
		t.Fatalf("segment is not an object: %#v", segs[0])
	}
	if seg["text"] != "hello" {
		t.Errorf("segment text = %v, want hello", seg["text"])
	}
	if seg["speaker"] != "Ada" {
		t.Errorf("segment speaker = %v, want Ada", seg["speaker"])
	}
}

func TestTranscriptionCompleteNoAudioSendsEmptyArrayNotNull(t *testing.T) {
	// The consumer distinguishes "transcribed, nothing said" from "the fork forgot
	// the field". A nil slice marshals to `null` and would read as the latter.
	body, err := buildTranscriptionCompleteBody("vid_1", "tok_1", "no_audio", nil, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	segs, ok := decodeBody(t, body)["segments"].([]any)
	if !ok {
		t.Fatalf("segments is not an array for a no-audio delivery: %s", body)
	}
	if len(segs) != 0 {
		t.Errorf("expected an empty segment array, got %d", len(segs))
	}
	if decodeBody(t, body)["status"] != "no_audio" {
		t.Errorf("status = %v, want no_audio", decodeBody(t, body)["status"])
	}
}

func TestTranscriptionCompleteTimestampIsRFC3339UTC(t *testing.T) {
	body, err := buildTranscriptionCompleteBody(
		"vid_1", "tok_1", "ready", []TranscriptSegment{}, time.Unix(1_700_000_000, 0),
	)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ts, ok := decodeBody(t, body)["timestamp"].(string)
	if !ok {
		t.Fatalf("timestamp is not a string: %s", body)
	}
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", ts, err)
	}
	if parsed.Location() != time.UTC && parsed.UTC() != parsed {
		t.Errorf("timestamp %q is not UTC", ts)
	}
}
