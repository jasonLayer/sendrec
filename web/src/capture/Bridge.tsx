// THE UPLOAD BRIDGE — a MajorGTM fork addition.
//
// MajorGTM's Implementations screen records an audio update with its OWN
// controls, in its own panel, because a recorder page designed for people using
// this app directly reads as a second application when it is framed. What the
// parent cannot do for itself is store the recording: /api/videos accepts this
// app's session and nothing else, and only a frame on this origin holds one
// (see internal/capture/handler.go). So the parent posts the finished blob here,
// and this frame does exactly what pages/Record.tsx does after a recording
// stops: create, upload, mark ready, announce.
//
// THIS FRAME IS NEVER SEEN. It renders one status line the parent may show or
// hide; every state that matters is reported back over postMessage. The parent
// origin is the one the server validated on the landing URL — a message from
// anywhere else is ignored, and every reply names that origin as its target.
//
// The recording is a WebM container carrying only an audio track, declared as
// video/webm: that is what /api/videos accepts, ffmpeg's audio extraction reads
// it regardless, and the transcript webhook fires the same way it does for a
// screen recording.

import { useEffect, useState } from "react";
import { apiFetch } from "../api/client";
import {
  announceRecordingComplete,
  BRIDGE_READY_MESSAGE_TYPE,
  captureParentOrigin,
  ERROR_MESSAGE_TYPE,
  postToParent,
  PROGRESS_MESSAGE_TYPE,
  UPLOAD_MESSAGE_TYPE,
} from "./announce";

interface CreateVideoResponse {
  id: string;
  uploadUrl: string;
  shareToken: string;
}

/** What the parent posts. Every field is untrusted and checked. */
interface UploadRequest {
  type: typeof UPLOAD_MESSAGE_TYPE;
  blob: Blob;
  /** Whole seconds, as the parent's timer counted them. */
  duration: number;
  title?: string;
}

const MAX_TITLE_CHARS = 200;

function isUploadRequest(data: unknown): data is UploadRequest {
  if (!data || typeof data !== "object") return false;
  const d = data as Record<string, unknown>;
  return d.type === UPLOAD_MESSAGE_TYPE &&
    d.blob instanceof Blob && d.blob.size > 0 &&
    typeof d.duration === "number" && Number.isFinite(d.duration) && d.duration >= 1;
}

function uploadWithProgress(
  url: string,
  blob: Blob,
  contentType: string,
  onProgress: (pct: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url);
    xhr.setRequestHeader("Content-Type", contentType);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error("Upload failed"));
    };
    xhr.onerror = () => reject(new Error("Upload failed"));
    xhr.send(blob);
  });
}

/**
 * Create → upload → ready → announce, the sequence Record.tsx runs. A failure
 * after the row exists deletes it, so a half-uploaded recording never sits in
 * the library as a broken video.
 */
export async function uploadForParent(request: UploadRequest): Promise<void> {
  let videoId: string | null = null;
  try {
    const title = (request.title ?? "").trim().slice(0, MAX_TITLE_CHARS) ||
      `Update ${new Date().toLocaleDateString("en-GB")}`;
    const contentType = "video/webm";
    const result = await apiFetch<CreateVideoResponse>("/api/videos", {
      method: "POST",
      body: JSON.stringify({
        title,
        duration: Math.max(1, Math.round(request.duration)),
        fileSize: request.blob.size,
        contentType,
      }),
    });
    if (!result) throw new Error("Failed to create video");
    videoId = result.id;

    await uploadWithProgress(result.uploadUrl, request.blob, contentType, (pct) =>
      postToParent({ type: PROGRESS_MESSAGE_TYPE, percent: pct }),
    );

    await apiFetch(`/api/videos/${result.id}`, {
      method: "PATCH",
      body: JSON.stringify({ status: "ready" }),
    });

    announceRecordingComplete({ videoId: result.id, shareToken: result.shareToken });
  } catch (err) {
    if (videoId) {
      apiFetch(`/api/videos/${videoId}`, { method: "DELETE" }).catch(() => {});
    }
    postToParent({
      type: ERROR_MESSAGE_TYPE,
      message: err instanceof Error ? err.message : "Upload failed",
    });
    throw err;
  }
}

export function Bridge() {
  const [status, setStatus] = useState("Ready");

  useEffect(() => {
    const parentOrigin = captureParentOrigin();
    let busy = false;

    async function onMessage(event: MessageEvent) {
      // Origin first — a message from anywhere else is not evidence of anything.
      if (!parentOrigin || event.origin !== parentOrigin) return;
      if (!isUploadRequest(event.data)) return;
      // One upload at a time: a second request while one is in flight is a
      // double-click, not a second recording.
      if (busy) return;
      busy = true;
      setStatus("Uploading…");
      try {
        await uploadForParent(event.data);
        setStatus("Saved");
      } catch {
        setStatus("Upload failed");
      } finally {
        busy = false;
      }
    }

    window.addEventListener("message", onMessage);
    // Tell the parent the session is established and the listener is armed, so
    // it never posts a blob into a frame that is still redeeming its token.
    postToParent({ type: BRIDGE_READY_MESSAGE_TYPE });
    return () => window.removeEventListener("message", onMessage);
  }, []);

  return (
    <p className="max-duration-label" data-testid="bridge-status" aria-live="polite">
      {status}
    </p>
  );
}
