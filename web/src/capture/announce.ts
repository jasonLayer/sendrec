// ANNOUNCING A FINISHED RECORDING TO THE EMBEDDING APPLICATION — a MajorGTM
// fork addition.
//
// Upstream's recorder finishes by showing a share link. That is the whole
// interaction, and it is the right one for a person using the recorder directly.
//
// Embedded, it is a dead end: the application around the frame is waiting to
// turn that recording into an update, and it has no way to learn the recording
// happened. It cannot read the frame (cross-origin), it cannot poll for "the
// recording that person just made" (there is no such query), and the transcript
// webhook arrives minutes later keyed by a video id nobody told it about. So the
// frame says so, once, when the upload is committed.
//
// THE TARGET ORIGIN IS NOT OURS TO CHOOSE. A share token is a capability, and
// postMessage's targetOrigin is the only thing standing between it and whoever
// is framing us — `'*'` would defeat the mechanism entirely. The frame cannot
// work out its parent for itself either: Referrer-Policy is no-referrer, so
// document.referrer is empty, and ancestorOrigins does not exist in Firefox.
//
// So the server decides. /capture validates the origin the parent claims against
// the same allowlist CSP frame-ancestors is built from and passes the survivor
// here in the landing URL. An origin that could not have framed us never reaches
// this file. See internal/capture/parent.go.

/** The message type the embedding application listens for. */
export const COMPLETE_MESSAGE_TYPE = "sendrec:complete";

// The upload bridge's vocabulary (MajorGTM's in-panel audio update). The parent
// records with its own UI and posts the finished blob here; this frame owns the
// session and does the upload, then announces completion exactly as the
// recorder page does. See Bridge.tsx.
export const UPLOAD_MESSAGE_TYPE = "sendrec:upload";
export const PROGRESS_MESSAGE_TYPE = "sendrec:progress";
export const ERROR_MESSAGE_TYPE = "sendrec:error";
export const BRIDGE_READY_MESSAGE_TYPE = "sendrec:bridge-ready";

/** Set on the landing URL by /capture, already validated. */
export const PARENT_QUERY_PARAM = "capture_parent";
export const ORG_QUERY_PARAM = "capture_org";
export const CAPTURE_SESSION_QUERY_PARAM = "capture_session";

export const MODE_QUERY_PARAM = "capture_mode";
export const MODE_BRIDGE = "bridge";

export const PARENT_STORAGE_KEY = "sendrec:capture-parent";
export const MODE_STORAGE_KEY = "sendrec:capture-mode";
export const ORG_STORAGE_KEY = "sendrec:capture-org";
export const CAPTURE_SESSION_STORAGE_KEY = "sendrec:capture-session";

export interface CompletedRecording {
  videoId: string;
  shareToken: string;
}

/** Report the live recorder light without sharing any recording content. */
export function announceRecordingState(active: boolean): void {
  if (window.parent === window) return;
  const parentOrigin = captureParentOrigin();
  if (!parentOrigin) return;
  try {
    window.parent.postMessage({ type: "sendrec:recording-state", active }, parentOrigin);
  } catch {
    // A missing parent must never interrupt capture.
  }
}

/**
 * The origin entitled to hear about recordings made in this session, or "".
 *
 * Read lazily rather than at module load, and remembered in sessionStorage,
 * because the query parameter exists only on the landing URL: the moment the
 * person navigates within the app or the frame reloads, the URL no longer
 * carries it — and an announcement that never fires is a parent that waits
 * forever on a recording that succeeded.
 */
export function captureParentOrigin(): string {
  const fromUrl = new URLSearchParams(window.location.search).get(PARENT_QUERY_PARAM);
  if (fromUrl) {
    // Storage is denied outright in some privacy modes. Losing the memory is
    // survivable; throwing on the recorder's landing page is not.
    try {
      sessionStorage.setItem(PARENT_STORAGE_KEY, fromUrl);
    } catch {
      // ignored deliberately — the value is still returned below
    }
    return fromUrl;
  }

  try {
    return sessionStorage.getItem(PARENT_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function captureOrgId(): string {
  const fromUrl = new URLSearchParams(window.location.search).get(ORG_QUERY_PARAM);
  if (fromUrl) {
    try {
      sessionStorage.setItem(ORG_STORAGE_KEY, fromUrl);
    } catch {
      // ignored deliberately — the value is still returned below
    }
    return fromUrl;
  }

  try {
    return sessionStorage.getItem(ORG_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

/**
 * The capture surface the server said the parent asked for, or "". Read the
 * same way as the parent origin: from the landing URL first, then from what was
 * remembered, because the SPA re-renders the root route without the query.
 */
export function captureMode(search = window.location.search): string {
  const fromUrl = new URLSearchParams(search).get(MODE_QUERY_PARAM);
  if (fromUrl) {
    try {
      sessionStorage.setItem(MODE_STORAGE_KEY, fromUrl);
    } catch {
      // ignored deliberately — the value is still returned below
    }
    return fromUrl;
  }

  try {
    return sessionStorage.getItem(MODE_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

/**
 * Post any bridge message to the validated parent. Silent when there is nobody
 * to tell, for the same reasons announceRecordingComplete is.
 */
export function postToParent(message: Record<string, unknown>): void {
  if (window.parent === window) return;
  const parentOrigin = captureParentOrigin();
  if (!parentOrigin) return;
  try {
    window.parent.postMessage(message, parentOrigin);
  } catch {
    // ignored deliberately
  }
}

export function captureSessionActive(search = window.location.search): boolean {
  const fromUrl = new URLSearchParams(search).get(CAPTURE_SESSION_QUERY_PARAM);
  if (fromUrl === "1") {
    try {
      sessionStorage.setItem(CAPTURE_SESSION_STORAGE_KEY, "1");
    } catch {
      // ignored deliberately — the value is still returned below
    }
    return true;
  }

  try {
    return sessionStorage.getItem(CAPTURE_SESSION_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * Tell the embedding application that a recording is committed and shareable.
 *
 * Silent, and deliberately so, in every case where there is nobody to tell: not
 * embedded, no validated parent, or a recording with no share token. Those are
 * the ordinary states of someone using the recorder directly, not errors.
 *
 * Never throws. By the time this runs the recording is already uploaded and
 * marked ready; a parent frame that has navigated away must not turn saved work
 * into a failed upload.
 */
export function announceRecordingComplete(recording: CompletedRecording): void {
  if (window.parent === window) {
    return;
  }
  if (!recording.shareToken) {
    return;
  }
  const parentOrigin = captureParentOrigin();
  if (!parentOrigin) {
    return;
  }

  try {
    window.parent.postMessage(
      {
        type: COMPLETE_MESSAGE_TYPE,
        videoId: recording.videoId,
        shareToken: recording.shareToken,
      },
      parentOrigin
    );
  } catch {
    // ignored deliberately — see above
  }
}
