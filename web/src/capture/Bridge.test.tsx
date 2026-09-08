import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
import { Bridge } from "./Bridge";
import {
  BRIDGE_READY_MESSAGE_TYPE,
  COMPLETE_MESSAGE_TYPE,
  ERROR_MESSAGE_TYPE,
  PARENT_QUERY_PARAM,
  PROGRESS_MESSAGE_TYPE,
  UPLOAD_MESSAGE_TYPE,
} from "./announce";

const mockApiFetch = vi.fn();

vi.mock("../api/client", () => ({
  apiFetch: (...args: unknown[]) => mockApiFetch(...args),
}));

const PARENT = "https://app.majorgtm.com";

class MockXHR {
  open = vi.fn();
  setRequestHeader = vi.fn();
  status = 200;
  send = vi.fn().mockImplementation(function (this: MockXHR) {
    if (this.upload?.onprogress) {
      this.upload.onprogress({ lengthComputable: true, loaded: 50, total: 100 } as ProgressEvent);
    }
    if (this.onload) this.onload();
  });
  upload: { onprogress: ((e: ProgressEvent) => void) | null } = { onprogress: null };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
}

function embed(): { postMessage: ReturnType<typeof vi.fn> } {
  const parent = { postMessage: vi.fn() };
  Object.defineProperty(window, "parent", { value: parent, configurable: true });
  return parent;
}

function landOn(search: string): void {
  window.history.replaceState({}, "", `/${search}`);
}

function deliver(origin: string, data: unknown): void {
  act(() => {
    window.dispatchEvent(new MessageEvent("message", { origin, data }));
  });
}

function blob(): Blob {
  return new Blob([new Uint8Array(2048)], { type: "audio/webm" });
}

function messagesOf(parent: { postMessage: ReturnType<typeof vi.fn> }, type: string) {
  return parent.postMessage.mock.calls.filter((c) => (c[0] as { type: string }).type === type);
}

describe("Bridge", () => {
  let originalXHR: typeof XMLHttpRequest;

  beforeEach(() => {
    mockApiFetch.mockReset();
    sessionStorage.clear();
    originalXHR = globalThis.XMLHttpRequest;
    globalThis.XMLHttpRequest = MockXHR as unknown as typeof XMLHttpRequest;
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}&capture_session=1&capture_mode=bridge`);
  });

  afterEach(() => {
    globalThis.XMLHttpRequest = originalXHR;
    Object.defineProperty(window, "parent", { value: window, configurable: true });
    vi.restoreAllMocks();
  });

  it("tells the validated parent it is ready as soon as it mounts", () => {
    const parent = embed();
    render(<Bridge />);
    expect(messagesOf(parent, BRIDGE_READY_MESSAGE_TYPE)).toHaveLength(1);
    expect(parent.postMessage.mock.calls[0][1]).toBe(PARENT);
  });

  it("creates, uploads, marks ready, and announces completion to the parent", async () => {
    const parent = embed();
    mockApiFetch
      .mockResolvedValueOnce({ id: "vid_1", uploadUrl: "https://r2.example/put", shareToken: "tok_1" })
      .mockResolvedValueOnce({});
    render(<Bridge />);

    deliver(PARENT, { type: UPLOAD_MESSAGE_TYPE, blob: blob(), duration: 42, title: "Sifly Homes Inc - Update 9.4.26" });

    await waitFor(() => expect(messagesOf(parent, COMPLETE_MESSAGE_TYPE)).toHaveLength(1));
    const create = mockApiFetch.mock.calls[0];
    expect(create[0]).toBe("/api/videos");
    expect(JSON.parse((create[1] as RequestInit).body as string)).toEqual({
      title: "Sifly Homes Inc - Update 9.4.26", duration: 42, fileSize: 2048, contentType: "video/webm",
    });
    expect(mockApiFetch.mock.calls[1][0]).toBe("/api/videos/vid_1");
    expect(messagesOf(parent, PROGRESS_MESSAGE_TYPE)[0][0]).toEqual({ type: PROGRESS_MESSAGE_TYPE, percent: 50 });
    expect(messagesOf(parent, COMPLETE_MESSAGE_TYPE)[0][0]).toEqual({
      type: COMPLETE_MESSAGE_TYPE, videoId: "vid_1", shareToken: "tok_1",
    });
    // Every reply names the parent, never '*'.
    for (const call of parent.postMessage.mock.calls) expect(call[1]).toBe(PARENT);
    expect(screen.getByTestId("bridge-status")).toHaveTextContent("Saved");
  });

  it("ignores a blob from any origin but the validated parent", async () => {
    const parent = embed();
    render(<Bridge />);
    deliver("https://evil.example", { type: UPLOAD_MESSAGE_TYPE, blob: blob(), duration: 5 });
    await new Promise((r) => setTimeout(r, 0));
    expect(mockApiFetch).not.toHaveBeenCalled();
    expect(messagesOf(parent, COMPLETE_MESSAGE_TYPE)).toHaveLength(0);
  });

  it("ignores a malformed request — no blob, or no duration", async () => {
    embed();
    render(<Bridge />);
    deliver(PARENT, { type: UPLOAD_MESSAGE_TYPE, duration: 5 });
    deliver(PARENT, { type: UPLOAD_MESSAGE_TYPE, blob: blob() });
    deliver(PARENT, { type: UPLOAD_MESSAGE_TYPE, blob: new Blob([]), duration: 5 });
    await new Promise((r) => setTimeout(r, 0));
    expect(mockApiFetch).not.toHaveBeenCalled();
  });

  it("deletes the half-made video and reports the failure when the upload breaks", async () => {
    const parent = embed();
    class FailingXHR extends MockXHR {
      send = vi.fn().mockImplementation(function (this: MockXHR) {
        if (this.onerror) this.onerror();
      });
    }
    globalThis.XMLHttpRequest = FailingXHR as unknown as typeof XMLHttpRequest;
    mockApiFetch
      .mockResolvedValueOnce({ id: "vid_2", uploadUrl: "https://r2.example/put", shareToken: "tok_2" })
      .mockResolvedValueOnce({});
    render(<Bridge />);

    deliver(PARENT, { type: UPLOAD_MESSAGE_TYPE, blob: blob(), duration: 9 });

    await waitFor(() => expect(messagesOf(parent, ERROR_MESSAGE_TYPE)).toHaveLength(1));
    expect(mockApiFetch.mock.calls.some((c) => c[0] === "/api/videos/vid_2" && (c[1] as RequestInit).method === "DELETE")).toBe(true);
    expect(messagesOf(parent, COMPLETE_MESSAGE_TYPE)).toHaveLength(0);
    expect(screen.getByTestId("bridge-status")).toHaveTextContent("Upload failed");
  });
});
