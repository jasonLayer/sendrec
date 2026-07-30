import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  announceRecordingComplete,
  captureParentOrigin,
  COMPLETE_MESSAGE_TYPE,
  PARENT_QUERY_PARAM,
  PARENT_STORAGE_KEY,
} from "./announce";

const PARENT = "https://app.majorgtm.com";

function landOn(search: string): void {
  window.history.replaceState({}, "", `/${search}`);
}

/** Pretends this document is inside a frame owned by someone else. */
function embed(): { postMessage: ReturnType<typeof vi.fn> } {
  const parent = { postMessage: vi.fn() };
  Object.defineProperty(window, "parent", { value: parent, configurable: true });
  return parent;
}

/** Restores the top-level case, where window.parent IS window. */
function unembed(): void {
  Object.defineProperty(window, "parent", { value: window, configurable: true });
}

const realSessionStorage = window.sessionStorage;

/**
 * Replaces sessionStorage with one whose named method throws.
 *
 * Replacement, not a spy — see the tests that use it for why.
 */
function denyStorage(method: "getItem" | "setItem"): ReturnType<typeof vi.fn> {
  const denied = vi.fn(() => {
    throw new Error("storage denied");
  });
  Object.defineProperty(window, "sessionStorage", {
    value: { ...realSessionStorage, getItem: () => null, setItem: () => {}, [method]: denied },
    configurable: true,
  });
  return denied;
}

function restoreStorage(): void {
  Object.defineProperty(window, "sessionStorage", {
    value: realSessionStorage,
    configurable: true,
  });
}

beforeEach(() => {
  restoreStorage();
  sessionStorage.clear();
  landOn("");
  unembed();
});

afterEach(() => {
  restoreStorage();
  unembed();
});

describe("captureParentOrigin", () => {
  it("reads the origin the server validated", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    expect(captureParentOrigin()).toBe(PARENT);
  });

  it("is empty when the recorder was opened directly", () => {
    expect(captureParentOrigin()).toBe("");
  });

  // The parameter only exists on the landing URL. Navigating inside the app, or
  // reloading the frame, would otherwise lose the one thing that lets the
  // recording be announced — and the parent would wait forever.
  it("survives the parameter disappearing from the URL", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    expect(captureParentOrigin()).toBe(PARENT);

    landOn("library");
    expect(captureParentOrigin()).toBe(PARENT);
  });

  it("does not invent an origin from an empty parameter", () => {
    landOn(`?${PARENT_QUERY_PARAM}=`);
    expect(captureParentOrigin()).toBe("");
  });

  // Storage is unavailable in some privacy modes, and a recorder that throws on
  // load is worse than one that cannot announce.
  //
  // The whole global is REPLACED rather than spied. jsdom implements Storage as
  // a Proxy that forwards to its own internals, so vi.spyOn installs an own
  // property that is never consulted — the spy records nothing, nothing throws,
  // and the test passes without exercising the thing it names. Asserting the
  // stub was actually called is what keeps that from creeping back.
  it("survives sessionStorage refusing to write", () => {
    const denied = denyStorage("setItem");
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);

    expect(captureParentOrigin()).toBe(PARENT);
    expect(denied).toHaveBeenCalled();
  });

  it("survives sessionStorage refusing to read", () => {
    const denied = denyStorage("getItem");

    expect(captureParentOrigin()).toBe("");
    expect(denied).toHaveBeenCalled();
  });
});

describe("announceRecordingComplete", () => {
  it("tells the parent which recording finished", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    const parent = embed();

    announceRecordingComplete({ videoId: "vid-1", shareToken: "tok-1" });

    expect(parent.postMessage).toHaveBeenCalledTimes(1);
    const [message, targetOrigin] = parent.postMessage.mock.calls[0];
    // The shape is the parent's contract: it reads these three fields flat.
    expect(message).toEqual({
      type: COMPLETE_MESSAGE_TYPE,
      videoId: "vid-1",
      shareToken: "tok-1",
    });
    expect(targetOrigin).toBe(PARENT);
  });

  // A share token is a capability. '*' would hand it to whoever is framing us.
  it("never posts to a wildcard target", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    const parent = embed();

    announceRecordingComplete({ videoId: "vid-1", shareToken: "tok-1" });

    expect(parent.postMessage.mock.calls[0][1]).not.toBe("*");
  });

  it("says nothing when no validated parent is known", () => {
    const parent = embed();

    announceRecordingComplete({ videoId: "vid-1", shareToken: "tok-1" });

    expect(parent.postMessage).not.toHaveBeenCalled();
  });

  it("says nothing when the recorder is not embedded at all", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    const postMessage = vi.spyOn(window, "postMessage");

    announceRecordingComplete({ videoId: "vid-1", shareToken: "tok-1" });

    expect(postMessage).not.toHaveBeenCalled();
    postMessage.mockRestore();
  });

  it("says nothing when the recording has no share token to announce", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    const parent = embed();

    announceRecordingComplete({ videoId: "vid-1", shareToken: "" });

    expect(parent.postMessage).not.toHaveBeenCalled();
  });

  // The upload path already committed the recording by the time this runs. A
  // parent frame that has navigated away, or a browser that refuses the post,
  // must not turn a saved recording into a thrown error.
  it("swallows a refusal from the parent frame", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    const parent = embed();
    parent.postMessage.mockImplementation(() => {
      throw new Error("frame is gone");
    });

    expect(() =>
      announceRecordingComplete({ videoId: "vid-1", shareToken: "tok-1" })
    ).not.toThrow();
  });

  it("stores the validated origin under a stable key", () => {
    landOn(`?${PARENT_QUERY_PARAM}=${encodeURIComponent(PARENT)}`);
    captureParentOrigin();
    expect(sessionStorage.getItem(PARENT_STORAGE_KEY)).toBe(PARENT);
  });
});
