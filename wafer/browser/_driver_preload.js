// Loaded into Patchright's driver (node --require, via hardened_driver_env).
//
// Playwright auto-attaches every target from its root browser session with
// waitForDebuggerOnStart and, for a shared worker, resumes and detaches it at
// once (crBrowser.js). Chromium queues that resume until the worker exists and
// flushes it ahead of wafer's override, so a shared worker could run its first
// script with the launch's empty high-entropy client hints: 15-17 of 100 for a
// blob: worker, which no request hold can reach (measured 2026-10-06 on a real
// sensor's worker). Excluding shared workers from that one auto-attach leaves
// wafer's browser session as the only one that pauses them, so it resumes each
// only after its override is in. Playwright uses shared workers for nothing.
//
// Only the root session's filterless Target.setAutoAttach is changed, and it
// keeps Chromium's default filter otherwise (target_handler.cc: exclude
// "browser" and "tab", include the rest). If the driver's modules change shape
// this does nothing, and wafer falls back to racing the resume.
'use strict';

const Module = require('module');

const SHARED_WORKER_FILTER = [
  { type: 'shared_worker', exclude: true },
  { type: 'browser', exclude: true },
  { type: 'tab', exclude: true },
  {},
];

function patch(exports) {
  const connection = exports && exports.CRConnection;
  const proto = connection && connection.prototype;
  if (!proto || typeof proto._rawSend !== 'function' || proto.__waferSharedWorkers) {
    return;
  }
  const rawSend = proto._rawSend;
  proto._rawSend = function (sessionId, method, params) {
    if (!sessionId && method === 'Target.setAutoAttach' && params && !params.filter) {
      params = Object.assign({}, params, { filter: SHARED_WORKER_FILTER });
    }
    return rawSend.call(this, sessionId, method, params);
  };
  proto.__waferSharedWorkers = true;
}

// Popups. Playwright sets up every page it attaches, popups included, and
// resumes it at the end of that setup (crPage.js, FrameSession._initialize);
// it sends a user-agent override first only when the context has a user
// agent or locale. So a popup's first document ran with the launch's empty
// high-entropy client hints (3 of 3), and wafer's own override, applied once
// Playwright reports the popup, came too late for it. harden_page publishes
// its override for the browser's user agent in the file WAFER_UA_PARAMS
// names; on a page session (one that sent Page.enable) that set no user
// agent of its own, it is sent right before Playwright's resume, and Chrome
// handles a session's commands in order. A context with a user agent or
// locale keeps Playwright's own override.
const fs = require('fs');

function waferOverride(browserUserAgent) {
  const file = process.env.WAFER_UA_PARAMS;
  if (!file || !browserUserAgent) {
    return null;
  }
  try {
    const table = JSON.parse(fs.readFileSync(file, 'utf8'));
    return table[browserUserAgent] || null;
  } catch (e) {
    return null;
  }
}

// Input Chrome never acknowledges. An Input.dispatch* command answers once the
// renderer has handled the event, and one in flight when the frame it went to
// is torn down is never answered: DataDome's full-page iframe on mouser.com
// was removed as the cleared page committed its reload, 4-14 ms after a
// mouseMoved, and that move never returned (macOS, 2 of 16 solves, on 0.7.11
// too). Playwright waits for the answer with no deadline, so the solve sat in
// mouse.move to its own timeout and the browser was then killed (see
// docs/ref-headless.md). An answer
// that has not come within INPUT_ACK_MS is taken as given; the event is
// Chrome's either way, and it keeps queued input in order. Measured acks:
// median 11 ms, slowest 354 ms of 1,467 (2026-11-04).
const INPUT_ACK_MS = 3000;
const INPUT_METHODS = new Set([
  'Input.dispatchMouseEvent',
  'Input.dispatchKeyEvent',
  'Input.dispatchTouchEvent',
  'Input.dispatchDragEvent',
  'Input.insertText',
]);

function boundedInput(result) {
  if (!result || typeof result.then !== 'function') {
    return result;
  }
  let timer;
  const unanswered = new Promise((resolve) => {
    timer = setTimeout(() => resolve({}), INPUT_ACK_MS);
    if (timer.unref) {
      timer.unref();
    }
  });
  result.then(() => clearTimeout(timer), () => clearTimeout(timer));
  return Promise.race([result, unanswered]);
}

function patchSession(exports) {
  const session = exports && exports.CRSession;
  const proto = session && session.prototype;
  if (!proto || typeof proto.send !== 'function' || proto.__waferUserAgent) {
    return;
  }
  const send = proto.send;
  proto.send = function (method, params) {
    const connection = this._connection;
    if (method === 'Page.enable') {
      this.__waferPage = true;
    } else if (method === 'Emulation.setUserAgentOverride') {
      // Playwright's own, from a context user agent or locale.
      this.__waferOverridden = true;
    } else if (
      method === 'Runtime.runIfWaitingForDebugger' &&
      this.__waferPage && !this.__waferOverridden && connection
    ) {
      const override = waferOverride(connection.__waferBrowserUserAgent);
      if (override) {
        this.__waferOverridden = true;
        send.call(this, 'Emulation.setUserAgentOverride', override).catch(() => {});
      }
    }
    const result = send.call(this, method, params);
    if (INPUT_METHODS.has(method)) {
      return boundedInput(result);
    }
    if (method === 'Browser.getVersion' && connection && result && result.then) {
      // The browser's own user agent: what wafer keys its override by.
      result.then((version) => {
        if (version && version.userAgent && !connection.__waferBrowserUserAgent) {
          connection.__waferBrowserUserAgent = version.userAgent;
        }
      }, () => {});
    }
    return result;
  };
  proto.__waferUserAgent = true;
}

// A detached element made the driver exit. Patchright's
// ElementHandle.evaluateExpression starts adopting the handle into the
// evaluation's world and never awaits that promise (javascript.js:
// `context.adoptIfNeeded(this) === null`). When the page navigates during the
// call, the adoption's DOM.describeNode rejects with "Cannot find context with
// specified id", nothing handles it, and Node's default for an unhandled
// rejection killed the whole driver. Every later browser call then hung to its
// timeout: Alibaba's slider accepted, navigated during a locator.evaluate
// poll, and the search failed at 179s after three dead contexts (fetchaller,
// 2026-10-08). A CDP protocol error only reports a target or context that is
// gone, and the call that needed it has already settled, so it is dropped.
// Any other unhandled rejection still ends the driver, as before.
function isProtocolError(reason) {
  return Boolean(
    reason &&
      (reason.constructor && reason.constructor.name === 'ProtocolError' ||
        typeof reason.method === 'string' && 'type' in reason)
  );
}

process.on('unhandledRejection', (reason) => {
  if (isProtocolError(reason)) {
    return;
  }
  throw reason;
});

const load = Module._load;
Module._load = function () {
  const exports = load.apply(this, arguments);
  try {
    patch(exports);
    patchSession(exports);
  } catch (e) {
    // Never break the driver over this.
  }
  return exports;
};
