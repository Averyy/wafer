"""Browserless execution for Google's SearchGuard JavaScript gate.

SearchGuard's page runs a bounded fingerprint VM and returns a short-lived
cookie plus a ``sei`` navigation. QuickJS is used as an isolated JavaScript
runtime; this module supplies only the DOM surface probed by the captured
challenge and never provides network, filesystem, or browser APIs.
"""

import logging
import os
import re
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

logger = logging.getLogger("wafer")

_MAX_HTML = 300_000
_MAX_SCRIPTS = 16
_MAX_SCRIPT_BYTES = 150_000
_MAX_COOKIE_BYTES = 32_768
_MAX_EXEC_SECONDS = 3


class _InlineScripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.scripts = []
        self._script = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self._script = []

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._script is not None:
            value = "".join(self._script)
            if value.strip():
                self.scripts.append(value)
            self._script = None


def _challenge_scripts(body: str) -> list[str] | None:
    if len(body.encode("utf-8", errors="ignore")) > _MAX_HTML:
        return None
    parser = _InlineScripts()
    try:
        parser.feed(body)
    except Exception:
        return None
    scripts = parser.scripts
    if not (2 <= len(scripts) <= _MAX_SCRIPTS):
        return None
    if sum(len(s.encode("utf-8")) for s in scripts) > _MAX_SCRIPT_BYTES:
        return None
    if not any("knitsail" in s for s in scripts):
        return None
    if not any("challenge_version" in s and "SG_SS" in s for s in scripts):
        return None
    # The measured shell places a small metrics bootstrap before the VM and
    # orchestrator. Run its first four inline scripts in document order and
    # omit the fifth, delayed error beacon (which is unrelated to solving).
    selected = scripts[:4]
    if len(selected) < 4 or not any("knitsail" in s for s in selected):
        return None
    return selected


_SHIM = r"""
globalThis.window = globalThis;
globalThis.self = globalThis;
globalThis.addEventListener = function addEventListener(_type, _listener, options) {
  // EventTarget converts its options dictionary even when no event fires.
  // The VM uses an accessor on that dictionary to detect passive support.
  if (options && typeof options === "object") {
    void options.capture; void options.once; void options.passive; void options.signal;
  }
};
globalThis.removeEventListener = function removeEventListener(
  _type, _listener, options) {
  if (options && typeof options === "object") void options.capture;
};
globalThis.parent = globalThis;
globalThis.top = globalThis;
globalThis.frames = globalThis;
globalThis.opener = null;
globalThis.isSecureContext = true;
globalThis.innerWidth = 1280;
globalThis.innerHeight = 720;
globalThis.outerWidth = 1280;
globalThis.outerHeight = 800;
globalThis.devicePixelRatio = 1;
globalThis.screen = {
  width: 1280, height: 800, availWidth: 1280, availHeight: 800,
  availLeft: 0, availTop: 0, colorDepth: 24, pixelDepth: 24
};
globalThis.history = {length: 1};
if (__waferIsChromium) globalThis.chrome = {
  app: {isInstalled: false},
  csi() { return {startE: Date.now(), onloadT: 0, pageT: 0, tran: 15}; },
  loadTimes() { return {}; }
};
globalThis.__waferCookie = "";
globalThis.__waferNavigation = "";
globalThis.__waferReadyState = "loading";
const __waferCookieMap = new Map();
for (const entry of __waferInitialCookie.split(";")) {
  const pair = entry.trim();
  const separator = pair.indexOf("=");
  if (separator > 0) {
    __waferCookieMap.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
}
globalThis.location = {
  ...__waferURLParts, href: __waferHref, search: __waferSearch,
  toString() { return this.href; },
  replace(value) { __waferNavigation = String(value); },
  assign(value) { __waferNavigation = String(value); }
};
// QuickJS-NG provides a monotonic high-resolution clock. Its native timeOrigin
// uses that clock's epoch, whereas browsers expose an epoch timestamp here.
const __waferPerformanceNow = performance.now;
globalThis.performance = {
  now: __waferPerformanceNow,
  timeOrigin: Date.now() - __waferPerformanceNow(),
  timing: { navigationStart: Date.now(), responseStart: Date.now() },
  memory: {jsHeapSizeLimit: 4294705152, totalJSHeapSize: 10485760,
    usedJSHeapSize: 5242880},
  getEntriesByType() { return []; }
};
const __waferNavigatorValues = {
  sendBeacon() { return true; }, userAgent: __waferUA,
  language: "en-US", languages: ["en-US", "en"],
  hardwareConcurrency: __waferCores, maxTouchPoints: 0,
  deviceMemory: 8, webdriver: false, platform: __waferPlatform,
  vendor: __waferIsChromium ? "Google Inc." : "",
  connection: {effectiveType: "4g", rtt: 50, downlink: 10, saveData: false}
};
if (!__waferIsChromium) {
  delete __waferNavigatorValues.deviceMemory;
  delete __waferNavigatorValues.connection;
}
globalThis.Navigator = new Proxy(function Navigator() {
  throw new TypeError("Illegal constructor");
}, {});
globalThis.navigator = Object.create(Navigator.prototype);
// WebIDL attributes live on the interface prototype, with branded accessors.
// Own data properties hide the prototype checks the VM performs.
for (const [name, value] of Object.entries(__waferNavigatorValues)) {
  const descriptor = {configurable: true, enumerable: true};
  if (typeof value === "function") {
    descriptor.value = new Proxy(value, {});
    descriptor.writable = true;
  } else {
    descriptor.get = new Proxy(function() {
      if (this !== navigator) throw new TypeError("Illegal invocation");
      return value;
    }, {});
  }
  Object.defineProperty(Navigator.prototype, name, descriptor);
}
for (const name of ["plugins", "mimeTypes"]) {
  const collection = Object.freeze([]);
  Object.defineProperty(Navigator.prototype, name, {
    configurable: true, enumerable: true,
    get: new Proxy(function() {
      if (this !== navigator) throw new TypeError("Illegal invocation");
      return collection;
    }, {})
  });
}
Object.defineProperty(Navigator.prototype, Symbol.toStringTag, {value: "Navigator"});
globalThis.HTMLMediaElement = new Proxy(function HTMLMediaElement() {
  throw new TypeError("Illegal constructor");
}, {});
HTMLMediaElement.prototype.canPlayType = new Proxy(function canPlayType() {
  throw new TypeError("Illegal invocation");
}, {});
globalThis.Permissions = new Proxy(function Permissions() {
  throw new TypeError("Illegal constructor");
}, {});
Permissions.prototype.query = new Proxy(function query() {
  throw new TypeError("Illegal invocation");
}, {});
globalThis.sessionStorage = {
  setItem() {}, getItem() { return null; }, removeItem() {}
};
globalThis.console = { log() {}, warn() {}, error() {} };
globalThis.atob = function(value) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let out = "", buffer = 0, bits = 0;
  for (const ch of String(value)) {
    if (ch === "=" || ch === "-") break;
    const digit = chars.indexOf(ch === "_" ? "/" : ch);
    if (digit < 0) continue;
    buffer = (buffer << 6) | digit; bits += 6;
    if (bits >= 8) { bits -= 8; out += String.fromCharCode((buffer >> bits) & 255); }
  }
  return out;
};
globalThis.btoa = function(value) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "", buffer = 0, bits = 0;
  for (const ch of String(value)) {
    buffer = (buffer << 8) | (ch.charCodeAt(0) & 255); bits += 8;
    while (bits >= 6) { bits -= 6; out += chars[(buffer >> bits) & 63]; }
  }
  if (bits) out += chars[(buffer << (6 - bits)) & 63];
  while (out.length % 4) out += "=";
  return out;
};
let __waferTimerId = 0;
let __waferTimers = [];
globalThis.setTimeout = function(callback, delay) {
  if (++__waferTimerId > 1000) throw new Error("timer limit");
  __waferTimers.push({id: __waferTimerId, callback,
    due: Date.now() + Math.max(0, Number(delay) || 0)});
  return __waferTimerId;
};
globalThis.clearTimeout = function(id) {
  __waferTimers = __waferTimers.filter(timer => timer.id !== id);
};
globalThis.setInterval = function(callback, delay) {
  return setTimeout(callback, delay);
};
globalThis.clearInterval = clearTimeout;
globalThis.__waferRunTimers = function() {
  const now = Date.now();
  const ready = __waferTimers.filter(timer => timer.due <= now);
  __waferTimers = __waferTimers.filter(timer => timer.due > now);
  for (const timer of ready) {
    if (typeof timer.callback === "function") timer.callback();
  }
  return ready.length;
};
globalThis.requestIdleCallback = function(callback) { return setTimeout(callback, 0); };
globalThis.cancelIdleCallback = clearTimeout;
function __waferElement(tag) {
  const style = { length: 0, cssText: "", navigation: "", cornerLeftShape: "",
    setProperty() {}, getPropertyValue() { return ""; },
    removeProperty() { return ""; }
  };
  const el = { tagName: String(tag).toUpperCase(), nodeType: 1, clientWidth: 0,
    width: 0, ELEMENT_NODE: 1, DOCUMENT_TYPE_NODE: 10,
    style, children: [], attrs: {},
    appendChild(child) {
      child.parentNode = this; this.children.push(child); return child;
    },
    removeChild(child) {
      const i=this.children.indexOf(child);
      if(i<0) throw Error("not child");
      this.children.splice(i,1); child.parentNode=null; return child;
    },
    setAttribute(name, value) { this.attrs[name]=String(value); },
    hasAttribute(name) { return Object.hasOwn(this.attrs, name); },
    getAttribute(name) { return this.attrs[name] ?? null; },
    getAttributeNames() { return Object.keys(this.attrs); },
    getAttributeNodeNS() { return null; },
    removeAttribute(name) { delete this.attrs[name]; },
    click() {}
  };
  if (String(tag).toLowerCase() === "iframe") {
    el.contentWindow = {String, Function, Object, Array, RegExp, Number, Boolean,
      Date, Math, JSON, Reflect};
  }
  __waferNativeMethods(style);
  __waferNativeMethods(el);
  return el;
}
function __waferNativeMethods(object) {
  for (const [name, descriptor] of Object.entries(
    Object.getOwnPropertyDescriptors(object))) {
    if (typeof descriptor.value === "function") {
      object[name] = new Proxy(descriptor.value, {});
    }
  }
}
const __waferBody = __waferElement("body");
globalThis.document = {
  hidden: false, get readyState() { return __waferReadyState; },
  contentType: "text/html",
  URL: __waferHref, location,
  body: __waferBody, documentElement: __waferElement("html"),
  get cookie() {
    return [...__waferCookieMap].map(([key, value]) => key + "=" + value).join("; ");
  },
  set cookie(value) {
    const pair = String(value).split(";", 1)[0];
    const separator = pair.indexOf("=");
    if (separator > 0) {
      __waferCookieMap.set(pair.slice(0, separator), pair.slice(separator + 1));
      __waferCookie = pair;
    }
  },
  createElement: __waferElement,
  createTextNode(text) { return {nodeType:3,textContent:String(text)}; },
  createEvent() {
    return {button:0,initMouseEvent(){},initCustomEvent(){},
      stopPropagation(){},preventDefault(){}};
  },
  getElementById() { return null; }, getElementsByTagName() { return []; },
  addEventListener() {}, removeEventListener() {}
};
const __waferTrustedTypes = {
  emptyHTML: "",
  createPolicy(_name, rules) {
    return {
      createHTML(value) { return rules.createHTML ? rules.createHTML(value) : value; },
      createScript(value) {
        return rules.createScript ? rules.createScript(value) : value;
      },
      createScriptURL(value) {
        return rules.createScriptURL ? rules.createScriptURL(value) : value;
      }
    };
  }
};
if (__waferIsChromium) globalThis.trustedTypes = __waferTrustedTypes;
for (const object of [location, performance, navigator, sessionStorage, document,
  globalThis.chrome, __waferTrustedTypes]) {
  if (object) __waferNativeMethods(object);
}
for (const name of ["addEventListener", "removeEventListener", "setTimeout",
  "clearTimeout", "setInterval", "clearInterval", "requestIdleCallback",
  "cancelIdleCallback", "atob", "btoa"]) {
  globalThis[name] = new Proxy(globalThis[name], {});
}
"""


def solve_searchguard(
    body: str, url: str, user_agent: str, document_cookie: str = ""
) -> tuple[str, str] | None:
    """Return the short-lived SG_SS cookie and validated ``sei`` URL.

    Returns ``None`` when QuickJS is not installed, the page is not the known
    challenge shape, the bounded VM fails, or the output is malformed.
    """
    scripts = _challenge_scripts(body)
    if scripts is None:
        return None
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or parsed_url.path != "/search":
        return None
    try:
        import quickjs
    except ImportError:
        return None

    context = quickjs.Context()
    context.set_memory_limit(32 * 1024 * 1024)
    context.set_time_limit(_MAX_EXEC_SECONDS)
    context.set_max_stack_size(256 * 1024)
    ua_lower = user_agent.lower()
    is_chromium = "chrome/" in ua_lower and "firefox/" not in ua_lower
    platform = (
        "Win32" if "windows" in ua_lower
        else "Linux x86_64" if "linux" in ua_lower
        else "MacIntel"
    )
    try:
        context.eval(
            "globalThis.__waferHref=" + _js_quote(url)
            + ";globalThis.__waferSearch=" + _js_quote("?" + parsed_url.query)
            + ";globalThis.__waferURLParts=" + _js_quote_url_parts(parsed_url)
            + ";globalThis.__waferUA=" + _js_quote(user_agent)
            + ";globalThis.__waferInitialCookie=" + _js_quote(document_cookie)
            + ";globalThis.__waferCores=" + str(min(64, max(1, os.cpu_count() or 4)))
            + ";globalThis.__waferPlatform=" + _js_quote(platform)
            + ";globalThis.__waferIsChromium=" + ("true" if is_chromium else "false")
            + ";"
        )
        context.eval(_SHIM)
        for script in scripts:
            context.eval(script)
        context.eval("__waferReadyState='interactive'")
        for _ in range(1000):
            if context.execute_pending_job():
                continue
            if context.eval("__waferCookie.startsWith('SG_SS=')"):
                break
            context.eval("__waferRunTimers()")
            time.sleep(0.001)
        cookie = context.eval("__waferCookie")
        navigation = context.eval("__waferNavigation")
    except Exception as exc:
        logger.debug("Google SearchGuard JS failed (%s)", type(exc).__name__)
        return None

    if not isinstance(cookie, str) or len(cookie) > _MAX_COOKIE_BYTES:
        return None
    match = re.fullmatch(r"SG_SS=([A-Za-z0-9.*_~+/=-]{16,32760})", cookie)
    if match is None:
        return None
    if not isinstance(navigation, str) or not navigation:
        return None
    target = urljoin(url, navigation)
    parsed_target = urlparse(target)
    if (
        parsed_target.scheme != "https"
        or (parsed_target.hostname or "").lower().rstrip(".")
        != (parsed_url.hostname or "").lower().rstrip(".")
        or parsed_target.path != "/search"
        or not parse_qs(parsed_target.query).get("sei")
    ):
        return None
    return f"SG_SS={match.group(1)}; Path=/; Max-Age=30; Secure", target


def _js_quote(value: str) -> str:
    """Quote text as a JS string literal without exposing it as source code."""
    import json

    return json.dumps(value, ensure_ascii=True)


def _js_quote_url_parts(parsed_url) -> str:
    import json

    host = parsed_url.netloc.rsplit("@", 1)[-1]
    return json.dumps({
        "protocol": parsed_url.scheme + ":",
        "host": host,
        "hostname": parsed_url.hostname or "",
        "port": str(parsed_url.port or ""),
        "origin": parsed_url.scheme + "://" + host,
        "pathname": parsed_url.path,
        "hash": "#" + parsed_url.fragment if parsed_url.fragment else "",
    }, ensure_ascii=True)
