"""Unit tests for the per-page half of browser hardening.

The real-browser behaviour these encode is measured in
``tests/test_headless_leaks.py``; here each piece is held to its contract with
fake CDP sessions, so a regression is caught without launching Chrome.
"""

import asyncio
import json
import logging
import sys
from unittest.mock import MagicMock

import pytest

from wafer.browser import _solver as solver_mod
from wafer.browser import harden_page, harden_page_async
from wafer.browser._solver import (
    _AUTO_ATTACH,
    _HEADLESS_FIX_SCRIPT,
    _MAC_DISPLAYS,
    _MAX_CHILD_DEPTH,
    _MAX_HANDLED_SHARED_WORKERS,
    _MAX_PENDING_REPLIES,
    _SCREENXY_FIX_SCRIPT,
    _browser_identity,
    _check_window_state,
    _child_target_commands,
    _first_attach,
    _harden_child_targets,
    _harden_child_targets_async,
    _harden_shared_workers,
    _harden_shared_workers_async,
    _headless_fix_script,
    _headless_geometry,
    _install_init_script_fallback,
    _install_init_script_fallback_async,
    _native_window,
    _page_hardening_commands,
    _page_scripts,
    _TargetRouter,
    _ua_override_params,
)

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
)
_HEADLESS_UA = _UA.replace("Chrome/", "HeadlessChrome/")
_VERSION = {"product": "Chrome/154.0.8037.98", "userAgent": _UA}


def _reply_event(params):
    """The Target.receivedMessageFromTarget Chrome sends back for a routed one."""
    path = [params["sessionId"]]
    message = json.loads(params["message"])
    while message["method"] == "Target.sendMessageToTarget":
        path.append(message["params"]["sessionId"])
        message = json.loads(message["params"]["message"])
    reply = {"id": message["id"], "result": {}}
    for session_id in reversed(path[1:]):
        reply = {
            "method": "Target.receivedMessageFromTarget",
            "params": {"sessionId": session_id, "message": json.dumps(reply)},
        }
    return {"sessionId": path[0], "message": json.dumps(reply)}


class FakeCDP:
    """Records sends, answers from a table, and lets a test emit events.

    Routed messages are answered the way Chrome answers them, with a
    Target.receivedMessageFromTarget reply, so code that waits for
    acknowledgement sees one.
    """

    def __init__(self, responses=None):
        self.sent = []
        self.handlers = {}
        self.responses = responses or {}

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)

    def send(self, method, params=None):
        self.sent.append((method, params))
        if method == "Target.sendMessageToTarget":
            for handler in self.handlers.get("Target.receivedMessageFromTarget", []):
                result = handler(_reply_event(params))
                if asyncio.iscoroutine(result):
                    asyncio.ensure_future(result)
        answer = self.responses.get(method, {})
        return answer(params) if callable(answer) else answer

    def emit(self, event, params):
        for handler in self.handlers.get(event, []):
            handler(params)

    def methods(self):
        return [method for method, _ in self.sent]


class AsyncFakeCDP(FakeCDP):
    async def send(self, method, params=None):
        return FakeCDP.send(self, method, params)

    async def emit(self, event, params):
        for handler in self.handlers.get(event, []):
            result = handler(params)
            if asyncio.iscoroutine(result):
                await result


def _unwrap(params):
    """The innermost message a Target.sendMessageToTarget delivers, and its path."""
    path = [params["sessionId"]]
    message = json.loads(params["message"])
    while message["method"] == "Target.sendMessageToTarget":
        path.append(message["params"]["sessionId"])
        message = json.loads(message["params"]["message"])
    return path, message


def _delivered(cdp):
    return [
        _unwrap(params)
        for method, params in cdp.sent
        if method == "Target.sendMessageToTarget"
    ]


def _window_state(width=1440, height=900, ratio=2):
    return {"result": {"value": json.dumps([width, height, ratio])}}


def _native_state(width=1536, height=864):
    """What a no_viewport page of hardened_launch_config's launch reports."""
    value = [width, height, 2, width, height + 87, 1710, 34, 30]
    return {"result": {"value": json.dumps(value)}}


# ---------------------------------------------------------------------------
# Screen geometry
# ---------------------------------------------------------------------------


class TestHeadlessGeometry:
    def test_picks_the_first_display_that_fits_with_room_for_chrome(self):
        geometry = _headless_geometry(1440, 900)
        assert (geometry["screenWidth"], geometry["screenHeight"]) == (1710, 1107)

    def test_outer_size_adds_the_window_frame(self):
        geometry = _headless_geometry(1366, 768)
        assert (geometry["outerWidth"], geometry["outerHeight"]) == (1368, 848)

    def test_falls_back_to_the_largest_display(self):
        geometry = _headless_geometry(3000, 2000)
        assert (geometry["screenWidth"], geometry["screenHeight"]) == _MAC_DISPLAYS[-1]

    def test_fixed_script_carries_the_geometry(self):
        geometry = _headless_geometry(1440, 900)
        assert json.dumps(geometry) in _headless_fix_script(geometry)

    def test_derived_script_is_the_shipped_init_script(self):
        # HardenedLaunch.init_scripts keeps deriving from its own window, which
        # is only meaningful in a top-level document.
        assert _headless_fix_script() == _HEADLESS_FIX_SCRIPT
        assert "var g = null;" in _HEADLESS_FIX_SCRIPT

    def test_one_display_table_feeds_both_forms(self):
        assert json.dumps([list(d) for d in _MAC_DISPLAYS]) in _HEADLESS_FIX_SCRIPT

    def test_page_scripts_share_one_geometry(self):
        # Iframes must report the window the top document does.
        scripts = _page_scripts(True, (1440, 900))
        assert scripts == [_headless_fix_script(_headless_geometry(1440, 900))]

    def test_headed_pages_get_no_window_patch(self):
        assert _page_scripts(False, (1440, 900)) == []

    def test_unknown_viewport_falls_back_to_deriving(self):
        assert _page_scripts(True, None) == [_HEADLESS_FIX_SCRIPT]


# ---------------------------------------------------------------------------
# Command plans
# ---------------------------------------------------------------------------


class TestPageCommands:
    def test_order_and_contents(self):
        params = _ua_override_params(_UA, "154.0.8037.98")
        commands = _page_hardening_commands(
            headless=True, ua_params=params, scripts=["S"], platform="darwin"
        )
        assert [m for m, _ in commands] == [
            "Page.enable",
            "Page.addScriptToEvaluateOnNewDocument",
            "Emulation.setEmulatedMedia",
            "Emulation.setUserAgentOverride",
        ]

    def test_ua_override_always_carries_metadata(self):
        # Without metadata Chrome drops sec-ch-ua, or fills it from the binary.
        params = _ua_override_params(_UA, "154.0.8037.98")
        assert params["userAgent"] == _UA
        assert params["acceptLanguage"] == "en-US,en"
        metadata = params["userAgentMetadata"]
        assert metadata["fullVersion"] == "154.0.8037.98"
        assert any(b["brand"] == "Google Chrome" for b in metadata["brands"])

    def test_color_gamut_only_for_headless_macos(self):
        for headless, platform in ((False, "darwin"), (True, "linux")):
            commands = _page_hardening_commands(
                headless=headless, ua_params=None, scripts=[], platform=platform
            )
            assert "Emulation.setEmulatedMedia" not in [m for m, _ in commands]

    def test_no_ua_means_no_override(self):
        commands = _page_hardening_commands(
            headless=False, ua_params=None, scripts=[], platform="darwin"
        )
        assert [m for m, _ in commands] == ["Page.enable"]


class TestChildCommands:
    def setup_method(self):
        self.params = _ua_override_params(_UA, "154.0.8037.98")

    def test_iframe_gets_scripts_override_and_its_own_auto_attach(self):
        commands = _child_target_commands(
            "iframe", headless=True, ua_params=self.params, scripts=["S"],
            platform="darwin",
        )
        methods = [m for m, _ in commands]
        assert methods == [
            "Page.enable",
            "Page.addScriptToEvaluateOnNewDocument",
            "Emulation.setEmulatedMedia",
            "Emulation.setUserAgentOverride",
            "Target.setAutoAttach",
        ]
        # Nested iframes and iframe workers attach under this one, paused too.
        assert commands[-1][1] == {
            "autoAttach": True,
            "waitForDebuggerOnStart": True,
            "flatten": False,
        }

    @pytest.mark.parametrize("target_type", ["worker", "service_worker"])
    def test_workers_get_the_network_override(self, target_type):
        # A service worker's fetches otherwise carry the browser default UA.
        commands = _child_target_commands(
            target_type, headless=True, ua_params=self.params, scripts=["S"]
        )
        assert [m for m, _ in commands] == [
            "Emulation.setUserAgentOverride",
            "Network.setUserAgentOverride",
        ]
        assert all(p is self.params for _, p in commands)

    def test_an_iframe_gets_exactly_the_page_commands(self):
        # One list: a step added to the page must reach iframes too.
        kwargs = dict(
            headless=True, ua_params=self.params, scripts=["S"], platform="darwin"
        )
        assert _child_target_commands("iframe", **kwargs, depth=1) == (
            _page_hardening_commands(**kwargs) + [_AUTO_ATTACH]
        )

    def test_iframes_stop_attaching_children_at_the_depth_cap(self):
        kwargs = dict(headless=True, ua_params=self.params, scripts=["S"])
        shallow = _child_target_commands("iframe", **kwargs, depth=_MAX_CHILD_DEPTH - 1)
        deep = _child_target_commands("iframe", **kwargs, depth=_MAX_CHILD_DEPTH)
        assert shallow[-1] == _AUTO_ATTACH
        assert _AUTO_ATTACH not in deep

    def test_a_message_at_the_depth_cap_stays_small(self):
        # Escaping doubles per nesting level; the cap is what bounds it.
        router = _TargetRouter()
        path = tuple(f"session-{i}" for i in range(_MAX_CHILD_DEPTH))
        _, params = router.wrap(path, "Emulation.setUserAgentOverride", self.params)
        assert len(json.dumps(params)) < 64_000

    def test_unknown_targets_get_nothing(self):
        assert (
            _child_target_commands(
                "other", headless=True, ua_params=self.params, scripts=["S"]
            )
            == []
        )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class TestTargetRouter:
    def test_wraps_one_level_per_session(self):
        router = _TargetRouter()
        method, params = router.wrap(("a", "b", "c"), "Runtime.enable", {"x": 1})
        assert method == "Target.sendMessageToTarget"
        path, message = _unwrap(params)
        assert path == ["a", "b", "c"]
        assert (message["method"], message["params"]) == ("Runtime.enable", {"x": 1})

    def test_unwraps_a_nested_event_to_its_session(self):
        router = _TargetRouter()
        inner = {"method": "Target.attachedToTarget", "params": {"sessionId": "c"}}
        middle = {
            "method": "Target.receivedMessageFromTarget",
            "params": {"sessionId": "b", "message": json.dumps(inner)},
        }
        path, method, params = router.unwrap(
            {"sessionId": "a", "message": json.dumps(middle)}
        )
        assert path == ("a", "b")
        assert method == "Target.attachedToTarget"
        assert params == {"sessionId": "c"}

    def test_unanswered_commands_are_bounded(self):
        # A target that goes away never replies; its entries must not pile up.
        router = _TargetRouter()
        for _ in range(_MAX_PENDING_REPLIES * 3):
            router.wrap(("a",), "Runtime.runIfWaitingForDebugger", {})
        assert len(router._pending) == _MAX_PENDING_REPLIES

    def test_a_rejected_command_is_logged(self, caplog):
        router = _TargetRouter()
        _, params = router.wrap(("a",), "Emulation.setUserAgentOverride", {})
        sent_id = json.loads(params["message"])["id"]
        reply = {"id": sent_id, "error": {"message": "nope"}}
        with caplog.at_level(logging.DEBUG, logger="wafer"):
            path, method, _ = router.unwrap(
                {"sessionId": "a", "message": json.dumps(reply)}
            )
        assert method is None
        assert "Emulation.setUserAgentOverride" in caplog.text


# ---------------------------------------------------------------------------
# Child targets
# ---------------------------------------------------------------------------


def _attached(session_id, target_type, target_id="T"):
    return {
        "sessionId": session_id,
        "targetInfo": {"type": target_type, "targetId": target_id},
        "waitingForDebugger": True,
    }


class TestChildTargets:
    def test_enables_auto_attach_unflattened_and_paused(self):
        cdp = FakeCDP()
        _harden_child_targets(cdp, lambda t, d: [])
        assert cdp.sent[-1] == (
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": False},
        )

    def test_applies_the_plan_then_resumes(self):
        cdp = FakeCDP()
        _harden_child_targets(
            cdp, lambda t, d: [("Network.setUserAgentOverride", {})]
        )
        cdp.emit("Target.attachedToTarget", _attached("s1", "worker"))
        delivered = [(path, m["method"]) for path, m in _delivered(cdp)]
        assert delivered == [
            (["s1"], "Network.setUserAgentOverride"),
            (["s1"], "Runtime.runIfWaitingForDebugger"),
        ]

    def test_nested_targets_are_addressed_through_their_parent(self):
        cdp = FakeCDP()
        _harden_child_targets(
            cdp, lambda t, d: [("Emulation.setUserAgentOverride", {})]
        )
        nested = {
            "method": "Target.attachedToTarget",
            "params": _attached("s2", "iframe"),
        }
        cdp.emit(
            "Target.receivedMessageFromTarget",
            {"sessionId": "s1", "message": json.dumps(nested)},
        )
        delivered = [(path, m["method"]) for path, m in _delivered(cdp)]
        assert delivered == [
            (["s1", "s2"], "Emulation.setUserAgentOverride"),
            (["s1", "s2"], "Runtime.runIfWaitingForDebugger"),
        ]

    def test_a_failing_plan_still_resumes_the_target(self):
        # It was attached paused: never resuming it hangs the page.
        cdp = FakeCDP()

        def plan(_type, _depth):
            raise RuntimeError("boom")

        _harden_child_targets(cdp, plan)
        cdp.emit("Target.attachedToTarget", _attached("s1", "iframe"))
        assert [m["method"] for _, m in _delivered(cdp)] == [
            "Runtime.runIfWaitingForDebugger"
        ]

    def test_async_variant_matches(self):
        cdp = AsyncFakeCDP()

        async def scenario():
            await _harden_child_targets_async(
                cdp, lambda t, d: [("Network.setUserAgentOverride", {})]
            )
            await cdp.emit("Target.attachedToTarget", _attached("s1", "worker"))

        asyncio.run(scenario())
        assert [(p, m["method"]) for p, m in _delivered(cdp)] == [
            (["s1"], "Network.setUserAgentOverride"),
            (["s1"], "Runtime.runIfWaitingForDebugger"),
        ]


class TestSharedWorkers:
    def _browser(self):
        cdp = FakeCDP({"Target.attachToTarget": {"sessionId": "nf"}})
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = cdp
        return browser, cdp

    def test_auto_attaches_only_shared_workers_flattened(self):
        # Chrome allows nothing but flattened auto-attach on a browser session.
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        method, params = cdp.sent[-1]
        assert method == "Target.setAutoAttach"
        assert params["flatten"] is True
        assert params["waitForDebuggerOnStart"] is True
        assert params["filter"][0] == {"type": "shared_worker", "exclude": False}

    def test_overrides_through_a_second_session_then_releases(self):
        browser, cdp = self._browser()
        params = {"userAgent": _UA}
        _harden_shared_workers(browser, params)
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        attach = ("Target.attachToTarget", {"targetId": "T", "flatten": False})
        assert attach in cdp.sent
        # The resume rides the override's session, so the worker processes
        # the override first. Under hardened_driver_env nothing else resumes
        # a shared worker.
        assert [(p, m["method"]) for p, m in _delivered(cdp)] == [
            (["nf"], "Emulation.setUserAgentOverride"),
            (["nf"], "Network.setUserAgentOverride"),
            (["nf"], "Runtime.runIfWaitingForDebugger"),
        ]
        assert cdp.sent[-1] == ("Target.detachFromTarget", {"sessionId": "flat"})

    def test_a_reattached_worker_is_left_alone(self):
        # Releasing the flattened session makes the auto-attacher re-attach the
        # now-running worker; handling it again would loop forever.
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        before = list(cdp.sent)
        again = dict(_attached("flat2", "shared_worker"), waitingForDebugger=False)
        cdp.emit("Target.attachedToTarget", again)
        assert cdp.sent == before

    def test_the_second_sessions_own_attach_is_never_detached(self):
        # Opening the unflattened session emits another attach for the same
        # worker, reporting it still paused. Detaching that session dropped
        # its override, and the worker started without one.
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        before = list(cdp.sent)
        cdp.emit("Target.attachedToTarget", _attached("nf", "shared_worker"))
        assert cdp.sent == before

    def test_handled_ids_are_bounded(self):
        handled = {}
        for i in range(_MAX_HANDLED_SHARED_WORKERS + 10):
            assert _first_attach(handled, f"T{i}")
        assert len(handled) == _MAX_HANDLED_SHARED_WORKERS
        assert not _first_attach(handled, f"T{_MAX_HANDLED_SHARED_WORKERS + 9}")

    def test_async_variant_matches(self):
        browser, sync_cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        sync_cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))

        async_cdp = AsyncFakeCDP({"Target.attachToTarget": {"sessionId": "nf"}})
        async_browser = MagicMock(spec=["new_browser_cdp_session"])

        async def session():
            return async_cdp

        async_browser.new_browser_cdp_session = session

        async def scenario():
            await _harden_shared_workers_async(async_browser, {"userAgent": _UA})
            await async_cdp.emit(
                "Target.attachedToTarget", _attached("flat", "shared_worker")
            )

        asyncio.run(scenario())
        assert async_cdp.sent == sync_cdp.sent

    def test_installed_once_per_browser(self):
        browser, _ = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        _harden_shared_workers(browser, {"userAgent": _UA})
        browser.new_browser_cdp_session.assert_called_once()

    def test_no_browser_object_is_skipped(self):
        _harden_shared_workers(None, {"userAgent": _UA})

    def test_a_failed_session_warns_and_can_retry(self, caplog):
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.side_effect = RuntimeError("closed")
        with caplog.at_level(logging.WARNING, logger="wafer"):
            _harden_shared_workers(browser, {"userAgent": _UA})
        assert "shared workers" in caplog.text
        _harden_shared_workers(browser, {"userAgent": _UA})
        assert browser.new_browser_cdp_session.call_count == 2

    def test_service_worker_attach_events_are_left_alone(self):
        # The channel's unflattened attach to a service worker emits an
        # attach event on the same session; it is not a shared worker.
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        before = list(cdp.sent)
        cdp.emit("Target.attachedToTarget", _attached("nf", "service_worker"))
        assert cdp.sent == before


def _paused(request_id, network_id):
    return {"requestId": request_id, "networkId": network_id, "request": {}}


def _routed_event(session_id, method):
    return {
        "sessionId": session_id,
        "message": json.dumps({"method": method, "params": {}}),
    }


class TestSharedWorkerScriptHold:
    """The browser session holds a shared worker's script fetch.

    Chrome reports a worker script's networkId as the worker's target id, so
    the hold matches each fetch to exactly its worker.
    """

    def _browser(self, cdp=None):
        cdp = cdp or FakeCDP({"Target.attachToTarget": {"sessionId": "nf"}})
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = cdp
        return browser, cdp

    def test_holds_scripts_before_auto_attaching(self):
        # A fetch that pauses with nothing listening never loads, and a
        # worker attached before the hold is in place is not held.
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        assert "Fetch.requestPaused" in cdp.handlers
        assert cdp.methods()[-2:] == ["Fetch.enable", "Target.setAutoAttach"]
        assert cdp.sent[-2][1] == {
            "patterns": [
                {"urlPattern": "*", "resourceType": "Other", "requestStage": "Request"}
            ]
        }

    def test_a_worker_script_waits_for_its_override(self):
        cdp = FakeCDP()

        def attach(params):
            cdp.emit("Fetch.requestPaused", _paused("R", "T"))
            return {"sessionId": "nf"}

        cdp.responses["Target.attachToTarget"] = attach
        browser, _ = self._browser(cdp)
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        continued = cdp.sent.index(("Fetch.continueRequest", {"requestId": "R"}))
        overrides = [
            i
            for i, (method, _) in enumerate(cdp.sent)
            if method == "Target.sendMessageToTarget"
        ]
        # Override, then the resume on the same session, then the release.
        assert len(overrides) == 3 and max(overrides) < continued
        assert cdp.sent[-1] == ("Target.detachFromTarget", {"sessionId": "flat"})

    def test_other_requests_continue_at_once(self):
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Fetch.requestPaused", _paused("R", "page-request"))
        assert cdp.sent[-1] == ("Fetch.continueRequest", {"requestId": "R"})

    def test_a_handled_workers_later_fetch_continues_at_once(self):
        # A restart fetches the script again under the same target id; the
        # override is already in place.
        browser, cdp = self._browser()
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        cdp.emit("Fetch.requestPaused", _paused("R2", "T"))
        assert cdp.sent[-1] == ("Fetch.continueRequest", {"requestId": "R2"})

    def test_a_failed_override_still_releases_the_script(self):
        cdp = FakeCDP()

        def attach(params):
            cdp.emit("Fetch.requestPaused", _paused("R", "T"))
            return {}  # no sessionId

        cdp.responses["Target.attachToTarget"] = attach
        browser, _ = self._browser(cdp)
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        assert ("Fetch.continueRequest", {"requestId": "R"}) in cdp.sent
        assert browser._wafer_channel.held == {}

    def test_a_failed_release_does_not_stop_the_others(self):
        cdp = FakeCDP()

        def attach(params):
            cdp.emit("Fetch.requestPaused", _paused("R1", "T"))
            cdp.emit("Fetch.requestPaused", _paused("R2", "T"))
            return {"sessionId": "nf"}

        def release(params):
            if params["requestId"] == "R1":
                raise RuntimeError("request gone")
            return {}

        cdp.responses["Target.attachToTarget"] = attach
        cdp.responses["Fetch.continueRequest"] = release
        browser, _ = self._browser(cdp)
        _harden_shared_workers(browser, {"userAgent": _UA})
        cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        assert ("Fetch.continueRequest", {"requestId": "R2"}) in cdp.sent
        assert cdp.sent[-1] == ("Target.detachFromTarget", {"sessionId": "flat"})

    def test_listeners_are_added_once_across_a_retry(self):
        # A second paused listener would continue every request twice.
        cdp = FakeCDP()
        calls = []

        def auto_attach(params):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("closed")
            return {}

        cdp.responses["Target.setAutoAttach"] = auto_attach
        browser, _ = self._browser(cdp)
        _harden_shared_workers(browser, {"userAgent": _UA})
        _harden_shared_workers(browser, {"userAgent": _UA})
        assert len(calls) == 2
        assert len(cdp.handlers["Fetch.requestPaused"]) == 1
        assert len(cdp.handlers["Target.attachedToTarget"]) == 1

    def test_async_holds_a_script_until_its_override(self):
        class YieldingCDP(AsyncFakeCDP):
            # Each send yields, as a real round trip does, so the paused
            # handler runs while the override is in flight.
            async def send(self, method, params=None):
                await asyncio.sleep(0)
                return FakeCDP.send(self, method, params)

        cdp = YieldingCDP()
        browser = MagicMock(spec=["new_browser_cdp_session"])

        async def session():
            return cdp

        browser.new_browser_cdp_session = session
        pending = []

        def attach(params):
            # The paused event's handler task is created while the override
            # is in flight, as Playwright's dispatch would.
            pending.append(asyncio.ensure_future(
                cdp.emit("Fetch.requestPaused", _paused("R", "T"))
            ))
            return {"sessionId": "nf"}

        cdp.responses["Target.attachToTarget"] = attach

        async def scenario():
            await _harden_shared_workers_async(browser, {"userAgent": _UA})
            attached = asyncio.ensure_future(
                cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
            )
            await asyncio.gather(attached, *pending)

        asyncio.run(scenario())
        continued = cdp.sent.index(("Fetch.continueRequest", {"requestId": "R"}))
        overrides = [
            i
            for i, (method, _) in enumerate(cdp.sent)
            if method == "Target.sendMessageToTarget"
        ]
        # Override, then the resume on the same session, then the release.
        assert len(overrides) == 3 and max(overrides) < continued
        assert browser._wafer_channel.held == {}


class TestSharedWorkerRestart:
    """A shared worker created again keeps its target and waits for wafer.

    Chrome announces no attach for it; wafer's session gets
    Inspector.targetReloadedAfterCrash and must resume the worker there, or
    it never runs.
    """

    def _channel(self):
        cdp = FakeCDP({"Target.attachToTarget": {"sessionId": "nf"}})
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = cdp
        _harden_shared_workers(browser, {"userAgent": _UA})
        return cdp

    def test_a_restarted_worker_is_resumed_through_its_session(self):
        cdp = self._channel()
        cdp.emit(
            "Target.receivedMessageFromTarget",
            _routed_event("nf", "Inspector.targetReloadedAfterCrash"),
        )
        assert [(p, m["method"]) for p, m in _delivered(cdp)] == [
            (["nf"], "Runtime.runIfWaitingForDebugger")
        ]

    def test_other_worker_events_resume_nothing(self):
        cdp = self._channel()
        before = list(cdp.sent)
        cdp.emit(
            "Target.receivedMessageFromTarget",
            _routed_event("nf", "Inspector.targetCrashed"),
        )
        assert cdp.sent == before

    def test_a_nested_reload_is_left_alone(self):
        # Only the channel's own sessions carry a worker's override.
        cdp = self._channel()
        before = list(cdp.sent)
        nested = {
            "method": "Target.receivedMessageFromTarget",
            "params": {
                "sessionId": "child",
                "message": json.dumps(
                    {"method": "Inspector.targetReloadedAfterCrash", "params": {}}
                ),
            },
        }
        cdp.emit(
            "Target.receivedMessageFromTarget",
            {"sessionId": "nf", "message": json.dumps(nested)},
        )
        assert cdp.sent == before

    def test_a_failed_resume_is_logged_not_raised(self, caplog):
        cdp = self._channel()
        cdp.responses["Target.sendMessageToTarget"] = lambda _: (_ for _ in ()).throw(
            RuntimeError("closed")
        )
        with caplog.at_level(logging.DEBUG, logger="wafer"):
            cdp.emit(
                "Target.receivedMessageFromTarget",
                _routed_event("nf", "Inspector.targetReloadedAfterCrash"),
            )
        assert "resume a restarted worker" in caplog.text

    def test_async_resumes_the_same_way(self):
        cdp = AsyncFakeCDP({"Target.attachToTarget": {"sessionId": "nf"}})
        browser = MagicMock(spec=["new_browser_cdp_session"])

        async def session():
            return cdp

        browser.new_browser_cdp_session = session

        async def scenario():
            await _harden_shared_workers_async(browser, {"userAgent": _UA})
            await cdp.emit(
                "Target.receivedMessageFromTarget",
                _routed_event("nf", "Inspector.targetReloadedAfterCrash"),
            )

        asyncio.run(scenario())
        assert [(p, m["method"]) for p, m in _delivered(cdp)] == [
            (["nf"], "Runtime.runIfWaitingForDebugger")
        ]


class TestServiceWorkerScriptHoldByUrl:
    """A service worker's script fetch is held, by URL, while its override is sent.

    One registered by a cross-site iframe has no main-script throttle: with
    the override delayed 400ms (yielding to other events), 0 of 15 read the
    right high-entropy hints without this hold, 15 of 15 with it.
    """

    def _setup(self):
        browser_cdp = FakeCDP()
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = browser_cdp
        holder = FakeCDP()
        page = MagicMock()
        page.context.new_cdp_session.return_value = holder
        return page, browser, browser_cdp, holder

    def _sw_attached(self, url="https://x.test/sw.js"):
        event = _attached("flat", "service_worker", target_id="SW")
        event["targetInfo"]["url"] = url
        return event

    def test_the_script_waits_for_the_override(self):
        page, browser, browser_cdp, holder = self._setup()
        solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        channel = browser._wafer_channel

        def attach(params):
            # The fetch pauses while the override is in flight.
            command = channel.paused(
                {"requestId": "R", "request": {"url": "https://x.test/sw.js"}}
            )
            assert command is None
            return {"sessionId": "nf"}

        browser_cdp.responses["Target.attachToTarget"] = attach
        holder.emit("Target.attachedToTarget", self._sw_attached())
        release = ("Fetch.continueRequest", {"requestId": "R"})
        continued = browser_cdp.sent.index(release)
        overrides = [
            i
            for i, (method, _) in enumerate(browser_cdp.sent)
            if method == "Target.sendMessageToTarget"
        ]
        assert overrides and max(overrides) < continued
        assert channel.held_urls == {}

    def test_other_urls_and_later_fetches_continue_at_once(self):
        page, browser, browser_cdp, holder = self._setup()
        browser_cdp.responses["Target.attachToTarget"] = {"sessionId": "nf"}
        solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        channel = browser._wafer_channel
        assert channel.paused(
            {"requestId": "A", "request": {"url": "https://x.test/other.js"}}
        ) == ("Fetch.continueRequest", {"requestId": "A"})
        holder.emit("Target.attachedToTarget", self._sw_attached())
        assert channel.paused(
            {"requestId": "B", "request": {"url": "https://x.test/sw.js"}}
        ) == ("Fetch.continueRequest", {"requestId": "B"})

    def test_a_failed_override_still_releases_the_script(self):
        page, browser, browser_cdp, holder = self._setup()
        solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        channel = browser._wafer_channel

        def attach(params):
            channel.paused(
                {"requestId": "R", "request": {"url": "https://x.test/sw.js"}}
            )
            return {}  # no sessionId

        browser_cdp.responses["Target.attachToTarget"] = attach
        holder.emit("Target.attachedToTarget", self._sw_attached())
        assert ("Fetch.continueRequest", {"requestId": "R"}) in browser_cdp.sent
        assert channel.held_urls == {}

    def test_overlapping_holds_on_one_url_release_together_last(self):
        channel = solver_mod._BrowserChannel(FakeCDP())
        channel.hold_url("u")
        channel.hold_url("u")
        channel.paused({"requestId": "R", "request": {"url": "u"}})
        assert channel.release_url("u") == []
        assert channel.release_url("u") == ["R"]
        assert channel.release_url("u") == []


class TestServiceWorkerHold:
    """A flattened page session holds a service worker's script fetch.

    Patchright resumes every worker as it attaches, so pausing on start holds
    nothing; Chromium's main-script throttle does, but only for flattened
    sessions auto-attached under the registering page.
    """

    def _setup(self):
        browser_cdp = FakeCDP({"Target.attachToTarget": {"sessionId": "nf"}})
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = browser_cdp
        holder = FakeCDP()
        page = MagicMock()
        page.context.new_cdp_session.return_value = holder
        return page, browser, browser_cdp, holder

    def test_holds_only_service_workers_flattened(self):
        page, browser, _, holder = self._setup()
        assert solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        method, params = holder.sent[-1]
        assert method == "Target.setAutoAttach"
        assert params["flatten"] is True
        assert params["waitForDebuggerOnStart"] is True
        assert params["filter"][0] == {"type": "service_worker", "exclude": False}

    def test_overrides_from_the_browser_then_releases_the_fetch(self):
        page, browser, browser_cdp, holder = self._setup()
        solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        holder.emit("Target.attachedToTarget", _attached("flat", "service_worker"))
        attach = ("Target.attachToTarget", {"targetId": "T", "flatten": False})
        assert attach in browser_cdp.sent
        assert [(p, m["method"]) for p, m in _delivered(browser_cdp)] == [
            (["nf"], "Emulation.setUserAgentOverride"),
            (["nf"], "Network.setUserAgentOverride"),
        ]
        assert holder.sent[-1] == ("Target.detachFromTarget", {"sessionId": "flat"})

    def test_a_service_worker_shared_by_pages_is_overridden_once(self):
        page, browser, browser_cdp, holder = self._setup()
        solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        holder.emit("Target.attachedToTarget", _attached("flat", "service_worker"))
        assert len(_delivered(browser_cdp)) == 2
        # Both holders still release their hold.
        detaches = [c for c in holder.sent if c[0] == "Target.detachFromTarget"]
        assert len(detaches) == 2

    def test_no_browser_object_means_no_hold(self):
        page = MagicMock()
        assert not solver_mod._hold_service_workers(page, None, {"userAgent": _UA})
        page.context.new_cdp_session.assert_not_called()

    def test_the_page_auto_attach_leaves_held_service_workers_alone(self):
        method, params = solver_mod._root_auto_attach(True)
        assert params["flatten"] is False
        assert params["filter"][0] == {"type": "service_worker", "exclude": True}
        assert params["filter"][-1] == {}
        assert solver_mod._root_auto_attach(False) == _AUTO_ATTACH

    def test_headless_harden_page_holds_and_excludes(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        page_cdp = _page_cdp()
        holder = FakeCDP()
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = FakeCDP()
        page = _page(page_cdp, viewport={"width": 1440, "height": 900}, browser=browser)
        page.context.new_cdp_session.side_effect = [page_cdp, holder]
        harden_page(page, headless=True)
        assert holder.sent[-1][1]["flatten"] is True
        root = [p for m, p in page_cdp.sent if m == "Target.setAutoAttach"][-1]
        assert root["filter"][0] == {"type": "service_worker", "exclude": True}


class TestFallbackParity:
    def test_async_fallback_sends_what_the_sync_one_does(self):
        def run_sync():
            page, main, cdp = MagicMock(), MagicMock(), FakeCDP()
            page.main_frame = main
            handlers = {}
            page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)
            _install_init_script_fallback(page, ["A", "B"], cdp)
            handlers["framenavigated"](main)
            return cdp.sent

        async def run_async():
            page, main, cdp = MagicMock(), MagicMock(), AsyncFakeCDP()
            page.main_frame = main
            handlers = {}
            page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)
            await _install_init_script_fallback_async(page, ["A", "B"], cdp)
            await handlers["framenavigated"](main)
            return cdp.sent

        assert asyncio.run(run_async()) == run_sync()

    def test_screenxy_script_skips_a_document_it_already_patched(self):
        # The fallback re-applies it after the init script ran; a second
        # wrap can leave PointerEvent half-patched.
        assert "[native code]" in _SCREENXY_FIX_SCRIPT


# ---------------------------------------------------------------------------
# Identity and window checks
# ---------------------------------------------------------------------------


class TestBrowserIdentity:
    def test_reads_the_full_version_from_the_product(self):
        ua, version = _browser_identity(_VERSION, None, headless=True)
        assert (ua, version) == (_UA, "154.0.8037.98")

    def test_scrubs_the_browser_ua(self):
        ua, _ = _browser_identity(
            {"product": "Chrome/154.0.8037.98", "userAgent": _HEADLESS_UA},
            None,
            headless=True,
        )
        assert ua == _UA

    def test_warns_when_headless_launched_without_the_ua_switch(self, caplog):
        with caplog.at_level(logging.WARNING, logger="wafer"):
            _browser_identity(
                {"product": "Chrome/154.0.8037.98", "userAgent": _HEADLESS_UA},
                None,
                headless=True,
            )
        assert "hardened_launch_config(user_agent=...)" in caplog.text

    def test_warns_about_chrome_headless_shell(self, caplog):
        with caplog.at_level(logging.WARNING, logger="wafer"):
            _browser_identity(
                {"product": "HeadlessChrome/147.0.7727.15", "userAgent": _HEADLESS_UA},
                None,
                headless=True,
            )
        assert "chrome-headless-shell" in caplog.text

    def test_headed_never_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="wafer"):
            _browser_identity(_VERSION, None, headless=False)
        assert caplog.text == ""

    def test_no_ua_fails_loudly(self):
        with pytest.raises(RuntimeError, match="did not report a user agent"):
            _browser_identity({"product": "Chrome/154"}, None, headless=True)


class TestWindowState:
    def test_returns_the_viewport(self):
        state = json.dumps([1440, 900, 2])
        assert _check_window_state(state, headless=True, platform="darwin") == (
            1440,
            900,
        )

    def test_warns_about_a_non_retina_mac(self, caplog):
        with caplog.at_level(logging.WARNING, logger="wafer"):
            _check_window_state(
                json.dumps([1440, 900, 1]), headless=True, platform="darwin"
            )
        assert "device_scale_factor=2" in caplog.text

    def test_other_platforms_accept_any_ratio(self, caplog):
        with caplog.at_level(logging.WARNING, logger="wafer"):
            _check_window_state(
                json.dumps([1440, 900, 1]), headless=True, platform="linux"
            )
        assert caplog.text == ""

    def test_garbage_is_ignored(self):
        assert _check_window_state(None, headless=True, platform="darwin") is None


class TestNativeWindow:
    """The launch's real display, which needs no window script."""

    def test_the_launch_display_is_native(self):
        assert _native_window(_native_state()["result"]["value"])

    def test_viewport_emulation_is_not(self):
        # Emulation reports the viewport as the screen, with no menu bar.
        emulated = json.dumps([1440, 900, 2, 1440, 900, 1440, 0, 24])
        assert not _native_window(emulated)

    def test_a_window_with_no_toolbar_is_not(self):
        flat = json.dumps([1440, 900, 2, 1440, 900, 1710, 34, 30])
        assert not _native_window(flat)

    def test_the_old_three_value_state_and_garbage_are_not(self):
        assert not _native_window(json.dumps([1440, 900, 2]))
        assert not _native_window(None)
        assert not _native_window("not json")


# ---------------------------------------------------------------------------
# harden_page
# ---------------------------------------------------------------------------


def _page(cdp, *, viewport=None, browser=None):
    page = MagicMock()
    page._wafer_hardened = False
    page.viewport_size = viewport
    page.context.new_cdp_session.return_value = cdp
    page.context.browser = browser
    return page


def _page_cdp(window=None):
    return FakeCDP(
        {
            "Browser.getVersion": _VERSION,
            "Runtime.evaluate": window or _window_state(),
        }
    )


class TestHardenPage:
    def test_publishes_its_override_for_the_driver(self, monkeypatch):
        # The driver preload gives it to pages it sets up itself, popups
        # included, before their first document runs.
        published = []
        monkeypatch.setattr(
            solver_mod, "_publish_ua_override", lambda ua, p: published.append((ua, p))
        )
        harden_page(_page(_page_cdp(), viewport=None), headless=False)
        assert published and published[0][0] == _VERSION["userAgent"]
        assert published[0][1]["userAgentMetadata"]["fullVersionList"]

    def test_headless_page_gets_the_full_recipe(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        cdp = _page_cdp()
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = FakeCDP()
        page = _page(cdp, viewport={"width": 1440, "height": 900}, browser=browser)

        harden_page(page, headless=True)

        methods = cdp.methods()
        assert methods[:2] == ["Browser.getVersion", "Runtime.evaluate"]
        script = _headless_fix_script(_headless_geometry(1440, 900))
        assert ("Page.addScriptToEvaluateOnNewDocument", {"source": script}) in cdp.sent
        override = dict(cdp.sent)["Emulation.setUserAgentOverride"]
        assert override["userAgent"] == _UA
        assert override["userAgentMetadata"]["fullVersion"] == "154.0.8037.98"
        assert "Target.setAutoAttach" in methods
        # The scripts also reach the document already there, without a gesture.
        assert ("Runtime.evaluate", {"expression": script, "userGesture": False}) in (
            cdp.sent
        )
        browser.new_browser_cdp_session.assert_called_once()
        assert page._wafer_hardened is True

    def test_window_reads_never_grant_user_activation(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        cdp = _page_cdp()
        page = _page(cdp, viewport={"width": 1440, "height": 900})
        harden_page(page, headless=True)
        page.evaluate.assert_not_called()

    def test_headed_page_gets_no_window_patch_and_no_shared_worker_session(self):
        cdp = _page_cdp()
        browser = MagicMock(spec=["new_browser_cdp_session"])
        page = _page(cdp, browser=browser)
        harden_page(page, headless=False)
        assert "Page.addScriptToEvaluateOnNewDocument" not in cdp.methods()
        assert "Emulation.setUserAgentOverride" in cdp.methods()
        browser.new_browser_cdp_session.assert_not_called()

    def test_viewport_falls_back_to_the_measured_window(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        cdp = _page_cdp(_window_state(1280, 720, 2))
        page = _page(cdp, viewport=None)
        harden_page(page, headless=True)
        script = _headless_fix_script(_headless_geometry(1280, 720))
        assert ("Page.addScriptToEvaluateOnNewDocument", {"source": script}) in cdp.sent

    def test_explicit_ua_wins(self):
        cdp = _page_cdp()
        page = _page(cdp)
        harden_page(page, headless=False, user_agent="Mozilla/5.0 Chrome/154.0.0.0")
        override = dict(cdp.sent)["Emulation.setUserAgentOverride"]
        assert override["userAgent"] == "Mozilla/5.0 Chrome/154.0.0.0"

    def test_second_call_is_a_no_op(self):
        cdp = _page_cdp()
        page = _page(cdp)
        harden_page(page, headless=False)
        harden_page(page, headless=False)
        page.context.new_cdp_session.assert_called_once()

    def test_async_matches_sync(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        sync_cdp = _page_cdp()
        viewport = {"width": 1440, "height": 900}
        harden_page(_page(sync_cdp, viewport=viewport), headless=True)

        async_cdp = AsyncFakeCDP(
            {"Browser.getVersion": _VERSION, "Runtime.evaluate": _window_state()}
        )
        page = _page(async_cdp, viewport={"width": 1440, "height": 900})

        async def new_session(_page):
            return async_cdp

        page.context.new_cdp_session = new_session
        asyncio.run(harden_page_async(page, headless=True))
        assert async_cdp.sent == sync_cdp.sent


class TestSolverUsesTheSameRecipe:
    """BrowserSolver's per-page setup and harden_page must not drift apart.

    The solver decides two things harden_page does not: the screenX/Y script
    (from its real-input probe) and the Kasada/Akamai exclusion of the window
    patch. Everything else must match command for command.
    """

    def _solver_commands(self, *, headless, screenxy=False, challenge_type=None):
        solver = solver_mod.BrowserSolver(headless=headless)
        solver._browser_ua = _UA
        solver._browser_version = "154.0.8037.98"
        solver._needs_screenxy_patch = screenxy
        cdp = FakeCDP()
        page = _page(cdp, viewport={"width": 1440, "height": 900})
        page._wafer_headless_patched = False
        try:
            solver._setup_headless_patches(page, challenge_type=challenge_type)
        finally:
            solver.close()
        # The window-state read, which harden_page makes before its own
        # commands too (sliced off in _public_commands).
        state_read = (
            "Runtime.evaluate",
            {"expression": solver_mod._WINDOW_STATE, "returnByValue": True},
        )
        return [c for c in cdp.sent if c != state_read]

    def _public_commands(self, *, headless):
        cdp = _page_cdp()
        viewport = {"width": 1440, "height": 900} if headless else None
        harden_page(_page(cdp, viewport=viewport), headless=headless)
        # harden_page reads the identity first; the solver already holds it.
        return cdp.sent[2:]

    @pytest.mark.parametrize("headless", [True, False])
    def test_same_commands(self, monkeypatch, headless):
        monkeypatch.setattr(sys, "platform", "darwin")
        assert self._solver_commands(headless=headless) == self._public_commands(
            headless=headless
        )

    def test_screenxy_is_the_only_addition(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with_patch = self._solver_commands(headless=True, screenxy=True)
        added = [c for c in with_patch if c not in self._public_commands(headless=True)]
        assert added == [
            ("Page.addScriptToEvaluateOnNewDocument", {"source": _SCREENXY_FIX_SCRIPT}),
            (
                "Runtime.evaluate",
                {"expression": _SCREENXY_FIX_SCRIPT, "userGesture": False},
            ),
        ]

    @pytest.mark.parametrize(
        "challenge_type", [None, "kasada", "akamai", "datadome"]
    )
    def test_a_native_window_gets_no_window_script(self, monkeypatch, challenge_type):
        # The launch described the real display and the context has no
        # viewport emulation: every challenge type, Kasada and Akamai
        # included, gets the same native geometry and no script to detect.
        monkeypatch.setattr(sys, "platform", "darwin")
        solver = solver_mod.BrowserSolver(headless=True)
        solver._browser_ua = _UA
        solver._browser_version = "154.0.8037.98"
        solver._needs_screenxy_patch = False
        cdp = FakeCDP({"Runtime.evaluate": _native_state()})
        page = _page(cdp, viewport=None)
        page._wafer_headless_patched = False
        try:
            solver._setup_headless_patches(page, challenge_type=challenge_type)
        finally:
            solver.close()
        added = "Page.addScriptToEvaluateOnNewDocument"
        assert [p for m, p in cdp.sent if m == added] == []
        assert page._wafer_native_window is True
        assert page._wafer_window_patch is False

    def test_harden_page_on_a_native_window_adds_no_script(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        cdp = _page_cdp(_native_state())
        harden_page(_page(cdp, viewport=None), headless=True)
        methods = [m for m, _ in cdp.sent]
        assert "Page.addScriptToEvaluateOnNewDocument" not in methods
        assert "Emulation.setUserAgentOverride" in methods

    @pytest.mark.parametrize("challenge_type", ["kasada", "akamai"])
    def test_kasada_and_akamai_drop_only_the_window_patch(
        self, monkeypatch, challenge_type
    ):
        monkeypatch.setattr(sys, "platform", "darwin")
        sent = self._solver_commands(headless=True, challenge_type=challenge_type)
        public = self._public_commands(headless=True)
        window_patch = _headless_fix_script(_headless_geometry(1440, 900))
        assert [c for c in public if c not in sent] == [
            ("Page.addScriptToEvaluateOnNewDocument", {"source": window_patch}),
            ("Runtime.evaluate", {"expression": window_patch, "userGesture": False}),
        ]

    def test_headless_page_without_a_ua_fails_loudly(self):
        solver = solver_mod.BrowserSolver(headless=True)
        solver._browser_ua = None
        page = _page(FakeCDP(), viewport={"width": 1440, "height": 900})
        page._wafer_headless_patched = False
        try:
            with pytest.raises(RuntimeError, match="no user agent"):
                solver._setup_headless_patches(page)
        finally:
            solver.close()

    def test_binds_the_page_so_solver_sleeps_release_its_children(self):
        from wafer.browser import _pump

        solver = solver_mod.BrowserSolver(headless=False)
        solver._browser_ua = _UA
        page = _page(FakeCDP())
        page._wafer_headless_patched = False
        try:
            solver._setup_headless_patches(page)
            assert _pump._local.page is page
        finally:
            solver.close()


class TestQuietRead:
    """Solver reads of page state must not mark the page user-activated.

    Playwright sends every evaluation with userGesture: true, and Patchright
    evaluates in an isolated world that cannot see the page's patches.
    """

    def test_a_hardened_page_is_read_through_cdp_without_a_gesture(self):
        cdp = FakeCDP({"Runtime.evaluate": {"result": {"value": 42}}})
        page = MagicMock()
        solver_mod._PAGE_SESSIONS[page] = cdp
        assert solver_mod._quiet_read(page, "1 + 41") == 42
        method, params = cdp.sent[-1]
        assert method == "Runtime.evaluate"
        assert params["userGesture"] is False
        assert "contextId" not in params  # the page's own world
        page.evaluate.assert_not_called()

    def test_an_unhardened_page_falls_back_to_playwright(self):
        page = MagicMock()
        page.evaluate.return_value = 7
        assert solver_mod._quiet_read(page, "7") == 7
        page.evaluate.assert_called_once_with("7")

    def test_a_script_error_raises(self):
        cdp = FakeCDP(
            {"Runtime.evaluate": {"exceptionDetails": {"text": "ReferenceError"}}}
        )
        page = MagicMock()
        solver_mod._PAGE_SESSIONS[page] = cdp
        with pytest.raises(RuntimeError, match="ReferenceError"):
            solver_mod._quiet_read(page, "nope")

    def test_harden_page_registers_its_session(self):
        cdp = _page_cdp()
        page = _page(cdp)
        harden_page(page, headless=False)
        assert solver_mod._PAGE_SESSIONS.get(page) is cdp

    def test_the_patch_check_reads_quietly(self):
        cdp = FakeCDP({"Runtime.evaluate": {"result": {"value": [1442, 1440, 30]}}})
        page = MagicMock()
        page._wafer_patch_checked = False
        solver_mod._PAGE_SESSIONS[page] = cdp
        solver = solver_mod.BrowserSolver(headless=True)
        try:
            solver._verify_headless_patches(page)
        finally:
            solver.close()
        assert cdp.sent[-1][0] == "Runtime.evaluate"
        page.evaluate.assert_not_called()


class TestAcknowledgement:
    def test_only_a_recorded_reply_counts(self):
        # An id dropped from the bounded pending table was never answered.
        router = _TargetRouter()
        router.wrap(("a",), "Runtime.enable", {})
        first = router.last_id
        for _ in range(_MAX_PENDING_REPLIES + 5):
            router.wrap(("a",), "Runtime.enable", {})
        assert not router.answered(first)

    def test_a_detached_child_ends_the_wait(self):
        router = _TargetRouter()
        router.wrap(("s1",), "Runtime.enable", {})
        router._record(router.gone, "s1")
        cdp = FakeCDP()
        solver_mod._settle(cdp, router, [router.last_id], session_id="s1")
        assert cdp.sent == []

    def test_nested_detaches_are_recorded(self):
        router = _TargetRouter()
        event = {"method": "Target.detachedFromTarget", "params": {"sessionId": "s2"}}
        router.unwrap({"sessionId": "s1", "message": json.dumps(event)})
        assert "s2" in router.gone


class TestWorkerFailurePaths:
    def test_a_cancelled_channel_open_does_not_hang_later_pages(self):
        browser = MagicMock(spec=["new_browser_cdp_session"])
        calls = []

        async def opening():
            calls.append(1)
            if len(calls) == 1:
                raise asyncio.CancelledError
            return AsyncFakeCDP()

        browser.new_browser_cdp_session = opening

        async def scenario():
            with pytest.raises(asyncio.CancelledError):
                await solver_mod._browser_channel_async(browser)
            return await asyncio.wait_for(
                solver_mod._browser_channel_async(browser), timeout=1
            )

        assert isinstance(asyncio.run(scenario()), solver_mod._BrowserChannel)

    def test_a_failed_override_can_be_retried(self):
        browser_cdp = FakeCDP()
        browser_cdp.responses["Target.attachToTarget"] = lambda _: {}  # no sessionId
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = browser_cdp
        _harden_shared_workers(browser, {"userAgent": _UA})
        browser_cdp.emit("Target.attachedToTarget", _attached("flat", "shared_worker"))
        assert "T" not in browser._wafer_channel.handled

    def test_a_holder_that_cannot_attach_is_detached(self):
        browser = MagicMock(spec=["new_browser_cdp_session"])
        browser.new_browser_cdp_session.return_value = FakeCDP()
        holder = MagicMock()
        holder.send.side_effect = RuntimeError("closed")
        page = MagicMock()
        page.context.new_cdp_session.return_value = holder
        assert not solver_mod._hold_service_workers(page, browser, {"userAgent": _UA})
        holder.detach.assert_called_once()


class TestPopups:
    """A popup is hardened as soon as it appears.

    Its first document cannot be held (Patchright resumes the new tab), but
    every later navigation and anything read after hardening is right.
    """

    def test_harden_page_hardens_popups(self):
        cdp = _page_cdp()
        page = _page(cdp)
        handlers = {}
        page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)
        harden_page(page, headless=False)

        popup_cdp = _page_cdp()
        popup = _page(popup_cdp)
        handlers["popup"](popup)
        assert popup._wafer_hardened is True
        assert "Emulation.setUserAgentOverride" in popup_cdp.methods()

    def test_a_failing_popup_harden_is_swallowed(self):
        page = MagicMock()
        handlers = {}
        page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)

        def boom(_popup):
            raise RuntimeError("closed")

        solver_mod._harden_popups(page, boom)
        handlers["popup"](MagicMock())  # must not raise into Playwright

    def test_the_solver_hardens_its_popups(self):
        solver = solver_mod.BrowserSolver(headless=False)
        solver._browser_ua = _UA
        page = _page(FakeCDP())
        page._wafer_headless_patched = False
        handlers = {}
        page.on.side_effect = lambda ev, fn: handlers.__setitem__(ev, fn)
        try:
            solver._setup_headless_patches(page)
            popup = _page(FakeCDP())
            popup._wafer_headless_patched = False
            handlers["popup"](popup)
            assert popup._wafer_headless_patched is True
        finally:
            solver.close()
