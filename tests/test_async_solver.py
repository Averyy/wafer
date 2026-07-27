"""Tests for the async-native solver entry points (E10).

``BrowserSolver.asolve`` / ``aintercept_iframe`` are thin async wrappers
that dispatch the blocking sync methods to a thread executor. They must
return the same result and not block the event loop.
"""

import asyncio
import threading
import time

import pytest

from wafer.browser._solver import BrowserSolver, InterceptResult, SolveResult


class _RecordingSolver(BrowserSolver):
    """BrowserSolver whose blocking methods are replaced by stubs.

    Each stub sleeps briefly (so we can prove the loop isn't blocked) and
    records the calling thread + the args it received.
    """

    def __init__(self):
        super().__init__()
        self.solve_calls = []
        self.intercept_calls = []
        self.solve_thread = None
        self.intercept_thread = None

    def solve(
        self,
        url,
        challenge_type=None,
        timeout=None,
        embedder=None,
        replay=None,
    ):
        self.solve_thread = threading.current_thread()
        self.solve_calls.append(
            (url, challenge_type, timeout, embedder, replay)
        )
        time.sleep(0.05)  # simulate a blocking solve
        return SolveResult(
            cookies=[{"name": "k", "value": "v"}],
            user_agent="UA",
        )

    def intercept_iframe(self, embedder_url, target_domain, timeout=None):
        self.intercept_thread = threading.current_thread()
        self.intercept_calls.append((embedder_url, target_domain, timeout))
        time.sleep(0.05)
        return InterceptResult(cookies=[], responses=[], user_agent="UA")


def test_asolve_returns_same_result_as_solve():
    solver = _RecordingSolver()
    sync_result = solver.solve("https://x.test", "cloudflare", 12.0)
    async_result = asyncio.run(
        solver.asolve("https://x.test", "cloudflare", 12.0)
    )
    assert isinstance(async_result, SolveResult)
    assert async_result.cookies == sync_result.cookies
    assert async_result.user_agent == sync_result.user_agent


def test_asolve_forwards_all_args():
    solver = _RecordingSolver()
    replay = {"method": "POST", "body": b"x", "content_type": "text/plain"}
    asyncio.run(
        solver.asolve(
            "https://api.test/data",
            challenge_type="imperva",
            timeout=7.5,
            embedder="https://www.test/",
            replay=replay,
        )
    )
    assert solver.solve_calls[-1] == (
        "https://api.test/data",
        "imperva",
        7.5,
        "https://www.test/",
        replay,
    )


def test_asolve_omits_max_size_for_legacy_solve_override():
    solver = _RecordingSolver()

    result = asyncio.run(
        solver.asolve(
            "https://x.test",
            "tmd",
            timeout=1.0,
            max_size=123,
        )
    )

    assert isinstance(result, SolveResult)
    assert solver.solve_calls[-1] == (
        "https://x.test",
        "tmd",
        1.0,
        None,
        None,
    )


def test_asolve_forwards_max_size_to_compatible_solve_override():
    class _SizeAwareSolver(_RecordingSolver):
        def __init__(self):
            super().__init__()
            self.max_sizes = []

        def solve(
            self,
            url,
            challenge_type=None,
            timeout=None,
            embedder=None,
            replay=None,
            *,
            max_size=None,
        ):
            self.max_sizes.append(max_size)
            return super().solve(
                url,
                challenge_type,
                timeout,
                embedder,
                replay,
            )

    solver = _SizeAwareSolver()

    result = asyncio.run(
        solver.asolve(
            "https://x.test",
            "tmd",
            timeout=1.0,
            max_size=123,
        )
    )

    assert isinstance(result, SolveResult)
    assert solver.max_sizes == [123]


@pytest.mark.parametrize("max_size", [None, 123])
def test_asolve_honors_instance_solve_override(max_size):
    solver = BrowserSolver()
    calls = []

    def solve_override(*args, **kwargs):
        calls.append((args, kwargs))
        return "instance-result"

    solver.solve = solve_override
    solver._solve_on_worker = lambda *_args, **_kwargs: "base-result"

    result = asyncio.run(
        solver.asolve(
            "https://x.test",
            "tmd",
            timeout=1.0,
            max_size=max_size,
        )
    )

    assert result == "instance-result"
    assert calls == [
        (
            ("https://x.test", "tmd", 1.0, None, None),
            {} if max_size is None else {"max_size": max_size},
        )
    ]


def test_asolve_runs_in_a_worker_thread():
    solver = _RecordingSolver()

    async def run():
        main_thread = threading.current_thread()
        await solver.asolve("https://x.test")
        return main_thread

    main_thread = asyncio.run(run())
    # The blocking solve ran off the event-loop thread.
    assert solver.solve_thread is not None
    assert solver.solve_thread is not main_thread


def test_asolve_does_not_block_event_loop():
    """A concurrent coroutine makes progress while asolve runs."""
    solver = _RecordingSolver()
    ticks = []

    async def ticker():
        for _ in range(5):
            ticks.append(time.monotonic())
            await asyncio.sleep(0.005)

    async def run():
        await asyncio.gather(
            solver.asolve("https://x.test"),
            ticker(),
        )

    asyncio.run(run())
    # The ticker kept running concurrently with the 0.05s blocking solve;
    # if asolve had blocked the loop, the ticker could not have ticked 5x.
    assert len(ticks) == 5


def test_aintercept_iframe_returns_same_result():
    solver = _RecordingSolver()
    sync_result = solver.intercept_iframe("https://page.test", "tile.test")
    async_result = asyncio.run(
        solver.aintercept_iframe("https://page.test", "tile.test")
    )
    assert isinstance(async_result, InterceptResult)
    assert async_result.cookies == sync_result.cookies
    assert async_result.responses == sync_result.responses


def test_aintercept_iframe_forwards_args_and_threads():
    solver = _RecordingSolver()

    async def run():
        main_thread = threading.current_thread()
        await solver.aintercept_iframe(
            "https://page.test", "tile.test", timeout=9.0
        )
        return main_thread

    main_thread = asyncio.run(run())
    assert solver.intercept_calls[-1] == (
        "https://page.test",
        "tile.test",
        9.0,
    )
    assert solver.intercept_thread is not main_thread


def test_aintercept_iframe_recovers_worker_on_caller_cancellation():
    """Caller cancellation must release the serial worker.

    ``asolve`` recovers on ``CancelledError``; without the same handling on
    ``aintercept_iframe`` the submitted operation keeps running and every
    later solve on this solver blocks behind it.
    """
    solver = BrowserSolver()
    started = threading.Event()
    release = threading.Event()
    recovered = []

    def blocking_intercept(*_args, **_kwargs):
        started.set()
        release.wait(timeout=5)
        return InterceptResult(cookies=[], responses=[], user_agent="UA")

    solver.intercept_iframe = blocking_intercept
    solver._recover_timed_out_worker = lambda future: recovered.append(future)

    async def run():
        task = asyncio.ensure_future(
            solver.aintercept_iframe("https://page.test", "tile.test", timeout=30)
        )
        await asyncio.get_running_loop().run_in_executor(None, started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(run())
        assert len(recovered) == 1
    finally:
        release.set()
        solver.close(timeout=1)


def test_aintercept_iframe_honors_instance_override():
    solver = BrowserSolver()
    calls = []

    def intercept_override(*args):
        calls.append(args)
        return "instance-result"

    solver.intercept_iframe = intercept_override
    solver._intercept_iframe_on_worker = (
        lambda *_args, **_kwargs: "base-result"
    )

    result = asyncio.run(
        solver.aintercept_iframe(
            "https://page.test",
            "tile.test",
            timeout=1.0,
        )
    )

    assert result == "instance-result"
    assert calls == [
        ("https://page.test", "tile.test", 1.0),
    ]
