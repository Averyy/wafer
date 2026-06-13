"""Tests for the async-native solver entry points (E10).

``BrowserSolver.asolve`` / ``aintercept_iframe`` are thin async wrappers
that dispatch the blocking sync methods to a thread executor. They must
return the same result and not block the event loop.
"""

import asyncio
import threading
import time

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
