"""Browser-solver lifecycle: sessions only close solvers they own.

A BrowserSolver passed in via browser_solver= is shared - the caller
owns its lifecycle, and __exit__/__aexit__ must NOT close it (closing
would tear it down for every other session holding it). wafer never
auto-creates a solver today, so _owns_solver is False unless a future
internal path sets it.
"""

import wafer
from tests.conftest import (
    MockResponse,
    make_async_session,
    make_sync_session,
)


class FakeSolver:
    def __init__(self):
        self.close_calls = 0

    def close(self):
        self.close_calls += 1


def ok():
    return MockResponse(200, {"content-type": "text/html"}, "ok")


class TestSyncSolverOwnership:
    def test_exit_does_not_close_passed_in_solver(self):
        solver = FakeSolver()
        session, _ = make_sync_session([ok()], browser_solver=solver)
        with session:
            pass
        assert solver.close_calls == 0

    def test_exit_closes_owned_solver(self):
        solver = FakeSolver()
        session, _ = make_sync_session(
            [ok()], browser_solver=solver, owns_solver=True,
        )
        with session:
            pass
        assert solver.close_calls == 1

    def test_constructor_marks_passed_in_solver_unowned(self):
        solver = FakeSolver()
        with wafer.SyncSession(browser_solver=solver) as session:
            assert session._owns_solver is False
        assert solver.close_calls == 0

    def test_shared_solver_survives_repeated_context_use(self):
        """Callers can safely reuse the session (and the solver) after
        a with-block - the previous footgun this guards against."""
        solver = FakeSolver()
        session, _ = make_sync_session([ok()], browser_solver=solver)
        with session:
            pass
        with session:
            pass
        assert solver.close_calls == 0


class TestAsyncSolverOwnership:
    async def test_aexit_does_not_close_passed_in_solver(self):
        solver = FakeSolver()
        session, _ = make_async_session([ok()], browser_solver=solver)
        async with session:
            pass
        assert solver.close_calls == 0

    async def test_aexit_closes_owned_solver(self):
        solver = FakeSolver()
        session, _ = make_async_session(
            [ok()], browser_solver=solver, owns_solver=True,
        )
        async with session:
            pass
        assert solver.close_calls == 1

    async def test_constructor_marks_passed_in_solver_unowned(self):
        solver = FakeSolver()
        session = wafer.AsyncSession(browser_solver=solver)
        assert session._owns_solver is False
        async with session:
            pass
        assert solver.close_calls == 0
