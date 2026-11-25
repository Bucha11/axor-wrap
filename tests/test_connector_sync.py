"""PlaneConnector from a synchronous agent: start() and submit()."""
from __future__ import annotations

import asyncio
import unittest

from axor_wrap.connect import PlaneConnector


class SyncAgentTest(unittest.TestCase):
    def test_submit_runs_on_the_nodes_own_loop(self) -> None:
        node = PlaneConnector("http://127.0.0.1:1", "n-sync")
        pending = asyncio.sleep(0)
        with self.assertRaises(RuntimeError):
            node.submit(pending)
        pending.close()
        try:
            import httpx  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest("the plane extra is not installed")
        node.start()
        try:
            self.assertIs(node.start(), node)  # idempotent
            seen: list[object] = []

            async def where() -> int:
                seen.append(asyncio.get_running_loop())
                return 7

            self.assertEqual(node.submit(where()), 7)
            self.assertIs(seen[0], node._loop)
            self.assertTrue(node.admit())  # a live session, from plain code
        finally:
            node.stop()


if __name__ == "__main__":
    unittest.main()
