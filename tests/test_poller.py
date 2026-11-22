"""Unit tests for the watch loop's state + pagination (no network).
Run:  python -m unittest discover -s tests -t ."""
import os
import tempfile
import unittest
from unittest import mock

import tfc_agent as ag


class FakeTFC:
    def __init__(self, pages, reviewed=()):
        self.pages = pages              # list of lists of run ids, newest first
        self.reviewed_marker = set(reviewed)
        self.calls = []

    def api(self, method, path, body=None):
        self.calls.append(path)
        if "/runs?" in path:
            n = int(path.split("page%5Bnumber%5D=")[1].split("&")[0])
            data = [{"id": r} for r in self.pages[n - 1]] if n <= len(self.pages) else []
            nxt = n + 1 if n < len(self.pages) else None
            return {"data": data, "meta": {"pagination": {"next-page": nxt}}}
        raise AssertionError(path)


class Poller(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")

    def run_poll(self, fake, state, review=None):
        review = review or (lambda rid, post, skip_if_done: ({"findings": []}, "md"))
        with mock.patch.object(ag, "api", fake.api), mock.patch.object(ag, "review_run", side_effect=review):
            return ag.poll_workspace("ws", "ws-1", state, log=lambda m: None)

    def test_paginates_and_persists(self):
        fake = FakeTFC([["r5", "r4"], ["r3", "r2"], ["r1"]])
        state = ag.State(self.path)
        self.assertEqual(self.run_poll(fake, state), ["r5", "r4", "r3", "r2", "r1"])
        # restart: nothing re-reviewed, and paging stops at the first page with a known run
        state2 = ag.State(self.path)
        fake2 = FakeTFC([["r6", "r5"], ["r4", "r3"]])
        self.assertEqual(self.run_poll(fake2, state2), ["r6"])
        self.assertEqual(sum("/runs?" in c for c in fake2.calls), 1)

    def test_marker_says_done_means_marked_without_comment(self):
        state = ag.State(self.path)
        self.assertEqual(self.run_poll(FakeTFC([["r1"]]), state, lambda *a, **k: None), [])
        self.assertIn("r1", state.known("ws-1"))

    def test_gives_up_after_repeated_failures(self):
        state = ag.State(self.path)

        def boom(*a, **k):
            raise RuntimeError("plan json gone")
        for _ in range(ag.MAX_FAILURES - 1):
            self.run_poll(FakeTFC([["r1"]]), state, boom)
            self.assertNotIn("r1", state.known("ws-1"))
        self.run_poll(FakeTFC([["r1"]]), state, boom)
        self.assertIn("r1", state.known("ws-1"))

    def test_corrupt_state_file(self):
        with open(self.path, "w") as fh:
            fh.write("{not json")
        with mock.patch("sys.stderr"):
            self.assertEqual(ag.State(self.path).reviewed, {})

    def test_post_apply_statuses_are_reviewable(self):
        self.assertIn("applied", ag.REVIEWABLE)
        self.assertIn("applying", ag.REVIEWABLE)


if __name__ == "__main__":
    unittest.main()
