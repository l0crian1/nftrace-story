import pathlib
import unittest

from nftrace_story import build_stories, parse_trace_lines, render_packets_only, summarize_trace_ids


class TestNftraceStory(unittest.TestCase):
    def test_example_trace_parses_and_renders(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        # Accept either sample file name
        candidates = sorted(repo_root.glob("example*.trace"))
        self.assertTrue(candidates, "expected an example*.trace file in repo root")
        trace_path = candidates[0]
        text = trace_path.read_text(encoding="utf-8", errors="replace")

        events = parse_trace_lines(text.splitlines())
        self.assertTrue(events)
        # Pick a real trace id from the file (don't hardcode).
        ids = [e.trace_id for e in events if e.trace_id != "(unparsed)"]
        self.assertTrue(ids)
        tid = ids[0]

        out = build_stories(events, markdown=False)
        self.assertIn(f"Trace {tid}", out)

        # Smoke test the other output modes.
        ids_out = summarize_trace_ids(events, markdown=False)
        self.assertIn(tid, ids_out)
        pkts_out = render_packets_only(events, markdown=False)
        self.assertIn(f"id={tid}", pkts_out)


if __name__ == "__main__":
    unittest.main()

