import sys
import pathlib
import unittest

# Make repo root importable no matter where this test is run from.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nftrace_story import (
    build_stories,
    parse_trace_lines,
    summarize_trace_ids,
    _parse_filter_arg,
    _trace_matches_filter,
)


class TestNftraceStory(unittest.TestCase):
    def test_example_trace_parses_and_renders(self) -> None:
        # Accept either sample file name
        candidates = sorted(REPO_ROOT.glob("example*.trace"))
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

    def test_filter_matches_at_least_one_trace(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        candidates = sorted(repo_root.glob("example*.trace"))
        self.assertTrue(candidates, "expected an example*.trace file in repo root")
        trace_path = candidates[0]
        events = parse_trace_lines(trace_path.read_text(encoding="utf-8", errors="replace").splitlines())

        # Build a filter from the first packet event so it should match.
        pkt = next(e for e in events if e.pkt.ip_saddr and e.pkt.ip_daddr)
        src = pkt.pkt.ip_saddr
        dst = pkt.pkt.ip_daddr
        # use dport if available, otherwise just match by addr
        dport = pkt.pkt.tcp_dport or pkt.pkt.udp_dport
        if dport is None:
            crit = _parse_filter_arg(f"srcaddr={src},dstaddr={dst}")
        else:
            crit = _parse_filter_arg(f"srcaddr={src},dstaddr={dst},dstport={dport}")

        # Group by trace id and ensure at least one group matches
        by_id: dict[str, list] = {}
        for e in events:
            by_id.setdefault(e.trace_id, []).append(e)
        self.assertTrue(any(_trace_matches_filter(evs, crit) for tid, evs in by_id.items() if tid != "(unparsed)"))

    def test_filter_validation(self) -> None:
        with self.assertRaises(ValueError):
            _parse_filter_arg("srcaddr=999.999.999.999")
        with self.assertRaises(ValueError):
            _parse_filter_arg("dstport=0")
        with self.assertRaises(ValueError):
            _parse_filter_arg("dstport=70000")
        # verdict filter is for final disposition (accept/drop/reject)
        _parse_filter_arg("verdict=accept")
        _parse_filter_arg("verdict=drop")
        _parse_filter_arg("verdict=reject")
        with self.assertRaises(ValueError):
            _parse_filter_arg("verdict=continue")

if __name__ == "__main__":
    unittest.main()

