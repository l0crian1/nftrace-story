#!/usr/bin/env python3
"""
nftrace_story.py

Parse `nft monitor trace` / nftrace-style output and render a human-readable
"story" of what happened to a packet.

No external dependencies (stdlib only).
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from collections import defaultdict
from typing import Iterable, List, Optional, Sequence, Tuple


TRACE_BASE_RE = re.compile(
    r"""
    \btrace\s+id\s+(?P<trace_id>[0-9a-fA-F]+)\s+
    (?P<family>\S+)\s+
    (?P<table>\S+)\s+
    (?P<chain>\S+)\s+
    (?P<rest>.*)
    $""",
    re.VERBOSE,
)


def _strip_optional_line_number_prefix(line: str) -> str:
    """
    Some tools export lines prefixed with "L12:" (e.g. editor copy/paste).
    Treat that as metadata and ignore it.
    """

    m = re.match(r"^\s*L\d+:(.*)$", line)
    return m.group(1).lstrip() if m else line


def _m(payload: str, pattern: str) -> Optional[str]:
    m = re.search(pattern, payload)
    return m.group(1) if m else None


@dataclasses.dataclass(frozen=True)
class PacketView:
    iif: Optional[str] = None
    oif: Optional[str] = None
    ether_saddr: Optional[str] = None
    ether_daddr: Optional[str] = None
    ip_saddr: Optional[str] = None
    ip_daddr: Optional[str] = None
    ip_protocol: Optional[str] = None
    ip_length: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None
    ip_dscp: Optional[str] = None
    ip_ecn: Optional[str] = None
    tcp_sport: Optional[int] = None
    tcp_dport: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_window: Optional[int] = None
    udp_sport: Optional[int] = None
    udp_dport: Optional[int] = None

    @staticmethod
    def from_payload(payload: str) -> "PacketView":
        def _int(v: Optional[str]) -> Optional[int]:
            if v is None:
                return None
            try:
                return int(v)
            except ValueError:
                return None

        return PacketView(
            iif=_m(payload, r'\biif\s+"([^"]+)"'),
            oif=_m(payload, r'\boif\s+"([^"]+)"'),
            ether_saddr=_m(payload, r"\bether\s+saddr\s+([0-9a-fA-F:]{17})\b"),
            ether_daddr=_m(payload, r"\bether\s+daddr\s+([0-9a-fA-F:]{17})\b"),
            ip_saddr=_m(payload, r"\bip\s+saddr\s+(\S+)\b"),
            ip_daddr=_m(payload, r"\bip\s+daddr\s+(\S+)\b"),
            ip_protocol=_m(payload, r"\bip\s+protocol\s+(\S+)\b"),
            ip_length=_int(_m(payload, r"\bip\s+length\s+(\d+)\b")),
            ip_ttl=_int(_m(payload, r"\bip\s+ttl\s+(\d+)\b")),
            ip_id=_int(_m(payload, r"\bip\s+id\s+(\d+)\b")),
            ip_dscp=_m(payload, r"\bip\s+dscp\s+(\S+)\b"),
            ip_ecn=_m(payload, r"\bip\s+ecn\s+(\S+)\b"),
            tcp_sport=_int(_m(payload, r"\btcp\s+sport\s+(\d+)\b")),
            tcp_dport=_int(_m(payload, r"\btcp\s+dport\s+(\d+)\b")),
            tcp_flags=_m(payload, r"\btcp\s+flags\s+==\s+(\S+)\b"),
            tcp_window=_int(_m(payload, r"\btcp\s+window\s+(\d+)\b")),
            udp_sport=_int(_m(payload, r"\budp\s+sport\s+(\d+)\b")),
            udp_dport=_int(_m(payload, r"\budp\s+dport\s+(\d+)\b")),
        )


@dataclasses.dataclass(frozen=True)
class TraceEvent:
    line_no: int
    raw: str
    trace_id: str
    family: str
    table: str
    chain: str
    payload: str
    pkt: PacketView

    @property
    def hook_hint(self) -> Optional[str]:
        """
        Best-effort inference of the netfilter hook based on common chain names.
        """
        c = self.chain.upper()
        if "PREROUTING" in c or c == "PREROUTING":
            return "PREROUTING"
        if "POSTROUTING" in c or c == "POSTROUTING":
            return "POSTROUTING"
        if c == "FORWARD" or "FORWARD" in c:
            return "FORWARD"
        if c == "INPUT" or "INPUT" in c:
            return "INPUT"
        if c == "OUTPUT" or "OUTPUT" in c:
            return "OUTPUT"
        return None


def parse_trace_lines(lines: Iterable[str], *, include_nontrace_lines: bool = False) -> List[TraceEvent]:
    events: List[TraceEvent] = []
    for idx, raw in enumerate(lines, start=1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            continue

        line = _strip_optional_line_number_prefix(raw).strip()
        m = TRACE_BASE_RE.search(line)
        if not m:
            if include_nontrace_lines:
                # Keep non-trace lines under a synthetic trace_id.
                events.append(
                    TraceEvent(
                        line_no=idx,
                        raw=raw,
                        trace_id="(unparsed)",
                        family="?",
                        table="?",
                        chain="?",
                        payload=line,
                        pkt=PacketView.from_payload(line),
                    )
                )
            continue

        rest = (m.group("rest") or "").strip()
        payload = rest
        if rest.lower().startswith("packet:"):
            payload = rest[len("packet:") :].strip()
        events.append(
            TraceEvent(
                line_no=idx,
                raw=raw,
                trace_id=m.group("trace_id"),
                family=m.group("family"),
                table=m.group("table"),
                chain=m.group("chain"),
                payload=payload,
                pkt=PacketView.from_payload(payload),
            )
        )
    return events


def _flow_tuple(pkt: PacketView) -> Optional[str]:
    if not pkt.ip_saddr or not pkt.ip_daddr:
        return None

    proto = (pkt.ip_protocol or "").lower()
    if proto == "tcp" and pkt.tcp_sport is not None and pkt.tcp_dport is not None:
        return f"tcp {pkt.ip_saddr}:{pkt.tcp_sport} → {pkt.ip_daddr}:{pkt.tcp_dport}"
    if proto == "udp" and pkt.udp_sport is not None and pkt.udp_dport is not None:
        return f"udp {pkt.ip_saddr}:{pkt.udp_sport} → {pkt.ip_daddr}:{pkt.udp_dport}"
    if proto:
        return f"{proto} {pkt.ip_saddr} → {pkt.ip_daddr}"
    return f"{pkt.ip_saddr} → {pkt.ip_daddr}"


def _primary_event(events: Sequence[TraceEvent]) -> TraceEvent:
    """
    Best-effort choice for "the packet" for a given trace id.
    Prefer a packet-like event with ip saddr/daddr so we can build a flow string.
    """
    if not events:
        raise ValueError("events must be non-empty")
    return next((e for e in events if e.pkt.ip_saddr and e.pkt.ip_daddr), events[0])


def _format_packet_one_line(e: TraceEvent) -> str:
    """
    A compact per-packet view suitable for selecting a trace id.
    """
    flow = _flow_tuple(e.pkt) or "(no ip flow)"
    bits: List[str] = [f"L{e.line_no}", f"id={e.trace_id}", flow]
    if e.pkt.iif:
        bits.append(f'iif="{e.pkt.iif}"')
    if e.pkt.oif:
        bits.append(f'oif="{e.pkt.oif}"')
    if e.pkt.ip_ttl is not None:
        bits.append(f"ttl={e.pkt.ip_ttl}")
    if e.pkt.ip_length is not None:
        bits.append(f"len={e.pkt.ip_length}")
    if e.pkt.tcp_flags:
        bits.append(f"tcp_flags={e.pkt.tcp_flags}")
    return " | ".join(bits)


def _format_event_short(e: TraceEvent) -> str:
    parts: List[str] = []
    where = f"{e.family} {e.table} {e.chain}"
    parts.append(where)

    if e.pkt.iif:
        parts.append(f'iif="{e.pkt.iif}"')
    if e.pkt.oif:
        parts.append(f'oif="{e.pkt.oif}"')
    if e.pkt.ip_ttl is not None:
        parts.append(f"ttl={e.pkt.ip_ttl}")

    return " | ".join(parts)


def story_for_trace(
    events: List[TraceEvent], *, markdown: bool = False, include_timeline: bool = True
) -> str:
    """
    Produce a story for a single trace id.
    """
    if not events:
        return ""

    # Prefer a "packet-like" event for story metadata (flow/ingress),
    # since traces can include many non-packet lines (rule/verdict/policy).
    first = next((e for e in events if e.trace_id != "(unparsed)"), events[0])
    primary = next((e for e in events if e.pkt.ip_saddr and e.pkt.ip_daddr), first)
    flow = _flow_tuple(primary.pkt)

    # Detect key transitions for "story" callouts
    iif0 = primary.pkt.iif
    oif_first = next((e.pkt.oif for e in events if e.pkt.oif), None)
    last = events[-1]
    last_hook = next((e.hook_hint for e in reversed(events) if e.hook_hint), None)
    ttl_changes: List[Tuple[int, int, int]] = []  # (line_no, prev, curr)
    prev_ttl: Optional[int] = None
    for e in events:
        ttl = e.pkt.ip_ttl
        if ttl is None:
            continue
        if prev_ttl is not None and ttl != prev_ttl:
            ttl_changes.append((e.line_no, prev_ttl, ttl))
        prev_ttl = ttl

    table_order: List[str] = []
    table_chains: dict[str, List[str]] = {}
    for e in events:
        t = e.table
        if t == "?":
            continue
        if t not in table_chains:
            table_chains[t] = []
            table_order.append(t)

        c = e.chain
        if c != "?" and c not in table_chains[t]:
            table_chains[t].append(c)

    # Verdict / disposition (accept/drop/reject) and NAT-ish flow changes.
    disposition_re = re.compile(
        r"""
        (?:
            \(verdict\s+(?P<v1>accept|drop|reject)\b |
            \bverdict\s+(?P<v2>accept|drop|reject)\b |
            \bpolicy\s+(?P<v3>accept|drop|reject)\b
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    final_disposition: Optional[Tuple[int, str]] = None  # (line_no, verdict)
    for e in events:
        m = disposition_re.search(e.payload)
        if m:
            verdict = (m.group("v1") or m.group("v2") or m.group("v3") or "").lower()
            if verdict:
                final_disposition = (e.line_no, verdict)

    def pkt_tuple(p: PacketView) -> Optional[Tuple[str, str, str, Optional[int], Optional[int]]]:
        if not p.ip_saddr or not p.ip_daddr:
            return None
        proto = (p.ip_protocol or "").lower()
        if proto == "tcp":
            return (p.ip_saddr, p.ip_daddr, proto, p.tcp_sport, p.tcp_dport)
        if proto == "udp":
            return (p.ip_saddr, p.ip_daddr, proto, p.udp_sport, p.udp_dport)
        return (p.ip_saddr, p.ip_daddr, proto, None, None)

    pkt_changes: List[Tuple[int, Tuple[str, str, str, Optional[int], Optional[int]], Tuple[str, str, str, Optional[int], Optional[int]]]] = []
    prev_pt: Optional[Tuple[str, str, str, Optional[int], Optional[int]]] = None
    for e in events:
        pt = pkt_tuple(e.pkt)
        if pt is None:
            continue
        if prev_pt is not None and pt != prev_pt:
            pkt_changes.append((e.line_no, prev_pt, pt))
            if len(pkt_changes) >= 3:
                break
        prev_pt = pt

    def _story_lines(*, as_markdown: bool) -> List[str]:
        """
        Pre-formatted lines for the Story section.

        - Markdown mode returns proper markdown bullets (including nested bullets).
        - Text mode returns "- " / "  - " bullets; the caller can indent if desired.
        """
        top = "- " if as_markdown else "- "
        sub = "  - " if as_markdown else "  - "

        lines: List[str] = []
        subject = flow or "Packet"
        if iif0:
            lines.append(f'{top}{subject} arrived on interface "{iif0}".')
        else:
            lines.append(f"{top}{subject} appeared in nftrace output.")

        if oif_first:
            lines.append(f'{top}Routing selected egress interface "{oif_first}" (forwarding path).')

        # Most common forwarding signature is TTL decrement by 1.
        for ln, a, b in ttl_changes:
            if a - b == 1:
                lines.append(f"{top}TTL was decremented by 1 at L{ln} (typical for forwarding).")
                break

        if last_hook:
            lines.append(f"{top}It was last observed near the {last_hook} hook (L{last.line_no}).")
        else:
            lines.append(f"{top}It was last observed at L{last.line_no}.")

        if final_disposition:
            ln, verdict = final_disposition
            lines.append(f"{top}Final disposition: {verdict.upper()} (L{ln}).")

        if pkt_changes:
            ln, a, b = pkt_changes[0]
            a_s, a_d, a_p, a_sp, a_dp = a
            b_s, b_d, b_p, b_sp, b_dp = b
            if a_p == b_p:
                if a_sp is not None and a_dp is not None and b_sp is not None and b_dp is not None:
                    lines.append(
                        f"{top}Flow changed at L{ln}: {a_p} {a_s}:{a_sp} → {a_d}:{a_dp} became {b_s}:{b_sp} → {b_d}:{b_dp}."
                    )
                else:
                    lines.append(f"{top}Addresses changed at L{ln}: {a_s} → {a_d} became {b_s} → {b_d}.")
            else:
                lines.append(f"{top}Packet headers changed at L{ln} (possible NAT/rewrite).")

        if table_order:
            lines.append(f"{top}Tables visited:")
            for t in table_order:
                chains = table_chains.get(t) or []
                if as_markdown:
                    t_disp = f"`{t}`"
                else:
                    t_disp = t
                if chains:
                    lines.append(f"{sub}{t_disp}: " + ", ".join(chains))
                else:
                    lines.append(f"{sub}{t_disp}")
        return lines

    # Build output
    out: List[str] = []
    title = f"Trace {events[0].trace_id}" if events[0].trace_id != "(unparsed)" else "Trace (unparsed)"
    if markdown:
        out.append(f"## {title}")
        out.append("")
        out.append("### Story")
        out.extend(_story_lines(as_markdown=True))
        out.append("")
        if flow:
            out.append(f"- **Flow**: {flow}")
        if iif0:
            out.append(f'- **Ingress**: received on `"{iif0}"`')
        if oif_first:
            out.append(f'- **Egress**: forwarded out `"{oif_first}"`')
        if ttl_changes:
            changes = ", ".join(f"L{ln}: {a}→{b}" for ln, a, b in ttl_changes)
            out.append(f"- **TTL changes**: {changes}")
        if include_timeline:
            out.append("")
            out.append("### Timeline")
            for e in events:
                out.append(f"- L{e.line_no}: {_format_event_short(e)}")
            out.append("")
    else:
        out.append(title)
        out.append("")
        out.append("Story:")
        for line in _story_lines(as_markdown=False):
            out.append("  " + line)
        out.append("")
        if flow:
            out.append(f"Flow: {flow}")
        if iif0:
            out.append(f'Ingress: "{iif0}"')
        if oif_first:
            out.append(f'Egress: "{oif_first}"')
        if ttl_changes:
            changes = ", ".join(f"L{ln}: {a}->{b}" for ln, a, b in ttl_changes)
            out.append(f"TTL changes: {changes}")
        if include_timeline:
            out.append("")
            out.append("Timeline:")
            for e in events:
                out.append(f"  L{e.line_no}: {_format_event_short(e)}")
            out.append("")

    return "\n".join(out)


def build_stories(
    all_events: List[TraceEvent], *, markdown: bool = False, include_timeline: bool = True
) -> str:
    grouped: dict[str, List[TraceEvent]] = defaultdict(list)
    for e in all_events:
        grouped[e.trace_id].append(e)

    # Stable ordering: trace ids as encountered (defaultdict doesn’t preserve "first seen"),
    # so we compute an order list.
    seen: List[str] = []
    for e in all_events:
        if e.trace_id not in seen:
            seen.append(e.trace_id)

    blocks: List[str] = []
    for tid in seen:
        blocks.append(
            story_for_trace(grouped[tid], markdown=markdown, include_timeline=include_timeline)
        )

    sep = "\n" if markdown else "\n"
    return sep.join(blocks).rstrip() + ("\n" if blocks else "")


def summarize_trace_ids(all_events: List[TraceEvent], *, markdown: bool = False) -> str:
    """
    One-line-per-trace-id summary so a user can pick an id to drill into.
    """
    grouped: dict[str, List[TraceEvent]] = defaultdict(list)
    for e in all_events:
        grouped[e.trace_id].append(e)

    # Preserve encounter order.
    seen: List[str] = []
    for e in all_events:
        if e.trace_id not in seen:
            seen.append(e.trace_id)

    lines: List[str] = []
    if markdown:
        lines.append("## Trace IDs")
        lines.append("")
    else:
        lines.append("Trace IDs")
        lines.append("")

    for tid in seen:
        evs = grouped[tid]
        primary = _primary_event(evs)
        flow = _flow_tuple(primary.pkt) or "(no ip flow)"
        packet_events = sum(1 for e in evs if e.pkt.ip_saddr and e.pkt.ip_daddr)
        event_count = len(evs)
        iif = primary.pkt.iif
        oif = next((e.pkt.oif for e in evs if e.pkt.oif), None)

        parts = [tid, flow, f"packets={packet_events}", f"events={event_count}"]
        if iif:
            parts.append(f'iif="{iif}"')
        if oif:
            parts.append(f'oif="{oif}"')

        if markdown:
            lines.append("- " + " | ".join(parts))
        else:
            lines.append("  " + " | ".join(parts))

    lines.append("")
    return "\n".join(lines)


def render_packets_only(all_events: List[TraceEvent], *, markdown: bool = False) -> str:
    """
    Prints only packet events (trace id + parsed packet tuple).
    """
    pkt_events = [e for e in all_events if e.pkt.ip_saddr and e.pkt.ip_daddr]
    lines: List[str] = []
    if markdown:
        lines.append("## Packets")
        lines.append("")
        for e in pkt_events:
            lines.append(f"- {_format_packet_one_line(e)}")
        lines.append("")
    else:
        lines.append("Packets")
        lines.append("")
        for e in pkt_events:
            lines.append("  " + _format_packet_one_line(e))
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Turn nftrace output (nft monitor trace) into a human readable story."
    )
    p.add_argument("trace_file", help="Path to a file containing nftrace output.")
    p.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "-o",
        "--out",
        default="-",
        help='Output file path, or "-" for stdout (default: "-").',
    )
    p.add_argument(
        "--include-nontrace-lines",
        action="store_true",
        help='Include lines that do not contain "trace id ..." (by default they are ignored).',
    )
    p.add_argument(
        "--list-ids",
        action="store_true",
        help="Only list trace ids (with a one-line summary) and exit.",
    )
    p.add_argument(
        "--id",
        dest="trace_id",
        help="Only include a specific trace id (hex string) in the output.",
    )
    p.add_argument(
        "--packets-only",
        action="store_true",
        help="Only output per-packet lines (trace id + packet info).",
    )
    p.add_argument(
        "--no-timeline",
        action="store_true",
        help="Omit the Timeline section from story output.",
    )
    args = p.parse_args(argv)

    try:
        with open(args.trace_file, "r", encoding="utf-8", errors="replace") as f:
            events = parse_trace_lines(f, include_nontrace_lines=args.include_nontrace_lines)
    except OSError as e:
        print(f"error: failed to read {args.trace_file!r}: {e}", file=sys.stderr)
        return 2

    # Optional trace id filter
    if args.trace_id:
        want = args.trace_id.lower()
        events = [e for e in events if e.trace_id.lower() == want]
        if not events:
            print(f"error: trace id {args.trace_id!r} not found in input", file=sys.stderr)
            return 2

    md = args.format == "markdown"
    if args.list_ids:
        rendered = summarize_trace_ids(events, markdown=md)
    elif args.packets_only:
        rendered = render_packets_only(events, markdown=md)
    else:
        rendered = build_stories(events, markdown=md, include_timeline=(not args.no_timeline))
    if args.out == "-":
        sys.stdout.write(rendered)
        return 0

    try:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(rendered)
    except OSError as e:
        print(f"error: failed to write {args.out!r}: {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

