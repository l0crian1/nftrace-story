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
import ipaddress
import json
import re
import sys
import textwrap
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

# Common trace payload regexes (compiled once; story_for_trace is called per trace id)
VERDICT_PAREN_RE = re.compile(r"\(verdict\s+([^)]+)\)", re.IGNORECASE)
VERDICT_SUFFIX_RE = re.compile(r"\s*\(verdict[^)]*\)\s*$", re.IGNORECASE)
DNAT_RE = re.compile(r"\bdnat\s+to\s+(.+)$", re.IGNORECASE)
SNAT_RE = re.compile(r"\bsnat\s+to\s+(.+)$", re.IGNORECASE)
MASQUERADE_RE = re.compile(r"\bmasquerade\b", re.IGNORECASE)
MSS_SET_RE = re.compile(r"\bmaxseg\s+size\s+set\s+(.+)$", re.IGNORECASE)

DISPOSITION_RE = re.compile(
    r"""
    (?:
        \(verdict\s+(?P<v1>accept|drop|reject)\b |
        \bverdict\s+(?P<v2>accept|drop|reject)\b |
        \bpolicy\s+(?P<v3>accept|drop|reject)\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
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


def _final_verdict(events: Sequence[TraceEvent]) -> Optional[Tuple[int, str]]:
    """
    Returns (line_no, verdict) for the last accept/drop/reject (final verdict) observed in the trace.
    """
    final: Optional[Tuple[int, str]] = None
    for e in events:
        m = DISPOSITION_RE.search(e.payload)
        if not m:
            continue
        verdict = (m.group("v1") or m.group("v2") or m.group("v3") or "").lower()
        if verdict:
            final = (e.line_no, verdict)
    return final


def _parse_filter_arg(filter_arg: str) -> dict[str, List[str]]:
    """
    Parse --filter like: "srcaddr=1.2.3.4,dstport=443,verdict=accept"
    Values may be OR'd with "|": "dstport=22|443"
    """
    crit: dict[str, List[str]] = {}
    for raw in filter_arg.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if "=" not in raw:
            raise ValueError(f"invalid filter token {raw!r} (expected key=value)")
        k, v = raw.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if not k or not v:
            raise ValueError(f"invalid filter token {raw!r} (empty key or value)")

        # aliases
        aliases = {
            "srcadd": "srcaddr",
            "saddr": "srcaddr",
            "dstadd": "dstaddr",
            "daddr": "dstaddr",
            "sport": "srcport",
            "dport": "dstport",
            "finalverdict": "verdict",
        }
        k = aliases.get(k, k)

        allowed = {"srcaddr", "dstaddr", "srcport", "dstport", "verdict"}
        if k not in allowed:
            raise ValueError(f"unknown filter key {k!r} (allowed: {', '.join(sorted(allowed))})")

        vals = [vv.strip() for vv in v.split("|") if vv.strip()]
        if not vals:
            raise ValueError(f"invalid filter token {raw!r} (no values)")
        crit.setdefault(k, []).extend(vals)

    # normalize / validate values
    if "verdict" in crit:
        crit["verdict"] = [v.lower() for v in crit["verdict"]]
        for v in crit["verdict"]:
            if v not in {"accept", "drop", "reject"}:
                raise ValueError("verdict must be one of: accept, drop, reject")

    for pk in ("srcport", "dstport"):
        if pk in crit:
            for v in crit[pk]:
                if not v.isdigit():
                    raise ValueError(f"{pk} must be numeric (got {v!r})")
                p = int(v)
                if p < 1 or p > 65535:
                    raise ValueError(f"{pk} must be in range 1-65535 (got {p})")

    for ak in ("srcaddr", "dstaddr"):
        if ak in crit:
            normalized: List[str] = []
            for v in crit[ak]:
                try:
                    normalized.append(str(ipaddress.ip_address(v)))
                except ValueError:
                    raise ValueError(f"{ak} must be a valid IPv4/IPv6 address (got {v!r})")
            crit[ak] = normalized

    return crit


def _trace_matches_filter(events: Sequence[TraceEvent], crit: dict[str, List[str]]) -> bool:
    """
    A trace matches if:
    - verdict filter matches final verdict (if specified)
    - and there exists at least one packet event that matches all address/port criteria (if any specified)
    """
    if not crit:
        return True

    if "verdict" in crit:
        fd = _final_verdict(events)
        if not fd:
            return False
        _, verdict = fd
        if verdict not in set(crit["verdict"]):
            return False

    packet_keys = {"srcaddr", "dstaddr", "srcport", "dstport"}
    packet_crit = {k: crit[k] for k in crit.keys() if k in packet_keys}
    if not packet_crit:
        return True

    srcaddr_set = set(packet_crit.get("srcaddr", []))
    dstaddr_set = set(packet_crit.get("dstaddr", []))
    srcport_set = set(int(v) for v in packet_crit.get("srcport", []))
    dstport_set = set(int(v) for v in packet_crit.get("dstport", []))

    for e in events:
        p = e.pkt
        if not (p.ip_saddr and p.ip_daddr):
            continue

        # Normalize packet addresses to match normalized filter values.
        try:
            p_src = str(ipaddress.ip_address(p.ip_saddr))
            p_dst = str(ipaddress.ip_address(p.ip_daddr))
        except ValueError:
            # If the trace has weird/non-IP values, skip this event for addr-based filtering.
            continue

        if srcaddr_set and p_src not in srcaddr_set:
            continue
        if dstaddr_set and p_dst not in dstaddr_set:
            continue

        if srcport_set:
            sp = p.tcp_sport if p.tcp_sport is not None else p.udp_sport
            if sp is None or sp not in srcport_set:
                continue

        if dstport_set:
            dp = p.tcp_dport if p.tcp_dport is not None else p.udp_dport
            if dp is None or dp not in dstport_set:
                continue

        return True

    return False


def _format_raw_trace_line(e: TraceEvent) -> str:
    # Normalize away any editor-export prefix like "L12:"; we add our own line numbers.
    line = _strip_optional_line_number_prefix(e.raw).strip()
    return f"L{e.line_no}: {line}"


RAW_TRACE_WRAP_WIDTH = 120


def _wrap_bullet(content: str, *, prefix: str, width: int = RAW_TRACE_WRAP_WIDTH) -> str:
    """
    Wrap a single bullet item to a fixed width, indenting continuation lines so
    they remain visually under the bullet.
    """
    return textwrap.fill(
        content,
        width=width,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=False,
        break_on_hyphens=False,
    )


def _pkt_sig(p: PacketView) -> Optional[Tuple[str, str, str, Optional[int], Optional[int]]]:
    if not p.ip_saddr or not p.ip_daddr:
        return None
    proto = (p.ip_protocol or "").lower()
    if proto == "tcp":
        return (p.ip_saddr, p.ip_daddr, proto, p.tcp_sport, p.tcp_dport)
    if proto == "udp":
        return (p.ip_saddr, p.ip_daddr, proto, p.udp_sport, p.udp_dport)
    return (p.ip_saddr, p.ip_daddr, proto, None, None)


def _build_trace_story_dict(events: Sequence[TraceEvent], *, include_raw_trace: bool) -> dict:
    """
    Build a structured representation of a single trace id's story.
    This dict is the source of truth for text/markdown output and JSON output.
    """
    if not events:
        raise ValueError("events must be non-empty")

    # Single-pass analysis over this trace's events.
    primary: Optional[TraceEvent] = None
    oif_first: Optional[str] = None
    last = events[-1]
    last_hook: Optional[str] = None

    ttl_dec_line: Optional[int] = None
    prev_ttl: Optional[int] = None

    table_chain_path: List[Tuple[str, str]] = []
    table_chain_seen: set[Tuple[str, str]] = set()

    max_rules = 50
    rule_order: List[Tuple[str, str, str, str]] = []
    rule_first_line: dict[Tuple[str, str, str, str], int] = {}

    final: Optional[Tuple[int, str]] = None

    nat_hits: List[Tuple[int, str]] = []
    rewrite_hits: List[Tuple[int, str]] = []
    NAT_MAX_HITS = 10
    rewrite_found = False
    prev_sig: Optional[Tuple[str, str, str, Optional[int], Optional[int]]] = None
    prev_flow: Optional[str] = None

    mss_hits: List[Tuple[int, str]] = []
    MSS_MAX_HITS = 10

    raw_trace: Optional[List[dict]] = [] if include_raw_trace else None

    for e in events:
        payload = (e.payload or "").strip()

        if raw_trace is not None:
            raw_trace.append({"line": e.line_no, "text": _format_raw_trace_line(e)})

        if primary is None and e.pkt.ip_saddr and e.pkt.ip_daddr:
            primary = e

        if oif_first is None and e.pkt.oif:
            oif_first = e.pkt.oif

        if e.hook_hint:
            last_hook = e.hook_hint

        ttl = e.pkt.ip_ttl
        if ttl is not None:
            if ttl_dec_line is None and prev_ttl is not None and (prev_ttl - ttl) == 1:
                ttl_dec_line = e.line_no
            prev_ttl = ttl

        t = e.table
        c = e.chain
        if t != "?" and c != "?":
            key_tc = (t, c)
            if key_tc not in table_chain_seen:
                table_chain_seen.add(key_tc)
                table_chain_path.append(key_tc)

        if payload.lower().startswith("rule "):
            verdict_m = VERDICT_PAREN_RE.search(payload)
            verdict = verdict_m.group(1).strip() if verdict_m else ""

            rule_text = payload[5:].strip()
            rule_text = VERDICT_SUFFIX_RE.sub("", rule_text).strip()

            key_rule = (e.table, e.chain, rule_text, verdict)
            if key_rule not in rule_first_line:
                rule_order.append(key_rule)
                rule_first_line[key_rule] = e.line_no

        m = DISPOSITION_RE.search(payload)
        if m:
            v = (m.group("v1") or m.group("v2") or m.group("v3") or "").lower()
            if v:
                final = (e.line_no, v)

        if len(nat_hits) < NAT_MAX_HITS and payload:
            m = DNAT_RE.search(payload)
            if m:
                target = VERDICT_SUFFIX_RE.sub("", m.group(1).strip()).strip()
                nat_hits.append((e.line_no, f"DNAT to {target}"))
            m = SNAT_RE.search(payload)
            if m:
                target = VERDICT_SUFFIX_RE.sub("", m.group(1).strip()).strip()
                nat_hits.append((e.line_no, f"SNAT to {target}"))
            if MASQUERADE_RE.search(payload):
                nat_hits.append((e.line_no, "Masquerade"))

        if len(mss_hits) < MSS_MAX_HITS and payload:
            m = MSS_SET_RE.search(payload)
            if m:
                set_value = VERDICT_SUFFIX_RE.sub("", m.group(1).strip()).strip()
                mss_hits.append((e.line_no, set_value))

        if not rewrite_found:
            sig = _pkt_sig(e.pkt)
            if sig is not None:
                flow_now = _flow_tuple(e.pkt) or f"{sig[0]} → {sig[1]}"
                if prev_sig is not None and sig != prev_sig:
                    saddr0, daddr0, proto0, sport0, dport0 = prev_sig
                    saddr1, daddr1, proto1, sport1, dport1 = sig

                    addr_changed = (saddr0 != saddr1) or (daddr0 != daddr1)
                    if addr_changed:
                        before = prev_flow or f"{proto0} {saddr0} → {daddr0}"
                        after = flow_now

                        changes: List[str] = []
                        if saddr0 != saddr1:
                            changes.append(f"saddr {saddr0} → {saddr1}")
                        if daddr0 != daddr1:
                            changes.append(f"daddr {daddr0} → {daddr1}")
                        if sport0 != sport1 and (sport0 is not None or sport1 is not None):
                            changes.append(f"sport {sport0} → {sport1}")
                        if dport0 != dport1 and (dport0 is not None or dport1 is not None):
                            changes.append(f"dport {dport0} → {dport1}")

                        detail = "; ".join(changes) if changes else "flow changed"
                        rewrite_hits.append(
                            (e.line_no, f"Flow rewrite: {before} became {after} ({detail})")
                        )
                        rewrite_found = True

                prev_sig = sig
                prev_flow = flow_now

    primary = primary or events[0]
    flow = _flow_tuple(primary.pkt)
    iif0 = primary.pkt.iif

    data: dict = {
        "id": events[0].trace_id,
        "flow": flow,
        "ingress": iif0,
        "egress": oif_first,
        "ttl_decrement_by_one_line": ttl_dec_line,
        "last": {"line": last.line_no, "hook": last_hook},
        "final_verdict": ({"line": final[0], "verdict": final[1]} if final else None),
        "nat": {
            "hits": [{"line": ln, "message": msg} for ln, msg in nat_hits],
            "rewrite": [{"line": ln, "message": msg} for ln, msg in rewrite_hits],
        },
        "mss_rewrite": [{"line": ln, "value": val} for ln, val in mss_hits],
        "tables_visited": [{"table": t, "chain": c} for t, c in table_chain_path],
        "rules_hit": [
            {
                "table": t,
                "chain": c,
                "line": rule_first_line[(t, c, rule_text, verdict)],
                "rule": rule_text,
                "verdict": verdict or None,
            }
            for (t, c, rule_text, verdict) in rule_order
        ],
        "rules_cap": max_rules,
    }

    if include_raw_trace:
        data["raw_trace"] = raw_trace or []

    return data


def _render_trace_story_dict(data: dict, *, markdown: bool, include_raw_trace: bool) -> str:
    trace_id = data.get("id", "(unknown)")
    title = f"Trace {trace_id}" if trace_id != "(unparsed)" else "Trace (unparsed)"

    flow = data.get("flow")
    iif0 = data.get("ingress")
    oif_first = data.get("egress")
    ttl_ln = data.get("ttl_decrement_by_one_line")
    last = data.get("last") or {}
    final = data.get("final_verdict")

    nat = data.get("nat") or {}
    nat_hits = nat.get("hits") or []
    nat_rewrite = nat.get("rewrite") or []
    mss_hits = data.get("mss_rewrite") or []
    tables = data.get("tables_visited") or []
    rules = data.get("rules_hit") or []
    rules_cap = int(data.get("rules_cap") or 50)

    out: List[str] = []

    story_top_prefix = "- " if markdown else "  - "
    story_sub_prefix = "  - " if markdown else "    - "

    def emit_story_line(s: str) -> None:
        out.append(f"{story_top_prefix}{s}")

    if markdown:
        out.append(f"## {title}")
        out.append("")
        out.append("### Story")
    else:
        out.append(title)
        out.append("")
        out.append("Story:")

    subject = flow or "Packet"
    if iif0:
        emit_story_line(f'{subject} arrived on interface "{iif0}".')
    else:
        emit_story_line(f"{subject} appeared in nftrace output.")

    if oif_first:
        emit_story_line(f'Routing selected egress interface "{oif_first}" (forwarding path).')

    if ttl_ln is not None:
        emit_story_line(f"TTL was decremented by 1 at L{ttl_ln} (typical for forwarding).")

    if last.get("hook"):
        emit_story_line(f"It was last observed near the {last['hook']} hook (L{last.get('line')}).")
    else:
        emit_story_line(f"It was last observed at L{last.get('line')}.")

    if final:
        emit_story_line(f"Final verdict: {str(final['verdict']).upper()} (L{final['line']}).")

    if nat_hits or nat_rewrite:
        emit_story_line("NAT detected:")
        for h in nat_hits:
            out.append(f"{story_sub_prefix}L{h['line']}: {h['message']}")
        for h in nat_rewrite:
            out.append(f"{story_sub_prefix}L{h['line']}: {h['message']}")

    if mss_hits:
        emit_story_line("MSS rewrite detected:")
        for h in mss_hits:
            out.append(f"{story_sub_prefix}L{h['line']}: maxseg size set {h['value']}")

    if tables:
        emit_story_line("Tables visited:")
        for tc in tables:
            t = tc["table"]
            c = tc["chain"]
            if markdown:
                out.append(f"{story_sub_prefix}`{t}`.`{c}`")
            else:
                out.append(f"{story_sub_prefix}{t}.{c}")

    if rules:
        shown = min(len(rules), rules_cap)
        if len(rules) > shown:
            emit_story_line(f"Rules hit (showing first {shown} of {len(rules)} unique rules):")
        else:
            emit_story_line("Rules hit:")

        for r in rules[:shown]:
            t = r["table"]
            c = r["chain"]
            ln = r["line"]
            rule_text = r["rule"]
            verdict = r.get("verdict")
            tc_disp = f"`{t}`.`{c}`" if markdown else f"{t}.{c}"
            suffix = f" (verdict {verdict})" if verdict else ""
            out.append(f"{story_sub_prefix}{tc_disp} L{ln}: {rule_text}{suffix}")

        if len(rules) > shown:
            out.append(f"{story_sub_prefix}… plus {len(rules) - shown} more unique rules")

    if markdown:
        out.append("")
        if flow:
            out.append(f"- **Flow**: {flow}")
        if iif0:
            out.append(f'- **Ingress**: received on `"{iif0}"`')
        if oif_first:
            out.append(f'- **Egress**: forwarded out `"{oif_first}"`')
        if include_raw_trace and data.get("raw_trace"):
            out.append("")
            out.append("### Raw trace")
            for e in data["raw_trace"]:
                out.append(_wrap_bullet(e["text"], prefix="- "))
            out.append("")
    else:
        out.append("")
        if flow:
            out.append(f"Flow: {flow}")
        if iif0:
            out.append(f'Ingress: "{iif0}"')
        if oif_first:
            out.append(f'Egress: "{oif_first}"')
        if include_raw_trace and data.get("raw_trace"):
            out.append("")
            out.append("Raw trace:")
            for e in data["raw_trace"]:
                out.append(_wrap_bullet(e["text"], prefix="  - "))
            out.append("")

    return "\n".join(out)


def _group_events_by_trace_id(
    all_events: Sequence[TraceEvent],
) -> Tuple[dict[str, List[TraceEvent]], List[str]]:
    """
    Group events by trace id and return ids in first-seen order.
    """
    grouped: dict[str, List[TraceEvent]] = defaultdict(list)
    seen: List[str] = []
    seen_set: set[str] = set()

    for e in all_events:
        grouped[e.trace_id].append(e)
        if e.trace_id not in seen_set:
            seen_set.add(e.trace_id)
            seen.append(e.trace_id)

    return grouped, seen


def _build_list_ids_dict(all_events: Sequence[TraceEvent]) -> dict:
    grouped, seen = _group_events_by_trace_id(all_events)

    rows: List[dict] = []
    for tid in seen:
        evs = grouped[tid]
        if not evs:
            continue

        primary: Optional[TraceEvent] = None
        packet_events = 0
        oif: Optional[str] = None
        final: Optional[Tuple[int, str]] = None

        for e in evs:
            if e.pkt.ip_saddr and e.pkt.ip_daddr:
                packet_events += 1
                if primary is None:
                    primary = e

            if oif is None and e.pkt.oif:
                oif = e.pkt.oif

            m = DISPOSITION_RE.search(e.payload)
            if m:
                v = (m.group("v1") or m.group("v2") or m.group("v3") or "").lower()
                if v:
                    final = (e.line_no, v)

        primary = primary or evs[0]
        flow = _flow_tuple(primary.pkt) or "(no ip flow)"
        event_count = len(evs)
        iif = primary.pkt.iif

        rows.append(
            {
                "id": tid,
                "flow": flow,
                "packets": packet_events,
                "events": event_count,
                "iif": iif,
                "oif": oif,
                "verdict": ({"line": final[0], "verdict": final[1]} if final else None),
            }
        )

    return {"trace_ids": rows}


def _render_list_ids_dict(data: dict, *, markdown: bool) -> str:
    lines: List[str] = []
    if markdown:
        lines.append("## Trace IDs")
        lines.append("")
    else:
        lines.append("Trace IDs")
        lines.append("")

    for r in data["trace_ids"]:
        parts = [r["id"], r["flow"], f"packets={r['packets']}", f"events={r['events']}"]
        if r.get("iif"):
            parts.append(f'iif="{r["iif"]}"')
        if r.get("oif"):
            parts.append(f'oif="{r["oif"]}"')
        if r.get("verdict"):
            v = r["verdict"]
            parts.append(f'verdict={v["verdict"].upper()} (L{v["line"]})')

        if markdown:
            lines.append("- " + " | ".join(parts))
        else:
            lines.append("  " + " | ".join(parts))

    lines.append("")
    return "\n".join(lines)


def story_for_trace(
    events: List[TraceEvent], *, markdown: bool = False, include_timeline: bool = False
) -> str:
    """
    Produce a story for a single trace id.
    """
    if not events:
        return ""
    data = _build_trace_story_dict(events, include_raw_trace=include_timeline)
    return _render_trace_story_dict(data, markdown=markdown, include_raw_trace=include_timeline)


def build_stories(
    all_events: List[TraceEvent], *, markdown: bool = False, include_timeline: bool = False
) -> str:
    grouped, seen = _group_events_by_trace_id(all_events)

    blocks: List[str] = []
    for tid in seen:
        blocks.append(
            story_for_trace(grouped[tid], markdown=markdown, include_timeline=include_timeline)
        )

    if not blocks:
        return ""

    if markdown:
        joined = "\n".join(blocks)
    else:
        delim = "\n" + ("-" * 72) + "\n"
        joined = delim.join(blocks)

    return joined.rstrip() + "\n"


def summarize_trace_ids(all_events: List[TraceEvent], *, markdown: bool = False) -> str:
    """
    One-line-per-trace-id summary so a user can pick an id to drill into.
    """
    data = _build_list_ids_dict(all_events)
    return _render_list_ids_dict(data, markdown=markdown)


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Turn nftrace output (nft monitor trace) into a human readable story."
    )
    p.add_argument("trace_file", help="Path to a file containing nftrace output.")
    p.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
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
        "--show-timeline",
        action="store_true",
        help="Include the raw nftrace lines for each trace.",
    )
    p.add_argument(
        "--filter",
        dest="trace_filter",
        help='Filter traces, e.g. --filter "srcaddr=1.2.3.4,dstport=443,verdict=accept"',
    )
    return p.parse_args(argv)


def _validate_args(args: argparse.Namespace) -> Optional[dict[str, List[str]]]:
    if args.trace_id and args.trace_filter:
        print(
            "error: --id and --filter cannot be used together (choose one).",
            file=sys.stderr,
        )
        raise SystemExit(2)

    if not args.trace_filter:
        return None

    try:
        return _parse_filter_arg(args.trace_filter)
    except ValueError as e:
        print(f"error: invalid --filter: {e}", file=sys.stderr)
        raise SystemExit(2)


def _load_events(args: argparse.Namespace) -> List[TraceEvent]:
    try:
        with open(args.trace_file, "r", encoding="utf-8", errors="replace") as f:
            events = parse_trace_lines(f, include_nontrace_lines=args.include_nontrace_lines)
    except OSError as e:
        print(f"error: failed to read {args.trace_file!r}: {e}", file=sys.stderr)
        raise SystemExit(2)

    if not any(e.trace_id != "(unparsed)" for e in events):
        print(
            "error: no trace events found (no 'trace id ...' lines detected). "
            "Is this the right file?",
            file=sys.stderr,
        )
        raise SystemExit(2)

    return events


def _apply_id_filter(events: List[TraceEvent], args: argparse.Namespace) -> List[TraceEvent]:
    if not args.trace_id:
        return events

    want = args.trace_id.lower()
    filtered = [e for e in events if e.trace_id.lower() == want]
    if not filtered:
        print(f"error: trace id {args.trace_id!r} not found in input", file=sys.stderr)
        raise SystemExit(2)
    return filtered


def _apply_trace_filter(
    events: List[TraceEvent], crit: Optional[dict[str, List[str]]]
) -> List[TraceEvent]:
    if crit is None:
        return events

    grouped, _ = _group_events_by_trace_id(events)
    keep_ids = {
        tid for tid, evs in grouped.items() if tid != "(unparsed)" and _trace_matches_filter(evs, crit)
    }
    filtered = [e for e in events if e.trace_id in keep_ids]
    if not any(e.trace_id != "(unparsed)" for e in filtered):
        print("error: no traces matched --filter", file=sys.stderr)
        raise SystemExit(2)
    return filtered


def _render_output(events: List[TraceEvent], args: argparse.Namespace) -> str:
    if args.format == "json":
        if args.list_ids:
            payload = _build_list_ids_dict(events)
        else:
            grouped, seen = _group_events_by_trace_id(events)
            payload = {
                "traces": [
                    _build_trace_story_dict(grouped[tid], include_raw_trace=bool(args.show_timeline))
                    for tid in seen
                ]
            }

        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    md = args.format == "markdown"
    if args.list_ids:
        return summarize_trace_ids(events, markdown=md)
    return build_stories(events, markdown=md, include_timeline=args.show_timeline)


def _write_output(rendered: str, args: argparse.Namespace) -> int:
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


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = _parse_args(argv)
        crit = _validate_args(args)
        events = _load_events(args)
        events = _apply_id_filter(events, args)
        events = _apply_trace_filter(events, crit)
        rendered = _render_output(events, args)
        return _write_output(rendered, args)
    except SystemExit as e:
        # Helpers raise SystemExit(2) on user-facing errors; keep main() signature (int return).
        return int(e.code) if isinstance(e.code, int) else 2


if __name__ == "__main__":
    raise SystemExit(main())

