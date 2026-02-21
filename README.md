# nftrace story

Small, dependency-free Python script that reads **nftrace / `nft monitor trace` output** and prints a human readable “story” of what happened to the packet(s).

## Usage

- **Text output** (default):

```bash
python nftrace_story.py "example trace.trace"
```

- **List trace IDs (summary so you can pick one)**:

```bash
python nftrace_story.py "example trace.trace" --list-ids
```

- **Story for a specific trace id**:

```bash
python nftrace_story.py "example trace.trace" --id 07c9c091
```

- **Story without the timeline**:

```bash
python nftrace_story.py "example trace.trace" --no-timeline
```

- **Packets-only (trace id + packet tuple, no story/timeline)**:

```bash
python nftrace_story.py "example trace.trace" --packets-only
```

- **Packets-only for a specific trace id**:

```bash
python nftrace_story.py "example trace.trace" --packets-only --id 07c9c091
```

- **Markdown output**:

```bash
python nftrace_story.py "example trace.trace" --format markdown
```

- **Write to a file**:

```bash
python nftrace_story.py "example trace.trace" -o story.txt
```

## Workflow example (pick an id, then drill in)

1) **Get a list of trace ids (markdown)**

```bash
python3 nftrace_story.py --format markdown --list-ids test.trace
```

Example output:

```text
## Trace IDs

- 07c9c091 | tcp 192.168.2.21:29670 → 10.0.101.214:22 | packets=8 | events=31 | iif="eth0"
- 89f3ae4f | tcp 192.168.2.21:29710 → 10.0.101.214:22 | packets=16 | events=62 | iif="eth0"
- 6af521c6 | tcp 192.168.0.50:40804 → 34.117.59.81:80 | packets=35 | events=130 | iif="eth1" | oif="eth0"
...
```

2) **Render the story for the id you care about (no timeline)**

```bash
python3 nftrace_story.py --format markdown --id 6af521c6 --no-timeline test.trace
```

Example output:

```text
## Trace 6af521c6

### Story
- tcp 192.168.0.50:40804 → 34.117.59.81:80 arrived on interface "eth1".
- Routing selected egress interface "eth0" (forwarding path).
- TTL was decremented by 1 at L418 (typical for forwarding).
- It was last observed near the FORWARD hook (L658).
- Final disposition: ACCEPT (L658).
- Packet headers changed at L385 (possible NAT/rewrite).
- Tables visited:
  - `trace`: prerouting
  - `vyos_conntrack`: PREROUTING, VYOS_CT_IGNORE, FW_CONNTRACK, NAT_CONNTRACK, PREROUTING_HELPER, VYOS_CT_HELPER
  - `vyos_filter`: VYOS_PREROUTING_raw, VYOS_FORWARD_filter
  - `vrf_zones`: vrf_zones_ct_in
  - `raw`: VYOS_PREROUTING_HOOK, vyos_rpfilter, vyos_global_rpfilter, VYOS_TCP_MSS
  - `vyos_static_nat`: PREROUTING, POSTROUTING
  - `vyos_nat`: PREROUTING, VYOS_PRE_DNAT_HOOK, POSTROUTING, VYOS_PRE_SNAT_HOOK
  - `mangle`: FORWARD
  - `nat`: VYOS_PRE_SNAT_HOOK

- **Flow**: tcp 192.168.0.50:40804 → 34.117.59.81:80
- **Ingress**: received on `"eth1"`
- **Egress**: forwarded out `"eth0"`
- **TTL changes**: L418: 64→63, L474: 63→64, L532: 64→63, L622: 63→64, L651: 64→63
```

## Notes

- The script groups events by `trace id ...` and prints one story per trace id.
- If your trace text includes editor-export prefixes like `L12:...`, those are ignored.
- Lines that do **not** contain `trace id ...` are **ignored by default** (so you don’t get a junk “Trace (unparsed)” section). If you want to include them anyway:

```bash
python nftrace_story.py "example trace.trace" --include-nontrace-lines
```

