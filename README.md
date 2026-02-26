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

- **Story with the timeline**:

```bash
python nftrace_story.py "example trace.trace" --show-timeline
```

- **Filter traces** (applies to `--list-ids` and default story output):

```bash
python nftrace_story.py "example trace.trace" --filter "srcaddr=1.2.3.4,dstport=443,verdict=accept"
```

- **Filter + list ids**:

```bash
python nftrace_story.py "example trace.trace" --list-ids --filter "dstport=22|443"
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

2) **Render the story for the id you care about**

```bash
python3 nftrace_story.py --format markdown --id 6af521c6 test.trace
```

Example output:

```text
## Trace 9faeedfc

### Story
- tcp 192.168.0.50:53158 → 34.117.59.81:80 arrived on interface "eth1".
- Routing selected egress interface "eth0" (forwarding path).
- TTL was decremented by 1 at L253 (typical for forwarding).
- It was last observed near the FORWARD hook (L523).
- Final disposition: ACCEPT (L523).
- NAT detected:
  - L271: Masquerade
- MSS rewrite detected:
  - L259: maxseg size set rt mtu
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
- Rules hit:
  - `trace`.`prerouting` L217: meta nftrace set 1 (verdict continue)
  - `vyos_conntrack`.`PREROUTING` L221: counter packets 2178 bytes 287508 jump VYOS_CT_IGNORE (verdict jump VYOS_CT_IGNORE)
  - `vyos_conntrack`.`PREROUTING` L223: counter packets 2178 bytes 287508 jump FW_CONNTRACK (verdict jump FW_CONNTRACK)
  - `vyos_conntrack`.`PREROUTING` L225: counter packets 2178 bytes 287508 jump NAT_CONNTRACK (verdict jump NAT_CONNTRACK)
  - `vyos_conntrack`.`NAT_CONNTRACK` L226: accept (verdict accept)
  - `vyos_filter`.`VYOS_PREROUTING_raw` L228: counter packets 19572 bytes 5868890 accept comment "PRE-raw default-action accept" (verdict accept)
  - `raw`.`vyos_rpfilter` L236: counter packets 19979 bytes 5901810 jump vyos_global_rpfilter (verdict jump vyos_global_rpfilter)
  - `vyos_nat`.`PREROUTING` L244: counter packets 14 bytes 1360 jump VYOS_PRE_DNAT_HOOK (verdict jump VYOS_PRE_DNAT_HOOK)
  - `vyos_conntrack`.`PREROUTING_HELPER` L249: counter packets 2178 bytes 287508 jump VYOS_CT_HELPER (verdict jump VYOS_CT_HELPER)
  - `vyos_filter`.`VYOS_FORWARD_filter` L257: counter packets 1356 bytes 110874 accept comment "FWD-filter default-action accept" (verdict accept)
  - `raw`.`VYOS_TCP_MSS` L259: oifname "eth0" tcp flags syn / syn,rst tcp option maxseg size set rt mtu (verdict continue)
  - `vyos_nat`.`POSTROUTING` L269: counter packets 13 bytes 1060 jump VYOS_PRE_SNAT_HOOK (verdict jump VYOS_PRE_SNAT_HOOK)
  - `vyos_nat`.`POSTROUTING` L271: oifname "eth0" ip saddr 192.168.0.0/16 counter packets 9 bytes 568 masquerade comment "SRC-NAT-10" (verdict accept)

- **Flow**: tcp 192.168.0.50:53158 → 34.117.59.81:80
- **Ingress**: received on `"eth1"`
- **Egress**: forwarded out `"eth0"`
```

## Notes

- The script groups events by `trace id ...` and prints one story per trace id.
- If your trace text includes editor-export prefixes like `L12:...`, those are ignored.
- The story output includes a **Rules hit** list (derived from trace lines that start with `rule ...`), capped to keep output readable.
- Lines that do **not** contain `trace id ...` are **ignored by default** (so you don’t get a junk “Trace (unparsed)” section). If you want to include them anyway:

```bash
python nftrace_story.py "example trace.trace" --include-nontrace-lines
```

