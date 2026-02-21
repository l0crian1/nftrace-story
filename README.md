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

## Notes

- The script groups events by `trace id ...` and prints one story per trace id.
- If your trace text includes editor-export prefixes like `L12:...`, those are ignored.
- Lines that do **not** contain `trace id ...` are **ignored by default** (so you don’t get a junk “Trace (unparsed)” section). If you want to include them anyway:

```bash
python nftrace_story.py "example trace.trace" --include-nontrace-lines
```

