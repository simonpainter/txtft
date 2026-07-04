# txtfs — a DNS TXT record file transfer utility

Serve arbitrary files as DNS `TXT` records and pull them back with a client that
walks an index and reassembles the pieces. A file is zipped, the zip is split into
raw segments sized so each one's base64 encoding fits a single TXT record, and every
segment is published under a plausible-looking hostname (`copper-lantern-drift.f.example.com`).
A seed/manifest record and one or more chained index records tie it together.

This is a novelty / teaching transport for content you're authorised to serve on
infrastructure you control. Large TXT records and high-volume TXT queries to one
zone are trivially visible to any DNS monitoring — it is not a covert channel.

Full design rationale, wire formats, and sizing math are in **[SPEC.md](SPEC.md)**.

## Components

| Tool | Role |
|------|------|
| `txtfs-encode` | Zip → segment → base64 → write a zone-store JSON, print the seed key. |
| `txtfs-serve` | Minimal authoritative `TXT` responder (asyncio UDP + TCP) over that store. |
| `txtfs-fetch` | Resolve the manifest, walk the index chain, fetch/decode/reassemble/verify. |

## Install

```bash
pip install -r requirements.txt          # just dnspython
# optional, for the txtfs-* console commands:
pip install -e .
```

Python 3.11+. Either invoke as modules (`python -m encode ...`) or, after
`pip install -e .`, use the `txtfs-encode` / `txtfs-serve` / `txtfs-fetch` commands.

## Quick start (loopback)

```bash
# 1. Encode a file into a zone store. Prints the seed key you hand to the downloader.
python -m encode ./report.pdf --zone f.example.com --out zone.json
#   seed key : delta-walnut-heath
#   seed FQDN: delta-walnut-heath.f.example.com

# 2. Serve it (high port, no root needed).
python -m serve zone.json --host 127.0.0.1 --port 5300

# 3. In another shell, download by seed key, querying the server directly.
python -m fetch delta-walnut-heath \
    --zone f.example.com --server 127.0.0.1 --port 5300 --out recovered.pdf
```

## Operating modes

The `<64 kB` TXT target is the single-record ceiling, and hitting it forces TCP —
oversized TXT does not fit UDP even with EDNS0, and public recursive resolvers
routinely truncate or drop it. Two presets trade record size against resolver reach:

| Mode | base64 chars/record | raw segment | transport | when |
|------|--------------------:|------------:|-----------|------|
| `direct` (default) | 60 000 | 45 000 B | TCP, query the authoritative server directly | you control the resolution path (`--server IP`) |
| `compatible` | 1 200 | 900 B | EDNS0/UDP (TCP fallback on TC) | traffic must survive arbitrary recursive resolvers |

Set on **both** encode and fetch:

```bash
python -m encode data.bin --zone f.example.com --mode compatible --out zone.json
python -m fetch <seed> --zone f.example.com --server <ip> --mode compatible
```

Override the exact size with `--payload-max N` (base64 chars per record) on encode.

## Multiple files

Pass several inputs; they're zipped into one archive under a single seed. `--name`
labels the bundle. The downloader extracts all members to `--out-dir`.

```bash
python -m encode a.pdf b.csv c.png --zone f.example.com --name bundle --out zone.json
python -m fetch <seed> --zone f.example.com --server <ip> --out-dir ./out
```

## Serving on the real DNS hierarchy

For resolution through normal recursion rather than a direct `--server`, delegate a
**dedicated subdomain** to the box running `txtfs-serve`, so you never touch the apex
zone. At the parent zone (`example.com`):

```
f.example.com.   IN  NS   ns-txtfs.example.com.
ns-txtfs.example.com. IN A   203.0.113.10
```

Then bind the server to `:53` (needs privilege) and point `txtfs-fetch` at the zone
without `--server` only if your resolver path preserves large TXT — otherwise keep
querying the authoritative IP directly with `--mode direct`.

## Integrity

Three independent layers, all checked by `txtfs-fetch`:

1. Manifest `sha256` of the original file (single-file) or the archive (multi-file).
2. Zip per-entry CRC-32, validated on extraction (`ZipFile.testzip`).
3. Index `segments` count and monotonic ordinal, catching a truncated index chain.

## Testing

```bash
pip install pytest
pytest tests/ -v
# or run the round-trip directly:
python tests/test_roundtrip.py
```

`tests/test_roundtrip.py` runs encode → serve (loopback) → fetch → byte-compare in
both `direct` (chained-index) and `compatible` (UDP) configurations.

## Layout

```
txtfs/
├── common.py       # sizing math, TXT string split/join, key generation, wordlist
├── encode.py       # txtfs-encode
├── serve.py        # txtfs-serve (asyncio UDP + TCP)
├── fetch.py        # txtfs-fetch
├── wordlist.txt    # ~230 words; use --words 4 or a bigger list for large files
├── tests/test_roundtrip.py
├── .github/workflows/ci.yml
├── pyproject.toml
├── requirements.txt
├── README.md
└── SPEC.md
```

## Keyspace note

Default keys are 3 hyphenated words. With the bundled ~230-word list that's ~12M
combinations — fine for moderate files, but collision re-rolls climb as segment count
rises. For large files pass `--words 4` (or a larger `--wordlist`); the encoder
guarantees uniqueness regardless and fails loudly if the keyspace is exhausted.
