"""txtfs-encode: pack file(s) into a zone store JSON of TXT records.

Zips the input, splits the zip bytes into raw segments sized so their base64
encoding fits one TXT record, allocates a plausible key per segment, chains the
ordered keys into one or more index records, and writes a manifest (seed) record
that ties it together with integrity metadata.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .common import (
    MODES,
    TXT_RECORD_CEILING,
    KeyGenerator,
    load_wordlist,
    raw_segment_bytes,
)


def build_zip(paths: list[Path]) -> bytes:
    """Zip the inputs into an in-memory standard .zip (DEFLATE), keyed by filename."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in paths:
            zf.write(p, arcname=p.name)
    return buf.getvalue()


def segment(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _index_len(keys: list[str], has_next: bool) -> int:
    """Serialized byte length of an index record for the given keys."""
    obj = {"v": 1, "i": 0, "keys": keys, "next": ("x" * 24 if has_next else None)}
    return len(json.dumps(obj, separators=(",", ":")).encode())


def build_indexes(seg_keys: list[str], keygen: KeyGenerator, payload_max: int):
    """Greedy-pack segment keys into chained index records.

    Returns ``(first_index_key, [(index_key, value_bytes), ...])``. Packs keys into
    a slice until one more would push the serialized record past ``payload_max``,
    then starts a new slice and links it via ``next``.
    """
    slices: list[list[str]] = []
    cur: list[str] = []
    for k in seg_keys:
        trial = cur + [k]
        if cur and _index_len(trial, has_next=True) > payload_max:
            slices.append(cur)
            cur = [k]
        else:
            cur = trial
    if cur:
        slices.append(cur)

    index_keys = [keygen.allocate() for _ in slices]
    records = []
    for i, (slc, ikey) in enumerate(zip(slices, index_keys)):
        nxt = index_keys[i + 1] if i + 1 < len(index_keys) else None
        value = json.dumps(
            {"v": 1, "i": i, "keys": slc, "next": nxt}, separators=(",", ":")
        ).encode()
        records.append((ikey, value))
    first = index_keys[0] if index_keys else None
    return first, records


def encode(args) -> None:
    wordlist = load_wordlist(args.wordlist)
    keygen = KeyGenerator(wordlist, words=args.words, seed=args.seed)
    payload_max = args.payload_max or MODES[args.mode]
    seg_size = raw_segment_bytes(payload_max)

    paths = [Path(p) for p in args.files]
    for p in paths:
        if not p.is_file():
            raise SystemExit(f"not a file: {p}")

    multi = len(paths) > 1
    zip_bytes = build_zip(paths)
    if multi:
        name = args.name or "archive"
        sha = hashlib.sha256(zip_bytes).hexdigest()
        size = len(zip_bytes)
        sha_target = "archive"
    else:
        original = paths[0].read_bytes()
        name = paths[0].name
        sha = hashlib.sha256(original).hexdigest()
        size = len(original)
        sha_target = "original"

    records: dict[str, dict] = {}

    # Segment records: one base64 chunk each.
    seg_keys: list[str] = []
    for chunk in segment(zip_bytes, seg_size):
        b64 = base64.b64encode(chunk).decode("ascii")
        key = keygen.allocate()
        seg_keys.append(key)
        records[key] = {"type": "segment", "value": b64}

    # Index records.
    first_index, index_records = build_indexes(seg_keys, keygen, payload_max)
    for ikey, value in index_records:
        records[ikey] = {"type": "index", "value": value.decode("ascii")}

    # Manifest / seed record.
    seed_key = keygen.allocate()
    manifest = {
        "v": 1,
        "name": name,
        "size": size,
        "sha256": sha,
        "sha_target": sha_target,
        "container": "zip",
        "segments": len(seg_keys),
        "seg_size": seg_size,
        "index": first_index,
    }
    records[seed_key] = {
        "type": "manifest",
        "value": json.dumps(manifest, separators=(",", ":")),
    }

    # Ceiling guard: no record value may exceed the single-TXT payload limit.
    biggest = 0
    for k, rec in records.items():
        vlen = len(rec["value"].encode())
        biggest = max(biggest, vlen)
        if vlen > TXT_RECORD_CEILING:
            raise SystemExit(
                f"record {k} value is {vlen}B, exceeds ceiling {TXT_RECORD_CEILING}; "
                f"lower --payload-max"
            )

    store = {
        "meta": {
            "version": 1,
            "zone": args.zone,
            "ttl": args.ttl,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "manifest_id": sha[:16],
            "seed_key": seed_key,
        },
        "records": records,
    }
    Path(args.out).write_text(json.dumps(store, indent=2))

    print(f"seed key : {seed_key}")
    print(f"seed FQDN: {seed_key}.{args.zone}")
    print(f"segments : {len(seg_keys)}   indexes: {len(index_records)}   records: {len(records)}")
    print(f"seg size : {seg_size} B raw -> {seg_size * 4 // 3} base64 chars")
    print(f"largest  : {biggest} B  (ceiling {TXT_RECORD_CEILING})")
    print(f"zone file: {args.out}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="txtfs-encode", description="Pack file(s) into a TXT zone store."
    )
    ap.add_argument("files", nargs="+", help="input file(s); multiple are zipped together")
    ap.add_argument("--zone", required=True, help="serving zone, e.g. f.example.com")
    ap.add_argument("--out", default="zone.json", help="output zone store path")
    ap.add_argument("--mode", choices=list(MODES), default="direct",
                    help="direct (TCP, big records) or compatible (EDNS/UDP, small)")
    ap.add_argument("--payload-max", type=int, default=None, dest="payload_max",
                    help="override base64 chars per record (default: mode preset)")
    ap.add_argument("--words", type=int, default=3, help="dictionary words per key")
    ap.add_argument("--wordlist", default="wordlist.txt", help="wordlist path")
    ap.add_argument("--ttl", type=int, default=3600, help="record TTL seconds")
    ap.add_argument("--name", default=None, help="archive label for multi-file input")
    ap.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible keys")
    encode(ap.parse_args(argv))


if __name__ == "__main__":
    main()
