"""txtfs-fetch: download and reassemble a file from a txtfs zone.

Given a seed key, resolves the manifest, walks the index chain to collect ordered
segment keys, fetches every segment (concurrently), concatenates the decoded bytes
back into the zip, verifies integrity, and extracts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from .common import join_txt_strings


class FetchError(SystemExit):
    pass


def query_txt(server: str, port: int, fqdn: str, timeout: float,
              retries: int, mode: str) -> bytes:
    """Resolve a single TXT record and return its concatenated payload bytes.

    In ``direct`` mode queries go straight over TCP (large records). In
    ``compatible`` mode they try EDNS/UDP first and fall back to TCP on TC.
    NXDOMAIN is fatal (no retry); timeouts are retried.
    """
    name = dns.name.from_text(fqdn)
    query = dns.message.make_query(name, dns.rdatatype.TXT, use_edns=0, payload=4096)

    last_exc: Exception | None = None
    for _ in range(max(1, retries)):
        try:
            if mode == "direct":
                resp = dns.query.tcp(query, server, port=port, timeout=timeout)
            else:
                resp = dns.query.udp(query, server, port=port, timeout=timeout)
                if resp.flags & dns.flags.TC:
                    resp = dns.query.tcp(query, server, port=port, timeout=timeout)

            if resp.rcode() == dns.rcode.NXDOMAIN:
                raise FetchError(f"NXDOMAIN: {fqdn}")
            for rrset in resp.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    return join_txt_strings(rrset[0].strings)
            raise FetchError(f"no TXT answer for {fqdn} (rcode {dns.rcode.to_text(resp.rcode())})")
        except dns.exception.Timeout as exc:
            last_exc = exc
            continue
    raise FetchError(f"timed out resolving {fqdn}: {last_exc}")


def fetch(args) -> None:
    def q(key: str) -> bytes:
        return query_txt(args.server, args.port, f"{key}.{args.zone}",
                         args.timeout, args.retries, args.mode)

    # 1. Manifest.
    manifest = json.loads(q(args.seed).decode("utf-8"))
    print(f"file: {manifest['name']}   size: {manifest['size']}   "
          f"segments: {manifest['segments']}")

    # 2. Walk the index chain, collecting ordered segment keys.
    seg_keys: list[str] = []
    idx_key = manifest["index"]
    expected_i = 0
    while idx_key:
        index = json.loads(q(idx_key).decode("utf-8"))
        if index.get("i") != expected_i:
            raise FetchError(
                f"index ordinal mismatch: got {index.get('i')}, expected {expected_i}"
            )
        seg_keys.extend(index["keys"])
        idx_key = index.get("next")
        expected_i += 1

    if len(seg_keys) != manifest["segments"]:
        raise FetchError(
            f"segment count mismatch: index chain lists {len(seg_keys)}, "
            f"manifest says {manifest['segments']}"
        )

    # 3. Fetch segments concurrently; reassemble in index order.
    segments: list[bytes | None] = [None] * len(seg_keys)

    def get(item):
        i, key = item
        return i, q(key)

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for i, payload in pool.map(get, enumerate(seg_keys)):
            segments[i] = payload

    # 4. Reassemble the zip.
    zip_bytes = b"".join(base64.b64decode(s) for s in segments)

    # 5. Verify and extract.
    if manifest.get("sha_target") == "archive":
        if hashlib.sha256(zip_bytes).hexdigest() != manifest["sha256"]:
            raise FetchError("archive sha256 mismatch")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        bad = zf.testzip()
        if bad is not None:
            raise FetchError(f"zip CRC failure in member: {bad}")
        names = zf.namelist()
        zf.extractall(out_dir)

    if manifest.get("sha_target", "original") == "original" and len(names) == 1:
        extracted = out_dir / names[0]
        if hashlib.sha256(extracted.read_bytes()).hexdigest() != manifest["sha256"]:
            raise FetchError("original sha256 mismatch")
        if args.out:
            dest = Path(args.out)
            dest.parent.mkdir(parents=True, exist_ok=True)
            extracted.replace(dest)
            print(f"wrote {dest}")
        else:
            print(f"wrote {extracted}")
    else:
        print(f"extracted {len(names)} file(s) to {out_dir}")

    print("integrity: OK")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="txtfs-fetch", description="Download a file from a txtfs zone."
    )
    ap.add_argument("seed", help="seed key (leftmost label of the manifest record)")
    ap.add_argument("--zone", required=True, help="serving zone, e.g. f.example.com")
    ap.add_argument("--server", required=True, help="authoritative server IP")
    ap.add_argument("--port", type=int, default=53, help="server port")
    ap.add_argument("--mode", choices=["direct", "compatible"], default="direct",
                    help="direct (TCP) or compatible (EDNS/UDP with TCP fallback)")
    ap.add_argument("--concurrency", type=int, default=16, help="parallel segment fetches")
    ap.add_argument("--timeout", type=float, default=5.0, help="per-query timeout seconds")
    ap.add_argument("--retries", type=int, default=3, help="per-query retries on timeout")
    ap.add_argument("--out", default=None, help="output path for single-file downloads")
    ap.add_argument("--out-dir", default=".", dest="out_dir", help="extraction directory")
    fetch(ap.parse_args(argv))


if __name__ == "__main__":
    main()
