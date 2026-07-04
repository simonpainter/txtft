"""End-to-end round-trip: encode -> serve (transfer) -> fetch/decode.

Exercises segmentation, index chaining, TXT string splitting, TCP framing, and
reassembly in one pass. Run with ``pytest`` or directly with ``python``.
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run_roundtrip(tmp_path: Path, payload_max: str, mode: str, size: int) -> None:
    src = tmp_path / "sample.bin"
    data = os.urandom(size)
    src.write_bytes(data)

    zone = "f.example.com"
    zonefile = tmp_path / "zone.json"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "encode",
            str(src),
            "--zone",
            zone,
            "--out",
            str(zonefile),
            "--wordlist",
            str(ROOT / "wordlist.txt"),
            "--words",
            "4",
            "--payload-max",
            payload_max,
        ],
        cwd=ROOT,
        check=True,
    )
    seed = json.loads(zonefile.read_text())["meta"]["seed_key"]

    port = free_port()
    server = subprocess.Popen(
        [sys.executable, "-m", "serve", str(zonefile), "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
    )
    try:
        time.sleep(1.5)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "fetch",
                seed,
                "--zone",
                zone,
                "--server",
                "127.0.0.1",
                "--port",
                str(port),
                "--mode",
                mode,
                "--out",
                str(tmp_path / "recovered.bin"),
                "--out-dir",
                str(tmp_path / "out"),
            ],
            cwd=ROOT,
            check=True,
        )
    finally:
        server.terminate()
        server.wait(timeout=5)

    recovered = (tmp_path / "recovered.bin").read_bytes()
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(data).hexdigest()


def test_encode_transfer_decode_direct(tmp_path):
    # Small payload_max forces many segments AND a chained index.
    _run_roundtrip(tmp_path, payload_max="4000", mode="direct", size=300_000)


def test_encode_transfer_decode_compatible(tmp_path):
    _run_roundtrip(tmp_path, payload_max="1200", mode="compatible", size=120_000)


if __name__ == "__main__":
    import tempfile

    for name, pmax, mode, size in [
        ("direct/chained", "4000", "direct", 300_000),
        ("compatible/udp", "1200", "compatible", 120_000),
    ]:
        with tempfile.TemporaryDirectory() as d:
            print(f"=== {name} ===")
            _run_roundtrip(Path(d), pmax, mode, size)
            print(f"=== {name}: OK ===\n")
    print("all round-trips passed")
