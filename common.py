"""Shared helpers for txtfs.

Sizing math, TXT character-string splitting/joining, plausible key generation,
and wordlist loading. These are the fiddly, easy-to-get-wrong bits that the three
tools all depend on, so they live in one place with the constants that drive them.
"""
from __future__ import annotations

import random
from pathlib import Path

# --- DNS wire limits (RFC 1035) -------------------------------------------------

#: Max data octets in a single TXT character-string (1 length octet prefixes it).
TXT_STRING_MAX = 255

#: Practical single-TXT payload ceiling. RDLENGTH is 16 bit (65535); splitting N
#: payload bytes into 255-byte strings costs ceil(N/255) length octets, leaving
#: ~65279 bytes of actual payload. Any record value must stay at or under this.
TXT_RECORD_CEILING = 65279

#: Operating-mode presets: base64 chars per record value.
#:   direct     -> large records, carried over TCP against the authoritative server.
#:   compatible -> small records that survive EDNS0/UDP through recursive resolvers.
MODES = {
    "direct": 60000,
    "compatible": 1200,
}


def raw_segment_bytes(payload_max: int) -> int:
    """Largest raw byte count whose base64 length is <= ``payload_max``.

    Rounded down to a multiple of 3 so base64 emits no padding and no partial
    trailing quantum: ``raw * 4 // 3`` base64 chars exactly.
    """
    return (payload_max // 4) * 3


def to_txt_strings(payload: bytes) -> list[bytes]:
    """Split a payload into <=255-byte character-strings for one TXT record.

    Always returns at least one (possibly empty) string, since a TXT record
    requires at least one character-string.
    """
    if not payload:
        return [b""]
    return [payload[i:i + TXT_STRING_MAX] for i in range(0, len(payload), TXT_STRING_MAX)]


def join_txt_strings(strings) -> bytes:
    """Concatenate TXT character-strings with no separator (standard semantics)."""
    return b"".join(bytes(s) for s in strings)


class KeyGenerator:
    """Allocates unique, plausible-looking DNS labels from a wordlist.

    Keys are ``words`` dictionary words joined by hyphens, e.g. ``copper-lantern-drift``.
    Collisions are re-rolled; each returned key is guaranteed unique within this
    generator's lifetime and a valid single DNS label (<= 63 octets, LDH).
    """

    def __init__(self, wordlist: list[str], words: int = 3, seed: int | None = None):
        if len(wordlist) < 4:
            raise ValueError("wordlist too small; need at least a few words")
        if words < 1:
            raise ValueError("words must be >= 1")
        self.words = wordlist
        self.n = words
        self.used: set[str] = set()
        self.rng = random.Random(seed)

    def allocate(self) -> str:
        for _ in range(100000):
            key = "-".join(self.rng.choice(self.words) for _ in range(self.n))
            if len(key) > 63:
                continue
            if key not in self.used:
                self.used.add(key)
                return key
        raise RuntimeError(
            "keyspace exhausted; use --words 4 or a larger wordlist"
        )


def load_wordlist(path: str | Path) -> list[str]:
    """Load and normalise a wordlist file: lowercase ASCII alpha words, deduped, sorted."""
    words = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        w = line.strip().lower()
        if w and w.isascii() and w.isalpha() and 2 <= len(w) <= 12:
            words.append(w)
    out = sorted(set(words))
    if len(out) < 4:
        raise ValueError(f"wordlist {path} yielded too few usable words ({len(out)})")
    return out
