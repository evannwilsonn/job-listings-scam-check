"""
Template memory: the detector remembers the wording of every scam a reviewer confirms, and recognizes the next copy of
it minutes later, long before any retrain.

Why it exists
  Scammers rotate the parts the identifier memory (defense.py) catches: emails, numbers, wallets, domains. The script
  itself changes much more slowly. A reviewer confirming one "assistant needed, $450 weekly, reply to my personal
  email" message should protect the next student who pastes the same script with a fresh address.

How it works
  * Each confirmed scam is kept as a bottom-k sketch of its word trigrams (the same near-copy notion learning.py uses
    for scam waves), with the date and a short title. A sketch is 128 small integers; the text itself is not stored here.
  * A new text is compared against every sketch (a few thousand fit comfortably). Jaccard is estimated from the
    sketches; MATCH (0.6) counts as the same template, EXACT (0.9) as a near-verbatim copy.
  * A "legit" or "undo" decision on the same text forgets it, so a mistaken label can't keep flagging real listings.
  * The store is an append-only JSONL file (SCAM_MEMORY_PATH, written by the site); `load()` replays it.
  * Email addresses and links are masked before hashing: they are identifiers (defense.py has its own memory for them)
    and must not leak through a shared sketch.

Sharing between schools
  * Sketches are keyed hashes (blake2b with SCAM_MEMORY_KEY). Partner schools that share a key (the site uses
    SHARE_HMAC_KEY, the same trust model as shared contact details) can compare sketches without seeing any text; without
    the key a sketch is a list of meaningless numbers.
  * A partner's feed is the whole current list: `import_peer` replaces everything from that source, so anything they
    forget or retract disappears here too.
  * A match against a partner's template is only ever a warning. Our own reviewers' confirmations can be critical.

What it is allowed to do
  * Same policy as the identifier memory: reviewer-confirmed evidence may raise a verdict, never lower one. A near-verbatim
    copy is critical; a same-template match is a warning that sends the item to a person. Every finding says which
    confirmed scam it matched and how closely, so a reviewer can disagree and forget it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import time
from pathlib import Path

from .ml import clean, tokens

K = 128                  # sketch size: bottom-k of the trigram hashes
MATCH = 0.6              # estimated Jaccard that counts as the same template (learning.py's NEAR_COPY)
EXACT = 0.9              # a near-verbatim copy
MIN_SHINGLES = 12        # texts shorter than this are too small to match on wording alone
MAX_ENTRIES = 5000       # oldest templates are dropped past this


_IDENT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?://\S+|www\.\S+")


def current_key() -> bytes:
    return os.environ.get("SCAM_MEMORY_KEY", "").encode()[:64]


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"memory-key:" + key).hexdigest()[:8] if key else "0"


def keyring() -> dict:
    """Key id -> key for every key this site can compute sketches with: its own, the peer key, and the unkeyed default."""
    keys = [b"", current_key(), os.environ.get("SCAM_MEMORY_PEER_KEY", "").encode()[:64]]
    return {key_id(k): k for k in keys}


def _h(s: str, key: bytes = b"") -> int:
    return struct.unpack("<Q", hashlib.blake2b(s.encode(), digest_size=8, key=key).digest())[0]


def shingles(text: str) -> set:
    t = tokens(clean(_IDENT.sub(" ", text or "")))
    return {" ".join(t[i:i + 3]) for i in range(max(0, len(t) - 2))}


def sketch(text: str, key: bytes | None = None) -> list[int]:
    """The K smallest trigram hashes, sorted. Jaccard(A, B) is estimated by merging two sketches made with the same key."""
    key = current_key() if key is None else key
    return sorted({_h(s, key) for s in shingles(text)})[:K]


def similarity(a: list[int], b: list[int]) -> float:
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    merged = sorted(sa | sb)[:K]
    return sum(1 for x in merged if x in sa and x in sb) / len(merged)


def text_key(text: str) -> str:
    return hashlib.sha256(" ".join(tokens(clean(text))).encode()).hexdigest()[:24]


class TemplateMemory:
    def __init__(self, entries: list[dict] | None = None):
        self.entries: dict[str, dict] = {}
        for e in entries or []:
            self.apply(e)

    def apply(self, e: dict) -> None:
        if e.get("op") == "forget":
            self.entries.pop(e["key"], None)
        elif e.get("op") == "drop_source":
            for k in [k for k, x in self.entries.items() if x.get("source") == e["source"]]:
                self.entries.pop(k)
        else:
            self.entries[e["key"]] = e
            while len(self.entries) > MAX_ENTRIES:
                self.entries.pop(next(iter(self.entries)))

    def match(self, text: str) -> dict | None:
        """The best confirmed scam this text copies, or None."""
        ring, sketches = keyring(), {}
        best = None
        for e in self.entries.values():
            kid = e.get("kid", "0")
            if kid not in ring:
                continue                                    # made with a key this site doesn't hold
            if kid not in sketches:
                sketches[kid] = sketch(text, ring[kid])
            sk = sketches[kid]
            if len(sk) < MIN_SHINGLES:
                return None
            s = similarity(sk, e["sketch"])
            if s >= MATCH and (best is None or s > best[0]):
                best = (s, e)
        if not best:
            return None
        s, e = best
        return {"similarity": round(s, 3), "exact": s >= EXACT, "key": e["key"], "title": e.get("title", ""),
                "when": e.get("when", ""), "source": e.get("source", ""), "note": e.get("note", ""),
                "peer": str(e.get("source", "")).startswith("peer:")}

    def finding(self, text: str) -> dict | None:
        m = self.match(text)
        if not m:
            return None
        when = f" on {m['when']}" if m["when"] else ""
        what = f"“{m['title']}”" if m["title"] else "a scam"
        if m["peer"]:
            school = m["source"][5:] or "a partner school"
            return {"rule_id": "peer_scam_template", "severity": "warning", "weight": 25 if m["exact"] else 20,
                    "title": "Reads like a scam confirmed at another school",
                    "why": (f"About {round(m['similarity'] * 100)}% of its wording matches a scam that reviewers at {school} confirmed{when}. "
                            "Scam scripts move from campus to campus. A reviewer here decides."),
                    "matched": [f"{round(m['similarity'] * 100)}% match", school],
                    "memory": {"key": m["key"], "similarity": m["similarity"], "source": m["source"]}}
        if m["exact"]:
            return {"rule_id": "confirmed_scam_copy", "severity": "critical", "weight": 30,
                    "title": "A copy of a scam our reviewers confirmed",
                    "why": (f"This is {round(m['similarity'] * 100)}% the same wording as {what}, which a reviewer confirmed as a scam{when}. "
                            "Scammers reuse their scripts with new names and numbers."),
                    "matched": [f"{round(m['similarity'] * 100)}% match", m["when"] or "confirmed"],
                    "memory": {"key": m["key"], "similarity": m["similarity"]}}
        return {"rule_id": "confirmed_scam_template", "severity": "warning", "weight": 20,
                "title": "Reads like a scam our reviewers confirmed",
                "why": (f"About {round(m['similarity'] * 100)}% of its wording matches {what}, confirmed as a scam{when}. "
                        "It can send this to a person or suggest caution; a reviewer decides."),
                "matched": [f"{round(m['similarity'] * 100)}% match", m["when"] or "confirmed"],
                "memory": {"key": m["key"], "similarity": m["similarity"]}}

    def __len__(self) -> int:
        return len(self.entries)


# ---------- the file store ----------

def memory_path() -> Path | None:
    p = os.environ.get("SCAM_MEMORY_PATH", "")
    return Path(p) if p else None


_cache: dict = {}


def load(path: Path | None = None) -> TemplateMemory | None:
    """The memory file replayed, cached by its size and mtime; None when there is no file."""
    p = path or memory_path()
    if not p or not p.exists():
        return None
    st = p.stat()
    sig = (str(p), st.st_size, st.st_mtime)
    if _cache.get("sig") != sig:
        entries = []
        for line in p.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
        _cache.update({"sig": sig, "mem": TemplateMemory(entries)})
    return _cache["mem"]


def _append(p: Path, e: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(e, separators=(",", ":")) + "\n")


def remember(text: str, *, title: str = "", source: str = "reviewer", note: str = "", path: Path | None = None) -> str | None:
    """Keep the wording of a confirmed scam. Returns its key, or None when the text is too short or there is no store."""
    p = path or memory_path()
    if not p:
        return None
    sk = sketch(text)
    if len(sk) < MIN_SHINGLES:
        return None
    e = {"key": text_key(text), "sketch": sk, "kid": key_id(current_key()), "title": (title or "")[:80], "when": time.strftime("%Y-%m-%d"),
         "source": source[:40], "note": (note or "")[:120]}
    _append(p, e)
    return e["key"]


def forget(text: str, *, path: Path | None = None) -> None:
    """A reviewer said this is not a scam (or undid a label): the template stops matching."""
    p = path or memory_path()
    if p:
        _append(p, {"op": "forget", "key": text_key(text)})


def shareable(path: Path | None = None, key: bytes | None = None, limit: int = 2000) -> list[dict]:
    """Our own confirmed templates made with `key` (the shared key), newest last: sketch and date only, never a title or note."""
    m = load(path)
    if not m:
        return []
    kid = key_id(current_key() if key is None else key)
    own = [e for e in m.entries.values() if e.get("kid", "0") == kid and not str(e.get("source", "")).startswith("peer:")]
    return [{"sketch": e["sketch"], "when": e.get("when", "")} for e in own[-limit:]]


def import_peer(source: str, templates: list, path: Path | None = None, key: bytes | None = None) -> int:
    """Replace everything from `source` with its current list. Each sketch must look like one (K or fewer unsigned 64-bit ints)."""
    p = path or memory_path()
    if not p:
        return 0
    src = "peer:" + str(source)[:60]
    kid = key_id(os.environ.get("SCAM_MEMORY_PEER_KEY", "").encode()[:64] if key is None else key)
    lines = [{"op": "drop_source", "source": src}]
    for t in (templates or [])[:5000]:
        sk = t.get("sketch") if isinstance(t, dict) else None
        if (not isinstance(sk, list) or not (MIN_SHINGLES <= len(sk) <= K)
                or not all(isinstance(x, int) and 0 <= x < 2 ** 64 for x in sk)):
            continue
        sk = sorted(set(sk))
        lines.append({"key": "p" + hashlib.sha256((src + json.dumps(sk)).encode()).hexdigest()[:23], "sketch": sk, "kid": kid,
                      "title": "", "when": str(t.get("when", ""))[:10], "source": src, "note": ""})
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in lines))
    return len(lines) - 1


def finding(text: str, path: Path | None = None) -> dict | None:
    """The one thing a scam check calls. Never raises."""
    try:
        m = load(path)
        return m.finding(text) if m else None
    except Exception:                                   # noqa: BLE001
        return None
