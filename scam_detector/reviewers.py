"""
Reviewer accounts for the review page: password rules, hashing, session tokens, CSRF.

    pw_hash = hash_password(pw)               scrypt, standard library only
    verify_password(pw, pw_hash) -> bool      constant time; DUMMY_HASH when the email is unknown
    token, token_hash = new_session()         the cookie holds token; the store keeps only token_hash
    csrf_for(token) / csrf_ok(token, value)   form tokens bound to the session

Accounts are made with tools/reviewers.py, never from the web. Nothing here touches the network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

MIN_PASSWORD = 12
SESSION_HOURS = 12
_N, _R, _P = 2 ** 14, 8, 1


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def password_problems(pw: str, email: str = "") -> list:
    """Every unmet rule, in plain words. Empty means acceptable. Length is what matters, so that's the main rule."""
    out = []
    pw = pw or ""
    if len(pw) < MIN_PASSWORD:
        out.append(f"at least {MIN_PASSWORD} characters")
    if pw and len(set(pw)) < 5:
        out.append("more than a few different characters")
    local = normalize_email(email).split("@")[0]
    if local and len(local) >= 4 and local in pw.lower():
        out.append("not your email name in it")
    return out


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, want = (stored or "").split("$")
        dk = hashlib.scrypt((pw or "").encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


# Checked when the email is unknown, so a missing account takes as long to reject as a wrong password.
DUMMY_HASH = hash_password("not-a-real-password-only-for-timing")


def token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


def new_session() -> tuple:
    token = secrets.token_urlsafe(32)
    return token, token_hash(token)


def temp_password() -> str:
    """For a new account or a reset: letters and digits only, so it can be read aloud or pasted anywhere."""
    return secrets.token_urlsafe(15).replace("-", "x").replace("_", "y")


def csrf_for(token: str) -> str:
    return hmac.new((token or "").encode(), b"lurecheck-review-csrf", hashlib.sha256).hexdigest()


def csrf_ok(token: str, value: str) -> bool:
    return bool(token) and hmac.compare_digest(csrf_for(token), value or "")
