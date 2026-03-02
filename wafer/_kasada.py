"""Kasada CD (proof-of-work) generator and per-domain CT/ST cache.

Pure Python, no external deps. The CD token is a per-request SHA-256
proof-of-work that Kasada validates server-side. The CT token is a
browser fingerprint obtained once via browser solve, reusable ~30 min.
"""

import hashlib
import json
import logging
import random
import time
from dataclasses import dataclass

logger = logging.getLogger("wafer")


@dataclass
class KasadaSession:
    """Per-domain Kasada token storage."""

    ct: str  # x-kpsdk-ct from /tl response
    st: int  # x-kpsdk-st from /tl response
    cookies: list[dict]  # tkrm_alpekz_s1.3 etc.
    expires: float  # monotonic deadline (~30 min)


# Module-level cache: domain → KasadaSession
_sessions: dict[str, KasadaSession] = {}


def store_session(
    domain: str,
    ct: str,
    st: int,
    cookies: list[dict],
    ttl: float = 1800,
) -> None:
    """Cache a Kasada session for a domain."""
    _sessions[domain] = KasadaSession(
        ct=ct,
        st=st,
        cookies=cookies,
        expires=time.monotonic() + ttl,
    )
    logger.info(
        "Kasada session stored for %s (TTL=%ds)", domain, ttl
    )


def get_session(domain: str) -> KasadaSession | None:
    """Get cached Kasada session, or None if expired/missing."""
    session = _sessions.get(domain)
    if session is None:
        return None
    if time.monotonic() > session.expires:
        del _sessions[domain]
        logger.debug("Kasada session expired for %s", domain)
        return None
    return session


def _hash_difficulty(h: str) -> float:
    """Compute hash difficulty: 2^52 / (parseInt(h[0:13], 16) + 1)."""
    return 0x10000000000000 / (int(h[:13], 16) + 1)


def generate_cd(
    st: int, difficulty: int = 10, subchallenges: int = 2
) -> str:
    """Generate a Kasada CD (proof-of-work) token.

    Pure SHA-256 hash grinding with "tp-v2-input" platform string and
    hash chaining between subchallenges. Returns a JSON string suitable
    for the x-kpsdk-cd header.

    Algorithm (from Fweak gist / tramodule Kasada-Solver):
    1. Generate random 32-hex challenge_id
    2. Initial hash = SHA256("tp-v2-input, {st}, {challenge_id}")
    3. Per subchallenge: iterate nonces from 1, hash "{nonce}, {hash_val}",
       chain hash_val = h when difficulty met
    """
    challenge_id = random.randbytes(16).hex()
    hash_val = hashlib.sha256(
        f"tp-v2-input, {st}, {challenge_id}".encode()
    ).hexdigest()

    target = difficulty / subchallenges
    answers = []

    for _ in range(subchallenges):
        nonce = 1
        while True:
            h = hashlib.sha256(
                f"{nonce}, {hash_val}".encode()
            ).hexdigest()
            if _hash_difficulty(h) >= target:
                answers.append(nonce)
                hash_val = h  # chain for next subchallenge
                break
            nonce += 1

    d = random.randint(1400, 2700)

    payload = {
        "workTime": int(time.time() * 1000) - d,
        "id": challenge_id,
        "answers": answers,
        "duration": round(random.uniform(2.0, 8.0), 1),
        "d": d,
        "st": st,
        "rst": st + d,
    }
    return json.dumps(payload, separators=(",", ":"))
