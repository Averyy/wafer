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


def generate_cd(
    st: int, difficulty: int = 10, subchallenges: int = 2
) -> str:
    """Generate a Kasada CD (proof-of-work) token.

    Pure SHA-256 hash grinding with "tp-v2-input" platform string.
    Returns a JSON string suitable for the x-kpsdk-cd header.
    """
    start = time.monotonic()
    threshold = (2**52 * subchallenges) // difficulty
    answers = []

    for _ in range(subchallenges):
        while True:
            nonce = random.randint(1, 2**31)
            input_str = f"tp-v2-input, {st}, {nonce}"
            h = hashlib.sha256(input_str.encode()).hexdigest()
            value = int(h[:13], 16)
            if value <= threshold:
                answers.append(nonce)
                break

    work_time = int((time.monotonic() - start) * 1000)

    payload = {
        "answers": answers,
        "duration": work_time,
        "d": difficulty,
        "st": st,
        "rst": int(time.time() * 1000),
    }
    return json.dumps(payload, separators=(",", ":"))
