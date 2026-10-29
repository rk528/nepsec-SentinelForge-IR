"""The admin console's passkey unlock, as SentinelForge checks it.

The console opens only after a passkey registered on the owner's device is used. NepSec Intel checks the passkey and
signs a 12-hour "gate" token (ES256), kept as the console_gate cookie on the console's address and so sent here with
every console request. It is checked against NepSec Intel's public key, fetched once an hour; if no key can be had,
nothing is let through.
"""

from __future__ import annotations

import base64
import json
import logging
import time

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app.config import get_settings

UNLOCK_COOKIE = "console_gate"
KEY_SECONDS = 3600
LOCKED = "Unlock the admin console with your passkey first."

log = logging.getLogger(__name__)
_cache: dict[str, object] = {"key": None, "at": 0.0}


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key() -> ec.EllipticCurvePublicKey | None:
    held = _cache["key"]
    if held is not None and time.time() - float(_cache["at"]) < KEY_SECONDS:
        return held  # type: ignore[return-value]
    try:
        response = httpx.get(get_settings().console_gate_key_url, timeout=8.0, headers={"User-Agent": "SentinelForge-IR/0.1"})
        response.raise_for_status()
        jwk = response.json()
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            return held  # type: ignore[return-value]
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(_unb64(jwk["x"]), "big"), int.from_bytes(_unb64(jwk["y"]), "big"), ec.SECP256R1()).public_key()
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        # Keep the last good key through a short outage; with none, refuse.
        log.warning("console gate key unavailable: %s", type(exc).__name__)
        return held  # type: ignore[return-value]
    _cache.update(key=key, at=time.time())
    return key


def set_key_for_tests(key: ec.EllipticCurvePublicKey | None) -> None:
    _cache.update(key=key, at=time.time() if key else 0.0)


def console_unlocked(token: str | None, now: float | None = None) -> bool:
    """Whether a request carries a passkey unlock NepSec Intel signed and that has not run out. Never raises."""
    if not token or len(token) > 1024 or token.count(".") != 1:
        return False
    payload, signature = token.split(".")
    try:
        raw = _unb64(signature)
        key = _key()
        if key is None or len(raw) != 64:
            return False
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), payload.encode(), ec.ECDSA(hashes.SHA256()))
        body = json.loads(_unb64(payload))
    except (InvalidSignature, ValueError, json.JSONDecodeError):
        return False
    return body.get("k") == "gate" and isinstance(body.get("exp"), int) and body["exp"] > (now if now is not None else time.time())
