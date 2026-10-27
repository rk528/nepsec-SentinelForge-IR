"""Password hashing, opaque token generation and constant-time comparison."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2id with library defaults

# A real hash used when the account does not exist, so that a failed login
# takes the same time whether or not the email is registered.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

ROLE_RANK = {"viewer": 0, "analyst": 1, "lead": 2, "admin": 3}

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def role_at_least(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[minimum]


def validate_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() == password or password.upper() == password or not any(c.isdigit() for c in password):
        raise ValueError("Password must mix upper and lower case letters and include a digit")
