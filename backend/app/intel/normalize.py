"""IOC normalisation and syntax validation.

Accepts common "defanged" notations (hxxp, [.], (.), [:]) and returns a
canonical (type, value) pair. Validation is syntactic only: a well-formed
indicator says nothing about whether it is malicious.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


class IocError(ValueError):
    pass


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"^hxxp(s?)://", r"http\1://", v, flags=re.I)
    v = re.sub(r"^fxp://", "ftp://", v, flags=re.I)
    for token in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        v = v.replace(token, ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    return v


def _domain(value: str) -> str:
    host = value.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IocError("domain is not valid") from exc
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise IocError("domain is not valid")
    if not re.match(r"^(xn--[a-z0-9-]+|[a-z]{2,63})$", labels[-1]):
        raise IocError("domain has an invalid top-level label")
    return host


def normalise(raw: str) -> tuple[str, str]:
    if not raw or len(raw) > 2048:
        raise IocError("indicator must be between 1 and 2048 characters")
    value = refang(raw)
    if any(c.isspace() for c in value):
        raise IocError("indicator must not contain whitespace")

    try:
        ip = ipaddress.ip_address(value.strip("[]"))
        return ("ipv4" if ip.version == 4 else "ipv6", str(ip))
    except ValueError:
        pass

    if _HEX.match(value) and len(value) in _HASH_TYPES:
        return _HASH_TYPES[len(value)], value.lower()

    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https"):
            raise IocError("only http and https URLs are supported")
        if not parts.hostname:
            raise IocError("URL has no host")
        try:
            host = str(ipaddress.ip_address(parts.hostname))
            if ":" in host:
                host = f"[{host}]"
        except ValueError:
            host = _domain(parts.hostname)
        default_port = {"http": 80, "https": 443}[parts.scheme.lower()]
        netloc = host if parts.port in (None, default_port) else f"{host}:{parts.port}"
        return "url", urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))

    return "domain", _domain(value)


def url_host(url: str) -> str | None:
    return urlsplit(url).hostname
