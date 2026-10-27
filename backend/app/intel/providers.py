"""Threat intelligence provider integrations.

Each provider maps its own response into a common shape. Rules that apply to
every provider:

* A missing record, zero reports or zero detections is reported as
  ``unknown``. It is never treated as evidence that an indicator is safe.
* ``harmless`` is only used when the provider positively says so.
* Raw responses are trimmed to the fields shown in the UI.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import get_settings


@dataclass
class ProviderResult:
    status: str  # ok | not_found | error | rate_limited | unconfigured | unsupported
    reported_verdict: str = "unknown"  # malicious | suspicious | harmless | unknown
    score: float | None = None
    confidence: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def http_client() -> httpx.Client:
    """Overridden in tests to inject a mock transport."""
    return httpx.Client(timeout=get_settings().intel_http_timeout_seconds, headers={"User-Agent": "SentinelForge-IR/0.1"})


class Provider:
    name: str
    label: str
    supported: tuple[str, ...]
    terms_url: str

    def api_key(self) -> str | None:
        raise NotImplementedError

    def configured(self) -> bool:
        return bool(self.api_key())

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        if ioc_type not in self.supported:
            return ProviderResult(status="unsupported")
        if not self.configured():
            return ProviderResult(status="unconfigured")
        try:
            with http_client() as client:
                return self._lookup(client, ioc_type, value)
        except httpx.TimeoutException:
            return ProviderResult(status="error", error="Provider timed out")
        except httpx.HTTPError as exc:
            return ProviderResult(status="error", error=f"Provider request failed: {type(exc).__name__}")
        except (KeyError, ValueError, TypeError):
            return ProviderResult(status="error", error="Provider returned an unexpected response")

    def _lookup(self, client: httpx.Client, ioc_type: str, value: str) -> ProviderResult:
        raise NotImplementedError

    @staticmethod
    def _common_errors(resp: httpx.Response) -> ProviderResult | None:
        if resp.status_code == 404:
            return ProviderResult(status="not_found")
        if resp.status_code == 429:
            return ProviderResult(status="rate_limited", error="Provider quota or rate limit reached")
        if resp.status_code in (401, 403):
            return ProviderResult(status="error", error="Provider rejected the API key")
        if resp.status_code >= 400:
            return ProviderResult(status="error", error=f"Provider returned HTTP {resp.status_code}")
        return None


class VirusTotal(Provider):
    name = "virustotal"
    label = "VirusTotal"
    supported = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
    terms_url = "https://docs.virustotal.com/docs/please-read"

    def api_key(self) -> str | None:
        k = get_settings().virustotal_api_key
        return k.get_secret_value() if k else None

    def _lookup(self, client: httpx.Client, ioc_type: str, value: str) -> ProviderResult:
        base = "https://www.virustotal.com/api/v3"
        if ioc_type in ("ipv4", "ipv6"):
            path = f"/ip_addresses/{value}"
        elif ioc_type == "domain":
            path = f"/domains/{value}"
        elif ioc_type == "url":
            path = "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else:
            path = f"/files/{value}"
        resp = client.get(base + path, headers={"x-apikey": self.api_key() or ""})
        if err := self._common_errors(resp):
            return err
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        if malicious >= 3:
            verdict = "malicious"
        elif malicious or suspicious:
            verdict = "suspicious"
        elif harmless and total >= 10:
            verdict = "harmless"
        else:
            verdict = "unknown"
        return ProviderResult(
            status="ok",
            reported_verdict=verdict,
            score=float(malicious),
            confidence="high" if total >= 50 else "medium" if total >= 10 else "low",
            summary={
                "engines_malicious": malicious,
                "engines_suspicious": suspicious,
                "engines_harmless": harmless,
                "engines_total": total,
                "reputation": attrs.get("reputation"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
            },
        )


class AbuseIPDB(Provider):
    name = "abuseipdb"
    label = "AbuseIPDB"
    supported = ("ipv4", "ipv6")
    terms_url = "https://www.abuseipdb.com/legal"

    def api_key(self) -> str | None:
        k = get_settings().abuseipdb_api_key
        return k.get_secret_value() if k else None

    def _lookup(self, client: httpx.Client, ioc_type: str, value: str) -> ProviderResult:
        resp = client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": self.api_key() or "", "Accept": "application/json"},
        )
        if err := self._common_errors(resp):
            return err
        data = resp.json()["data"]
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        if data.get("isWhitelisted"):
            verdict = "harmless"
        elif score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        else:
            verdict = "unknown"
        return ProviderResult(
            status="ok",
            reported_verdict=verdict,
            score=float(score),
            confidence="high" if reports >= 25 else "medium" if reports >= 5 else "low",
            summary={
                "abuse_confidence_score": score,
                "total_reports": reports,
                "distinct_reporters": data.get("numDistinctUsers"),
                "last_reported_at": data.get("lastReportedAt"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted"),
            },
        )


class AlienVaultOTX(Provider):
    name = "otx"
    label = "AlienVault OTX"
    supported = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
    terms_url = "https://otx.alienvault.com/"

    _SECTION = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}

    def api_key(self) -> str | None:
        k = get_settings().otx_api_key
        return k.get_secret_value() if k else None

    def _lookup(self, client: httpx.Client, ioc_type: str, value: str) -> ProviderResult:
        resp = client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{self._SECTION[ioc_type]}/{value}/general",
            headers={"X-OTX-API-KEY": self.api_key() or ""},
        )
        if err := self._common_errors(resp):
            return err
        body = resp.json()
        pulse_info = body.get("pulse_info") or {}
        count = int(pulse_info.get("count") or 0)
        pulses = [p.get("name", "")[:140] for p in (pulse_info.get("pulses") or [])[:5]]
        # Appearing in community pulses means "reported", not "confirmed malicious".
        return ProviderResult(
            status="ok",
            reported_verdict="suspicious" if count else "unknown",
            score=float(count),
            confidence="medium" if count >= 5 else "low",
            summary={"pulse_count": count, "recent_pulses": pulses, "reputation": body.get("reputation")},
        )


PROVIDERS: list[Provider] = [VirusTotal(), AbuseIPDB(), AlienVaultOTX()]
