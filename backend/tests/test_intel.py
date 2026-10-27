"""Threat-intel normalisation, provider mapping (mocked HTTP) and caching."""

from __future__ import annotations

import httpx
import pytest

from app.config import get_settings
from app.intel import providers
from app.intel.normalize import IocError, normalise


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.7", ("ipv4", "203.0.113.7")),
        ("203[.]0[.]113[.]7", ("ipv4", "203.0.113.7")),
        ("2001:DB8::1", ("ipv6", "2001:db8::1")),
        ("Invoice-Portal.Example", ("domain", "invoice-portal.example")),
        ("invoice-portal[.]example", ("domain", "invoice-portal.example")),
        ("hxxps://Invoice-Portal.example:443/view?id=1", ("url", "https://invoice-portal.example/view?id=1")),
        ("http://198.51.100.4:8080", ("url", "http://198.51.100.4:8080/")),
        ("D41D8CD98F00B204E9800998ECF8427E", ("md5", "d41d8cd98f00b204e9800998ecf8427e")),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709")),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
    ],
)
def test_normalise_valid(raw: str, expected: tuple[str, str]) -> None:
    assert normalise(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a domain", "localhost", "javascript:alert(1)", "ftp://example.test/x", "a" * 3000, "-bad-.example", "abc.123"])
def test_normalise_rejects_invalid(raw: str) -> None:
    with pytest.raises(IocError):
        normalise(raw)


def _mock(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    calls: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    monkeypatch.setattr(providers, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(wrapped)))
    return calls


def test_unconfigured_providers_report_unconfigured(api_for) -> None:
    api = api_for("analyst")
    r = api.post("/api/v1/iocs/lookup", json={"value": "203.0.113.9"})
    assert r.status_code == 200, r.text
    statuses = {e["provider"]: e["status"] for e in r.json()["enrichments"]}
    assert statuses == {"virustotal": "unconfigured", "abuseipdb": "unconfigured", "otx": "unconfigured", "nepsecintel": "unconfigured"}
    assert all(e["reported_verdict"] == "unknown" for e in r.json()["enrichments"])


def test_virustotal_mapping_rate_limit_and_cache(api_for, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-not-real")
    get_settings.cache_clear()
    stats = {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10}
    calls = _mock(monkeypatch, lambda req: httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats, "reputation": -20}}}))
    api = api_for("analyst")

    r = api.post("/api/v1/iocs/lookup", json={"value": "198.51.100.66"})
    vt = next(e for e in r.json()["enrichments"] if e["provider"] == "virustotal")
    assert vt["status"] == "ok" and vt["reported_verdict"] == "malicious" and vt["cached"] is False
    assert calls[0].headers["x-apikey"] == "test-key-not-real"
    assert "/ip_addresses/198.51.100.66" in str(calls[0].url)

    # Second lookup is served from cache: no new HTTP request.
    r2 = api.post("/api/v1/iocs/lookup", json={"value": "198.51.100.66"})
    vt2 = next(e for e in r2.json()["enrichments"] if e["provider"] == "virustotal")
    assert vt2["cached"] is True and len(calls) == 1


def test_provider_rate_limit_is_reported_and_not_cached_long(api_for, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key-not-real")
    get_settings.cache_clear()
    _mock(monkeypatch, lambda req: httpx.Response(429, json={"error": "quota"}))
    api = api_for("analyst")
    r = api.post("/api/v1/iocs/lookup", json={"value": "invoice-portal.example"})
    vt = next(e for e in r.json()["enrichments"] if e["provider"] == "virustotal")
    assert vt["status"] == "rate_limited" and vt["reported_verdict"] == "unknown"


def test_zero_detections_is_unknown_not_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key-not-real")
    get_settings.cache_clear()
    _mock(monkeypatch, lambda req: httpx.Response(200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}}))
    result = providers.AbuseIPDB().lookup("ipv4", "198.51.100.5")
    assert result.status == "ok" and result.reported_verdict == "unknown"


def test_provider_timeout_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTX_API_KEY", "test-key-not-real")
    get_settings.cache_clear()

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout", request=req)

    _mock(monkeypatch, boom)
    result = providers.AlienVaultOTX().lookup("domain", "invoice-portal.example")
    assert result.status == "error" and result.reported_verdict == "unknown"


def _nepsec_body(level: str, score: int | None) -> dict:
    return {
        "indicator": {"type": "ipv4", "value": "198.51.100.77"},
        "assessment": {"score": score, "level": level, "title": "High risk", "factors": [{"points": 40, "source": "AbuseIPDB", "label": "Abuse score 90"}]},
        "results": [{"provider": "abuseipdb", "status": "ok"}, {"provider": "virustotal", "status": "ok"}, {"provider": "shodan", "status": "unconfigured"}],
    }


def test_nepsecintel_mapping_and_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEPSECINTEL_API_KEY", "tl_test-key-not-real")
    get_settings.cache_clear()
    calls = _mock(monkeypatch, lambda req: httpx.Response(200, json=_nepsec_body("malicious", 82)))
    result = providers.NepSecIntel().lookup("ipv4", "198.51.100.77")
    assert result.status == "ok" and result.reported_verdict == "malicious" and result.score == 82.0
    assert result.confidence == "medium" and result.summary["sources_answered"] == "2 of 3"
    assert result.summary["report_url"] == "https://nepsecintel.kuinkel.com/?q=198.51.100.77"
    assert calls[0].method == "POST" and calls[0].url.path == "/api/v1/lookup"
    assert calls[0].headers["authorization"] == "Bearer tl_test-key-not-real"


def test_nepsecintel_clean_is_unknown_not_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEPSECINTEL_API_KEY", "tl_test-key-not-real")
    get_settings.cache_clear()
    _mock(monkeypatch, lambda req: httpx.Response(200, json=_nepsec_body("clean", 0)))
    assert providers.NepSecIntel().lookup("ipv4", "198.51.100.77").reported_verdict == "unknown"


def test_nepsecintel_without_pro_plan_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEPSECINTEL_API_KEY", "tl_test-key-not-real")
    get_settings.cache_clear()
    _mock(monkeypatch, lambda req: httpx.Response(403, json={"detail": "The workspace is part of the Pro plan."}))
    result = providers.NepSecIntel().lookup("domain", "invoice-portal.example")
    assert result.status == "error" and result.reported_verdict == "unknown"


def test_analyst_verdict_is_separate_from_provider(api_for) -> None:
    api = api_for("analyst")
    ind = api.post("/api/v1/iocs/lookup", json={"value": "203.0.113.45"}).json()["indicator"]
    r = api.patch(f"/api/v1/iocs/{ind['id']}", json={"analyst_verdict": "malicious", "analyst_note": "Source of password guessing"})
    assert r.status_code == 200 and r.json()["analyst_verdict"] == "malicious"
    detail = api.get(f"/api/v1/iocs/{ind['id']}").json()
    assert detail["indicator"]["analyst_verdict"] == "malicious"
    assert all(e["reported_verdict"] == "unknown" for e in detail["enrichments"])


def test_invalid_ioc_returns_422(api_for) -> None:
    api = api_for("analyst")
    assert api.post("/api/v1/iocs/lookup", json={"value": "javascript:alert(1)"}).status_code == 422
