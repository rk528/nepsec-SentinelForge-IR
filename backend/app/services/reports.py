"""Incident report generation (JSON and Markdown).

The report is assembled from stored records only. Analyst-written text is
quoted verbatim and kept separate from computed sections, so generated
content can never silently replace original evidence or analyst judgement.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.attack import TECHNIQUES
from app.detection.base import is_external_ip
from app.detection.rules import RULES_BY_ID
from app.models import (
    Alert,
    Asset,
    Event,
    Evidence,
    Incident,
    IncidentEvent,
    IncidentIndicator,
    IncidentNote,
    Indicator,
    IndicatorEnrichment,
    User,
)
from app.services.incidents import build_timeline, reference

REPORT_VERSION = 1


def _linked_events(db: Session, incident: Incident) -> list[Event]:
    return list(
        db.execute(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(IncidentEvent.incident_id == incident.id).order_by(Event.event_time)).scalars()
    )


def factual_summary(db: Session, incident: Incident) -> dict[str, Any]:
    events = _linked_events(db, incident)
    alerts = list(db.execute(select(Alert).where(Alert.incident_id == incident.id)).scalars())
    rule_ids = sorted({a.rule_id for a in alerts})
    return {
        "reference": reference(incident.number),
        "linked_events": len(events),
        "linked_alerts": len(alerts),
        "activity_window": {
            "first_event": events[0].event_time.isoformat() if events else None,
            "last_event": events[-1].event_time.isoformat() if events else None,
        },
        "hosts": sorted({e.host for e in events if e.host}),
        "accounts": sorted({u for e in events for u in (e.user_name, e.target_user) if u}),
        "external_addresses": sorted({ip for e in events for ip in (e.src_ip, e.dst_ip) if is_external_ip(ip)}),
        "rules": rule_ids,
        "event_types": sorted({e.event_type for e in events}),
    }


def build_report(db: Session, incident: Incident) -> dict[str, Any]:
    events = _linked_events(db, incident)
    alerts = list(db.execute(select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.first_seen)).scalars())
    evidence = list(db.execute(select(Evidence).where(Evidence.incident_id == incident.id).order_by(Evidence.created_at)).scalars())
    notes = db.execute(
        select(IncidentNote, User.display_name)
        .outerjoin(User, User.id == IncidentNote.author_id)
        .where(IncidentNote.incident_id == incident.id, IncidentNote.note_type.in_(("analyst", "assessment")))
        .order_by(IncidentNote.created_at)
    ).all()
    assignee = db.get(User, incident.assignee_id) if incident.assignee_id else None

    hosts = sorted({e.host for e in events if e.host})
    assets = db.execute(select(Asset).where(Asset.org_id == incident.org_id, Asset.hostname.in_(hosts))).scalars().all() if hosts else []

    indicators = (
        db.execute(select(Indicator).join(IncidentIndicator, IncidentIndicator.indicator_id == Indicator.id).where(IncidentIndicator.incident_id == incident.id)).scalars().all()
    )
    ioc_findings = []
    for ind in indicators:
        latest: dict[str, IndicatorEnrichment] = {}
        for enr in db.execute(select(IndicatorEnrichment).where(IndicatorEnrichment.indicator_id == ind.id).order_by(IndicatorEnrichment.fetched_at)).scalars():
            latest[enr.provider] = enr
        ioc_findings.append(
            {
                "type": ind.ioc_type,
                "value": ind.value,
                "analyst_verdict": ind.analyst_verdict,
                "analyst_note": ind.analyst_note,
                "provider_findings": [
                    {"provider": p, "status": e.status, "reported_verdict": e.reported_verdict, "fetched_at": e.fetched_at.isoformat()} for p, e in sorted(latest.items())
                ],
            }
        )

    rules = []
    techniques: dict[str, set[str]] = defaultdict(set)
    for rule_id in sorted({a.rule_id for a in alerts}):
        rule = RULES_BY_ID.get(rule_id)
        if rule is None:
            continue
        rules.append({"id": rule.id, "name": rule.name, "description": rule.description, "false_positives": rule.false_positives})
        for t in rule.attack_techniques:
            techniques[t].add(rule.id)
    for a in alerts:  # techniques specific to the matched pattern, when the rule reports them
        for t in a.evidence_summary.get("techniques", []) if isinstance(a.evidence_summary, dict) else []:
            techniques[t].add(a.rule_id)
    attack = [
        {"technique": t, "name": TECHNIQUES.get(t, {}).get("name", "Unknown"), "tactic": TECHNIQUES.get(t, {}).get("tactic"), "via_rules": sorted(r)}
        for t, r in sorted(techniques.items())
    ]

    containment = next((e.content for e in reversed(evidence) if e.provenance.get("method") == "playbook:record_containment"), None)
    limitations = [
        "Automated detections map to ATT&CK techniques by design intent; a mapping is not proof of the technique.",
        "Provider findings reflect third-party data at lookup time. Missing or empty results are not evidence of safety.",
    ]
    if incident.is_synthetic or any(e.is_synthetic for e in events):
        limitations.insert(0, "This incident is built from SYNTHETIC demonstration data. No real systems or people are involved.")
    if not any(f["provider_findings"] for f in ioc_findings):
        limitations.append("No threat intelligence provider returned data for the linked indicators.")

    return {
        "report_version": REPORT_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "incident": {
            "reference": reference(incident.number),
            "title": incident.title,
            "summary": incident.summary,
            "severity": incident.severity,
            "status": incident.status,
            "verdict": incident.verdict,
            "closure_reason": incident.closure_reason,
            "tags": incident.tags,
            "assignee": assignee.display_name if assignee else None,
            "created_at": incident.created_at.isoformat(),
            "acknowledged_at": incident.acknowledged_at.isoformat() if incident.acknowledged_at else None,
            "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "is_synthetic": incident.is_synthetic,
        },
        "timeline": [{**i, "at": i["at"].isoformat()} for i in build_timeline(db, incident)],
        "affected_assets": [{"hostname": a.hostname, "type": a.asset_type, "criticality": a.criticality, "os": a.os} for a in assets],
        "affected_accounts": sorted({u for e in events for u in (e.user_name, e.target_user) if u}),
        "alerts": [
            {
                "id": str(a.id),
                "rule_id": a.rule_id,
                "title": a.title,
                "severity": a.severity,
                "confidence": a.confidence,
                "first_seen": a.first_seen.isoformat(),
                "disposition": a.disposition,
            }
            for a in alerts
        ],
        "evidence": [
            {"id": str(e.id), "type": e.evidence_type, "title": e.title, "sha256": e.sha256, "provenance": e.provenance, "created_at": e.created_at.isoformat()} for e in evidence
        ],
        "supporting_events": [
            {
                "id": str(e.id),
                "time": e.event_time.isoformat(),
                "type": e.event_type,
                "host": e.host,
                "user": e.user_name,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "domain": e.domain,
                "synthetic": e.is_synthetic,
            }
            for e in events[:100]
        ],
        "ioc_findings": ioc_findings,
        "detection_rules": rules,
        "attack_mapping": attack,
        "analyst_assessment": [{"type": n.note_type, "author": author, "at": n.created_at.isoformat(), "text": n.body} for n, author in notes],
        "containment_recommendations": containment,
        "limitations": limitations,
    }


def _code(value: Any) -> str:
    """Render untrusted text as inline code so it cannot form links or markup."""
    text = str(value).replace("\n", " ").replace("`", "'")
    return f"`{text}`" if text else "—"


def _text(value: Any) -> str:
    """Escape analyst/system text for Markdown while keeping it readable."""
    text = str(value or "")
    for ch in ("\\", "`", "*", "_", "[", "]", "<", ">", "#", "|"):
        text = text.replace(ch, "\\" + ch)
    return text


def render_markdown(r: dict[str, Any]) -> str:
    inc = r["incident"]
    out: list[str] = []
    w = out.append
    w(f"# {inc['reference']}: {_text(inc['title'])}")
    w("")
    if inc["is_synthetic"]:
        w("> **Synthetic data.** This report was generated from demonstration data.")
        w("")
    w(f"Generated {r['generated_at']} · report format v{r['report_version']}")
    w("")
    w("## Summary")
    w("")
    w("| Field | Value |")
    w("| --- | --- |")
    for label, key in (
        ("Severity", "severity"),
        ("Status", "status"),
        ("Verdict", "verdict"),
        ("Assignee", "assignee"),
        ("Opened", "created_at"),
        ("Acknowledged", "acknowledged_at"),
        ("Contained", "contained_at"),
        ("Resolved", "resolved_at"),
        ("Closed", "closed_at"),
    ):
        w(f"| {label} | {_text(inc[key]) if inc[key] else '—'} |")
    w("")
    w(_text(inc["summary"]) or "_No summary recorded._")
    w("")
    w("## Timeline (UTC)")
    w("")
    for item in r["timeline"]:
        detail = f" — {_code(item['detail'])}" if item.get("detail") else ""
        w(f"- **{item['at']}** · {item['kind']} · {_text(item['title'])}{detail}")
    w("")
    w("## Affected assets and accounts")
    w("")
    for a in r["affected_assets"]:
        w(f"- Host {_code(a['hostname'])} ({a['type']}, criticality {a['criticality']})")
    for u in r["affected_accounts"]:
        w(f"- Account {_code(u)}")
    if not r["affected_assets"] and not r["affected_accounts"]:
        w("_None identified from linked evidence._")
    w("")
    w("## Supporting evidence")
    w("")
    for e in r["evidence"]:
        w(f"- {_text(e['title'])} ({e['type']}), sha256 {_code(e['sha256'][:16])}…, method {_code(e['provenance'].get('method', 'n/a'))}")
    w("")
    w("## IOC findings")
    w("")
    if not r["ioc_findings"]:
        w("_No indicators linked._")
    for f in r["ioc_findings"]:
        w(f"- {f['type']} {_code(f['value'])} · analyst verdict **{f['analyst_verdict']}**")
        for p in f["provider_findings"]:
            w(f"  - {p['provider']}: {p['status']}, reported {p['reported_verdict']} (looked up {p['fetched_at']})")
        if not f["provider_findings"]:
            w("  - No provider data. This does not indicate the indicator is safe.")
    w("")
    w("## Detection rules")
    w("")
    for rule in r["detection_rules"]:
        w(f"- **{rule['id']}** {_text(rule['name'])}: {_text(rule['description'])}")
    w("")
    w("## ATT&CK mapping")
    w("")
    for t in r["attack_mapping"]:
        w(f"- {t['technique']} {_text(t['name'])} ({t['tactic']}) via {', '.join(t['via_rules'])}")
    w("")
    w("## Analyst assessment")
    w("")
    if not r["analyst_assessment"]:
        w("_No analyst notes recorded._")
    for n in r["analyst_assessment"]:
        w(f"> **{_text(n['author'] or 'Unknown')}** ({n['type']}, {n['at']})")
        w(">")
        for line in str(n["text"]).splitlines() or [""]:
            w(f"> {_text(line)}")
        w("")
    w("## Containment and recovery recommendations")
    w("")
    rec = r["containment_recommendations"]
    if rec:
        for item in rec.get("recommendations", []):
            w(f"- **{item['rule_id']}** {_text(item['rule_name'])}")
            for step in item["steps"]:
                w(f"  - {_text(step)}")
    else:
        w("_The containment recommendations playbook has not been run._")
    w("")
    w("## Closure")
    w("")
    w(f"Verdict: **{inc['verdict'] or 'not set'}**")
    w("")
    w(_text(inc["closure_reason"]) or "_Incident not closed._")
    w("")
    w("## Limitations")
    w("")
    for lim in r["limitations"]:
        w(f"- {_text(lim)}")
    w("")
    return "\n".join(out)
