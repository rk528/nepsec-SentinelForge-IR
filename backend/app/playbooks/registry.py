"""Response playbooks.

Every playbook here is either read-only (it collects, enriches or writes
documents) or *simulated*. No playbook contacts a firewall, identity
provider or endpoint agent. ``simulate_firewall_block`` records exactly what
would have been changed, and only after a second person approves it.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.audit import RequestContext
from app.detection.base import is_external_ip
from app.detection.rules import RULES_BY_ID
from app.intel import service as intel
from app.models import Alert, Event, Incident, IncidentEvent, IncidentIndicator, Indicator, IndicatorEnrichment
from app.services import incidents as inc_svc
from app.services import reports


@dataclass
class PlaybookSpec:
    id: str
    name: str
    description: str
    category: str
    requires_approval: bool
    min_role: str
    simulated: bool
    handler: Callable[[Session, RequestContext, Incident, dict[str, Any]], dict[str, Any]]
    rollback_plan: str | None = None


def _incident_events(db: Session, incident: Incident) -> list[Event]:
    return list(db.execute(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(IncidentEvent.incident_id == incident.id)).scalars())


def _incident_alerts(db: Session, incident: Incident) -> list[Alert]:
    return list(db.execute(select(Alert).where(Alert.incident_id == incident.id)).scalars())


def _entities(db: Session, incident: Incident) -> dict[str, set[str]]:
    hosts: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()
    for a in _incident_alerts(db, incident):
        for key, target in (("host", hosts), ("user", users), ("target_user", users), ("src_ip", ips), ("dst_ip", ips)):
            if a.entities.get(key):
                target.add(str(a.entities[key]))
    for e in _incident_events(db, incident):
        if e.host:
            hosts.add(e.host)
        if e.user_name:
            users.add(e.user_name)
    return {"hosts": hosts, "users": users, "ips": ips}


# --- handlers ---------------------------------------------------------------


def collect_related_evidence(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    events = _incident_events(db, incident)
    if not events:
        return {"linked": 0, "note": "No linked events to pivot from."}
    ents = _entities(db, incident)
    start = min(e.event_time for e in events) - timedelta(hours=12)
    end = max(e.event_time for e in events) + timedelta(hours=12)
    conditions = []
    if ents["hosts"]:
        conditions.append(Event.host.in_(ents["hosts"]))
    if ents["users"]:
        conditions.append(Event.user_name.in_(ents["users"]))
    if ents["ips"]:
        conditions.append(or_(Event.src_ip.in_(ents["ips"]), Event.dst_ip.in_(ents["ips"])))
    if not conditions:
        return {"linked": 0, "note": "No host, user or IP entities to pivot on."}
    existing = {e.id for e in events}
    candidates = (
        db.execute(select(Event).where(Event.org_id == incident.org_id, Event.event_time.between(start, end), or_(*conditions)).order_by(Event.event_time).limit(200))
        .scalars()
        .all()
    )
    new = [e for e in candidates if e.id not in existing][:50]
    if new:
        db.execute(
            pg_insert(IncidentEvent)
            .values([{"incident_id": incident.id, "event_id": e.id, "added_by": ctx.user_id, "reason": "Collected by playbook: related entity within ±12h"} for e in new])
            .on_conflict_do_nothing()
        )
    content = {
        "pivot_entities": {k: sorted(v) for k, v in ents.items()},
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "linked_event_ids": [str(e.id) for e in new],
        "event_types": sorted({e.event_type for e in new}),
    }
    inc_svc.add_evidence(
        db,
        incident,
        evidence_type="playbook_output",
        title=f"Related evidence collection: {len(new)} event(s) linked",
        content=content,
        provenance={"method": "playbook:collect_related_evidence", "source_system": "SentinelForge event store"},
        collected_by=ctx.user_id,
    )
    return {"linked": len(new), **content}


def _extract_iocs(db: Session, incident: Incident) -> list[tuple[str, str]]:
    found: dict[tuple[str, str], None] = {}
    for e in _incident_events(db, incident):
        for ip in (e.src_ip, e.dst_ip):
            if ip and is_external_ip(ip):
                found[("ipv6" if ":" in ip else "ipv4", ip)] = None
        if e.domain:
            found[("domain", e.domain)] = None
        if e.file_hash and len(e.file_hash) in (32, 40, 64):
            found[({32: "md5", 40: "sha1", 64: "sha256"}[len(e.file_hash)], e.file_hash.lower())] = None
    return list(found)[:10]


def enrich_iocs(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    iocs = _extract_iocs(db, incident)
    results = []
    for ioc_type, value in iocs:
        r = intel.investigate(db, ctx, incident.org_id, ctx.user_id, ioc_type, value, incident=incident, force_refresh=False)  # type: ignore[arg-type]
        results.append(
            {
                "type": ioc_type,
                "value": value,
                "providers": {e["provider"]: {"status": e["status"], "reported_verdict": e["reported_verdict"]} for e in r["enrichments"]},
                "local_event_count": r["local"]["event_count"],
            }
        )
    inc_svc.add_evidence(
        db,
        incident,
        evidence_type="ioc_enrichment",
        title=f"IOC enrichment for {len(results)} indicator(s)",
        content={"indicators": results},
        provenance={"method": "playbook:enrich_iocs", "source_system": "Configured threat intelligence providers"},
        collected_by=ctx.user_id,
    )
    return {"indicators": results}


def prepare_summary(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    summary = reports.factual_summary(db, incident)
    inc_svc.add_evidence(
        db,
        incident,
        evidence_type="playbook_output",
        title="Generated factual summary",
        description="Computed from linked records. It does not replace the analyst assessment.",
        content=summary,
        provenance={"method": "playbook:prepare_summary", "generated": True},
        collected_by=ctx.user_id,
    )
    return summary


def _block_candidates(db: Session, incident: Incident) -> list[dict[str, Any]]:
    linked = (
        db.execute(select(Indicator).join(IncidentIndicator, IncidentIndicator.indicator_id == Indicator.id).where(IncidentIndicator.incident_id == incident.id)).scalars().all()
    )
    candidates = []
    for ind in linked:
        provider_verdicts = db.execute(
            select(IndicatorEnrichment.provider, IndicatorEnrichment.reported_verdict)
            .where(IndicatorEnrichment.indicator_id == ind.id, IndicatorEnrichment.status == "ok")
            .order_by(IndicatorEnrichment.fetched_at.desc())
        ).all()
        provider_flags = sorted({p for p, v in provider_verdicts if v in ("malicious", "suspicious")})
        if ind.analyst_verdict in ("malicious", "suspicious") or provider_flags:
            candidates.append(
                {
                    "type": ind.ioc_type,
                    "value": ind.value,
                    "analyst_verdict": ind.analyst_verdict,
                    "provider_flags": provider_flags,
                    "basis": "analyst verdict" if ind.analyst_verdict in ("malicious", "suspicious") else "provider report only",
                }
            )
    return candidates


def propose_blocklist(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    candidates = _block_candidates(db, incident)
    content = {
        "proposed": candidates,
        "note": "Proposal only. Entries backed solely by provider reports need analyst confirmation before any block.",
    }
    inc_svc.add_evidence(
        db,
        incident,
        evidence_type="playbook_output",
        title=f"Proposed IOC block list ({len(candidates)} entr{'y' if len(candidates) == 1 else 'ies'})",
        content=content,
        provenance={"method": "playbook:propose_blocklist"},
        collected_by=ctx.user_id,
    )
    return content


def validate_block_targets(params: dict[str, Any]) -> list[str]:
    targets = params.get("ip_addresses")
    if not isinstance(targets, list) or not targets or len(targets) > 20:
        raise HTTPException(status_code=422, detail="Provide between 1 and 20 ip_addresses to block")
    cleaned = []
    for t in targets:
        try:
            ip = str(ipaddress.ip_address(str(t).strip()))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Not an IP address: {str(t)[:64]}") from None
        if not is_external_ip(ip):
            raise HTTPException(status_code=422, detail=f"Refusing to block internal or reserved address {ip}")
        cleaned.append(ip)
    return sorted(set(cleaned))


def simulate_firewall_block(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    """Executed only after approval. Produces the change that *would* be made."""
    targets = validate_block_targets(params)
    return {
        "simulated": True,
        "target_system": "perimeter-firewall (simulation, no device contacted)",
        "would_apply": [{"rule": f"deny ip any host {ip}", "direction": "outbound", "comment": f"{inc_svc.reference(incident.number)}"} for ip in targets],
        "expires_after_hours": int(params.get("duration_hours", 24)),
    }


def record_containment(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    rules = sorted({a.rule_id for a in _incident_alerts(db, incident)})
    guidance = {
        "SF-AUTH-001": ["Reset the affected account's password and revoke active sessions.", "Review sign-ins from the source address across all accounts."],
        "SF-PROC-001": ["Isolate the host through the EDR console after confirming business impact.", "Collect the process tree and any downloaded files."],
        "SF-IAM-001": ["Disable the newly created account and remove it from privileged groups.", "Identify how the creating account was authorised."],
        "SF-DEF-001": ["Restore logging and confirm forwarding is healthy.", "Treat the gap in telemetry as a period of unknown activity."],
        "SF-NET-001": ["Block the destination at the egress firewall if confirmed malicious.", "Check other hosts for connections to the same destination."],
        "SF-MAIL-001": ["Purge the message from all mailboxes and block the sender domain.", "Reset credentials if the user entered them on the site."],
    }
    recommendations = [{"rule_id": r, "rule_name": RULES_BY_ID[r].name if r in RULES_BY_ID else r, "steps": guidance.get(r, [])} for r in rules]
    content = {"recommendations": recommendations, "status": "recommended, not executed"}
    inc_svc.add_evidence(
        db,
        incident,
        evidence_type="playbook_output",
        title="Containment recommendations",
        content=content,
        provenance={"method": "playbook:record_containment"},
        collected_by=ctx.user_id,
    )
    return content


def closure_report(db: Session, ctx: RequestContext, incident: Incident, params: dict[str, Any]) -> dict[str, Any]:
    report = reports.build_report(db, incident)
    markdown = reports.render_markdown(report)
    inc_svc.add_evidence(
        db,
        incident,
        evidence_type="report",
        title=f"Closure report snapshot ({incident.status})",
        content={"markdown": markdown, "generated_for_status": incident.status},
        provenance={"method": "playbook:closure_report", "generated": True},
        collected_by=ctx.user_id,
    )
    return {"characters": len(markdown), "status_at_generation": incident.status}


PLAYBOOKS: dict[str, PlaybookSpec] = {
    p.id: p
    for p in [
        PlaybookSpec(
            "collect_related_evidence",
            "Collect related evidence",
            "Links events that share a host, user or IP with the incident within ±12 hours.",
            "investigation",
            False,
            "analyst",
            False,
            collect_related_evidence,
        ),
        PlaybookSpec(
            "enrich_iocs",
            "Enrich associated IOCs",
            "Extracts external IPs, domains and hashes from linked events and queries configured intelligence providers.",
            "investigation",
            False,
            "analyst",
            False,
            enrich_iocs,
        ),
        PlaybookSpec(
            "prepare_summary",
            "Prepare incident summary",
            "Computes a factual summary from linked records. Does not overwrite analyst text.",
            "documentation",
            False,
            "analyst",
            False,
            prepare_summary,
        ),
        PlaybookSpec(
            "propose_blocklist",
            "Propose IOC block list",
            "Lists indicators judged malicious by an analyst or flagged by providers. Proposal only.",
            "containment",
            False,
            "analyst",
            False,
            propose_blocklist,
        ),
        PlaybookSpec(
            "simulate_firewall_block",
            "Simulate firewall block",
            "Requests an egress block for external IPs. Requires approval from a different lead. Simulated: no device is contacted.",
            "containment",
            True,
            "analyst",
            True,
            simulate_firewall_block,
            rollback_plan="Remove the simulated deny entries; in a real deployment, delete the rules tagged with the incident reference.",
        ),
        PlaybookSpec(
            "record_containment",
            "Record containment recommendations",
            "Records rule-specific containment steps for analysts to carry out manually.",
            "containment",
            False,
            "analyst",
            False,
            record_containment,
        ),
        PlaybookSpec(
            "closure_report", "Generate closure report", "Snapshots the incident report as an immutable evidence record.", "documentation", False, "analyst", False, closure_report
        ),
    ]
}


def sync_playbooks(db: Session) -> None:
    from app.models import Playbook

    for spec in PLAYBOOKS.values():
        values = {
            "id": spec.id,
            "name": spec.name,
            "description": spec.description,
            "category": spec.category,
            "requires_approval": spec.requires_approval,
            "min_role": spec.min_role,
            "simulated": spec.simulated,
        }
        stmt = pg_insert(Playbook).values(**values)
        db.execute(stmt.on_conflict_do_update(index_elements=["id"], set_={k: stmt.excluded[k] for k in values if k != "id"}))
