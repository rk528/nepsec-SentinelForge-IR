"""Audit logging helper.

Audit records are written in the same transaction as the change they
describe, so a rolled-back change never leaves a misleading audit entry.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


class RequestContext:
    """Who is acting and from where. Built once per request in deps.py."""

    def __init__(
        self,
        *,
        org_id: uuid.UUID | None,
        user_id: uuid.UUID | None,
        actor_label: str,
        ip: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> None:
        self.org_id = org_id
        self.user_id = user_id
        self.actor_label = actor_label
        self.ip = ip
        self.user_agent = user_agent
        self.request_id = request_id


def record(
    db: Session,
    ctx: RequestContext,
    action: str,
    *,
    target_type: str | None = None,
    target_id: Any = None,
    details: dict[str, Any] | None = None,
    org_id: uuid.UUID | None = None,
) -> AuditLog:
    entry = AuditLog(
        org_id=org_id or ctx.org_id,
        actor_user_id=ctx.user_id,
        actor_label=ctx.actor_label,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=details or {},
        ip=ctx.ip,
        user_agent=(ctx.user_agent or "")[:400] or None,
        request_id=ctx.request_id,
    )
    db.add(entry)
    return entry


SYSTEM_CONTEXT = RequestContext(org_id=None, user_id=None, actor_label="system")
