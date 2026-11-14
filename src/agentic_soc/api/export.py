"""Static export of a recorded run for the console (the GitHub Pages demo).

The console's static data mode reads the same JSON the API serves, from files: the incident
list and one file per incident (detail, evidence, agent trace), one file per entity (detail and
timeline), actions, metrics, the audit log, the pipeline log (replayed in the overview) and the
evaluation results.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from agentic_soc.api.service import ConsoleService
from agentic_soc.schemas.security import ACTION_TARGET_KIND

ENTITY_KINDS = {"users": "user", "hosts": "host", "ips": "ip"}
TRIAGED = {"agent", "playbook"}


def _drop_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_nulls(v) for v in value]
    return value


def entity_file(entity: str) -> str:
    """File name of an entity (same rule as ``entityFile`` in web/src/lib/api.ts)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", entity)


def _write(path: Path, payload: Any) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, separators=(",", ":"), default=str)
    path.write_text(text)
    return len(text)


def export_static(
    service: ConsoleService,
    out: Path,
    timeline_hours: float = 72.0,
    timeline_limit: int = 50,
    alert_limit: int = 8,
    stream_hours: float = 12.0,
) -> dict[str, int]:
    """Write the console's static data files into ``out``; returns file counts and bytes.

    Entity pages are exported for the entities of triaged incidents (routed to the agent or a
    playbook) and of containment actions, with their newest events and alerts."""
    for stale in ("incidents", "entities"):
        shutil.rmtree(out / stale, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    size = 0
    size += _write(out / "health.json", service.health())
    size += _write(out / "stream-health.json", service.stream_health(stream_hours, 300))

    incidents = service.incidents(limit=1_000_000)
    size += _write(out / "incidents.json", incidents)
    entities: set[str] = set()
    for incident in incidents:
        incident_id = incident["incident_id"]
        size += _write(
            out / "incidents" / f"{incident_id}.json",
            {
                "detail": service.incident(incident_id),
                "evidence": service.evidence(incident_id, limit=100_000),
                "trace": service.trace(incident_id),
            },
        )
        if incident["route"] in TRIAGED or incident["actions"]:
            for key, kind in ENTITY_KINDS.items():
                entities.update(f"{kind}:{v}" for v in incident["entities"].get(key, []))
    actions = service.actions(limit=1_000_000)
    for action in actions:
        entities.add(f"{ACTION_TARGET_KIND[action['type']]}:{action['target']}")

    end = service.now()
    start = end - timedelta(hours=timeline_hours)
    for entity in sorted(entities):
        timeline = service.timeline(entity, start, end, limit=timeline_limit)
        timeline["alerts"] = sorted(timeline["alerts"], key=lambda a: a["window_end"], reverse=True)
        timeline["alerts"] = timeline["alerts"][:alert_limit]
        size += _write(
            out / "entities" / f"{entity_file(entity)}.json",
            {"detail": service.entity(entity), "timeline": _drop_nulls(timeline)},
        )

    size += _write(out / "actions.json", actions)
    size += _write(out / "metrics.json", service.metrics())
    size += _write(out / "audit.json", service.audit(limit=100_000))
    size += _write(out / "audit-verify.json", service.verify_audit())
    size += _write(out / "log.json", service.log(limit=1_000_000))
    evaluation = service.evaluation()
    if evaluation is not None:
        size += _write(out / "evaluation.json", evaluation)
    else:
        (out / "evaluation.json").unlink(missing_ok=True)
    return {"incidents": len(incidents), "entities": len(entities), "bytes": size}
