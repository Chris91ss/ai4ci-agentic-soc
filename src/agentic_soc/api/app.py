"""FastAPI backend of the SOC console: stream health, incident queue, entity timelines, the
agent's tool trace and evidence, approve/reject controls, live metrics and the audit log.
Live pipeline events are pushed to the console as server-sent events (``/api/events``)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agentic_soc import __version__
from agentic_soc.api.service import ConsoleService, ReadOnlyError
from agentic_soc.evidence import VERDICTS
from agentic_soc.mcp_server.tools import ToolError


class AnalystAction(BaseModel):
    analyst: str = Field(min_length=1, max_length=64)
    reason: str = Field(default="", max_length=500)


class FeedbackIn(BaseModel):
    analyst: str = Field(min_length=1, max_length=64)
    verdict: str = Field(description=f"One of {', '.join(VERDICTS)}.")
    comment: str = Field(default="", max_length=2000)
    alert_ids: list[str] | None = None


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def create_app(service: ConsoleService, cors_origins: list[str] | None = None) -> FastAPI:
    app = FastAPI(title="Agentic SOC console API", version=__version__)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.service = service

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return service.health()

    @app.get("/api/stream-health")
    def stream_health(hours: float = Query(6.0, gt=0, le=168), bucket_s: int = Query(300, ge=60)):
        return service.stream_health(hours, bucket_s)

    @app.get("/api/incidents")
    def incidents(
        status: list[str] | None = Query(None),
        min_risk: float = Query(0.0, ge=0, le=1),
        entity: str | None = None,
        limit: int = Query(200, ge=1, le=5000),
    ) -> list[dict[str, Any]]:
        return service.incidents(status, min_risk, entity, limit)

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str) -> dict[str, Any]:
        found = service.incident(incident_id)
        if found is None:
            raise HTTPException(404, f"unknown incident {incident_id}")
        return found

    @app.get("/api/incidents/{incident_id}/evidence")
    def evidence(
        incident_id: str,
        kind: str | None = None,
        entity: str | None = None,
        stream: str | None = None,
        detector: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        cited: bool | None = None,
        limit: int = Query(500, ge=1, le=10_000),
    ) -> list[dict[str, Any]]:
        return service.evidence(incident_id, kind=kind, entity=entity, stream=stream,
                                detector=detector, start=start, end=end, cited=cited, limit=limit)  # fmt: skip

    @app.get("/api/incidents/{incident_id}/trace")
    def trace(incident_id: str) -> dict[str, Any]:
        return service.trace(incident_id)

    @app.post("/api/incidents/{incident_id}/feedback")
    def feedback(incident_id: str, body: FeedbackIn) -> dict[str, Any]:
        try:
            return service.feedback(
                incident_id, body.verdict, body.analyst, body.comment, body.alert_ids
            )
        except KeyError as exc:
            raise HTTPException(404, f"unknown incident {incident_id}") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/entities/{entity}")
    def entity(entity: str) -> dict[str, Any]:
        try:
            return service.entity(entity)
        except ToolError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/entities/{entity}/timeline")
    def timeline(
        entity: str,
        start: datetime | None = None,
        end: datetime | None = None,
        streams: list[str] | None = Query(None),
        limit: int = Query(300, ge=1, le=5000),
    ) -> dict[str, Any]:
        try:
            return service.timeline(entity, start, end, streams, limit)
        except (ToolError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/actions")
    def actions(status: list[str] | None = Query(None), limit: int = Query(500, ge=1, le=10_000)):
        return service.actions(status, limit)

    def _act(fn: Any, action_id: str, *args: Any) -> dict[str, Any]:
        try:
            return fn(action_id, *args)
        except ReadOnlyError as exc:
            raise HTTPException(409, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(404, f"unknown action {action_id}") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/actions/{action_id}/approve")
    def approve(action_id: str, body: AnalystAction) -> dict[str, Any]:
        return _act(service.approve, action_id, body.analyst)

    @app.post("/api/actions/{action_id}/reject")
    def reject(action_id: str, body: AnalystAction) -> dict[str, Any]:
        return _act(service.reject, action_id, body.analyst, body.reason)

    @app.get("/api/metrics")
    def metrics() -> dict[str, Any]:
        return service.metrics()

    @app.get("/api/audit")
    def audit(object_id: str | None = None, limit: int = Query(200, ge=1, le=5000)):
        return service.audit(object_id, limit)

    @app.get("/api/audit/verify")
    def verify_audit() -> dict[str, Any]:
        return service.verify_audit()

    @app.get("/api/evaluation")
    def evaluation() -> dict[str, Any]:
        found = service.evaluation()
        if found is None:
            raise HTTPException(404, "no evaluation results (run `soc evaluate`)")
        return found

    @app.get("/api/log")
    def log(kinds: list[str] | None = Query(None), limit: int = Query(20_000, ge=1, le=200_000)):
        """The pipeline log, e.g. to replay a recorded run in the console."""
        return service.log(kinds, limit)

    @app.get("/api/events")
    async def events(
        cursor: int = Query(0, ge=0),
        interval_s: float = Query(1.0, gt=0, le=30),
        max_s: float | None = Query(None, gt=0, description="Close the stream after this long."),
    ) -> StreamingResponse:
        """Server-sent events: pipeline events (alert, incident, route, decision, action, ...)
        as they happen, and a metrics snapshot every few seconds."""

        async def stream():
            position, waited, since_metrics = cursor, 0.0, 1e9
            yield _sse("hello", {"live": service.live, "cursor": position})
            while max_s is None or waited < max_s:
                entries, position = service.log_since(position)
                for entry in entries:
                    yield _sse(entry["kind"], entry)
                if since_metrics >= 5.0:
                    since_metrics = 0.0
                    yield _sse("metrics", service.metrics() | {"cursor": position})
                await asyncio.sleep(interval_s)
                waited += interval_s
                since_metrics += interval_s

        headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        return StreamingResponse(stream(), media_type="text/event-stream", headers=headers)

    return app
