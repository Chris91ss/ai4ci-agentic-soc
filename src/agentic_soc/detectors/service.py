"""Detector scoring over REST (the MCP scoring tools call M1-M3 through this API) and the
clients used by the pipeline: an in-process client and an HTTP client with the same interface."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Protocol

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import AwareDatetime, BaseModel, Field

from agentic_soc.detectors.base import Score
from agentic_soc.detectors.registry import KIND_TO_DETECTOR, DetectorSet, ModelRegistry
from agentic_soc.features import FEATURES, FeatureRow


class RowModel(BaseModel):
    """Wire format of a feature row."""

    detector: str = Field(description="M1-user, M1-ip, M2 or M3")
    key: str
    window_start: AwareDatetime
    window_end: AwareDatetime
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    features: dict[str, float]
    late: bool = False
    context: dict[str, Any] = Field(default_factory=dict)

    def to_row(self) -> FeatureRow:
        return FeatureRow(**self.model_dump())

    @classmethod
    def from_row(cls, row: FeatureRow) -> RowModel:
        return cls(
            detector=row.detector, key=row.key, window_start=row.window_start, window_end=row.window_end,
            users=row.users, hosts=row.hosts, ips=row.ips, event_ids=row.event_ids, features=row.features,
            late=row.late, context=row.context,
        )  # fmt: skip


class ScoreRequest(BaseModel):
    rows: list[RowModel]


class ScoreModel(BaseModel):
    detector: str
    kind: str
    key: str
    window_end: datetime
    score: float
    threshold: float
    alert: bool
    severity: str
    top_features: list[dict[str, Any]]
    techniques: list[str]
    summary: str


class ScoreResponse(BaseModel):
    model_version: str
    latency_ms: float
    scores: list[ScoreModel]


def _to_score(score: ScoreModel) -> Score:
    return Score(
        score.detector,
        score.kind,
        score.score,
        score.threshold,
        score.top_features,
        score.techniques,
        score.summary,
    )


class DetectorClient(Protocol):
    def score(self, name: str, rows: list[FeatureRow]) -> list[Score]: ...

    def versions(self) -> dict[str, str]: ...


class LocalDetectorClient:
    """In-process scoring (single-process pipeline, evaluation runs)."""

    def __init__(self, detectors: DetectorSet) -> None:
        self.detectors = detectors

    def score(self, name: str, rows: list[FeatureRow]) -> list[Score]:
        return self.detectors.detectors[name].score(rows)

    def versions(self) -> dict[str, str]:
        return self.detectors.versions


class HttpDetectorClient:
    """Scoring through the detector REST service."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8001",
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.http = client or httpx.Client(base_url=base_url, timeout=timeout)

    def score(self, name: str, rows: list[FeatureRow]) -> list[Score]:
        if not rows:
            return []
        payload = ScoreRequest(rows=[RowModel.from_row(r) for r in rows]).model_dump(mode="json")
        response = self.http.post(f"/score/{name}", json=payload)
        response.raise_for_status()
        return [_to_score(ScoreModel(**s)) for s in response.json()["scores"]]

    def versions(self) -> dict[str, str]:
        response = self.http.get("/health")
        response.raise_for_status()
        return response.json()["models"]


def create_app(
    registry: ModelRegistry | None = None, detectors: DetectorSet | None = None
) -> FastAPI:
    registry = registry or ModelRegistry()
    app = FastAPI(title="Agentic SOC detectors", version="1.0", description="M1-M3 scoring service")
    state: dict[str, DetectorSet] = {"set": detectors or registry.load_set()}

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "models": state["set"].versions}

    @app.get("/models")
    def models() -> dict[str, Any]:
        return {name: registry.versions(name) for name in ("M1", "M2", "M3")}

    @app.get("/features/{kind}")
    def feature_names(kind: str) -> list[str]:
        if kind not in FEATURES:
            raise HTTPException(404, f"unknown feature kind {kind}")
        return FEATURES[kind]

    @app.post("/score/{name}", response_model=ScoreResponse)
    def score(name: str, request: ScoreRequest) -> ScoreResponse:
        detectors = state["set"].detectors
        if name not in detectors:
            raise HTTPException(404, f"unknown detector {name}")
        rows = [r.to_row() for r in request.rows]
        for row in rows:
            if KIND_TO_DETECTOR.get(row.detector) != name:
                raise HTTPException(422, f"{row.detector} rows cannot be scored by {name}")
            missing = set(FEATURES[row.detector]) - set(row.features)
            if missing and row.detector != "M3":
                raise HTTPException(422, f"missing features for {row.key}: {sorted(missing)[:5]}")
        started = time.perf_counter()
        scores = detectors[name].score(rows)
        latency = (time.perf_counter() - started) * 1000
        return ScoreResponse(
            model_version=detectors[name].version,
            latency_ms=round(latency, 2),
            scores=[
                ScoreModel(key=row.key, window_end=row.window_end, alert=s.alert, severity=s.severity, **{
                    k: v for k, v in s.to_dict().items() if k not in {"alert", "severity"}
                })
                for row, s in zip(rows, scores, strict=True)
            ],
        )  # fmt: skip

    @app.post("/reload")
    def reload() -> dict[str, Any]:
        state["set"] = registry.load_set()
        return {"status": "reloaded", "models": state["set"].versions}

    return app
