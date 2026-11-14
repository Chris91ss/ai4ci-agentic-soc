"""Analyst feedback: verdicts on alerts feed per-detector false-positive statistics and
retraining labels (RFC, evidence and verification)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from agentic_soc.storage import Store

FeedbackVerdict = Literal["true_positive", "false_positive", "benign_positive"]
VERDICTS: tuple[str, ...] = ("true_positive", "false_positive", "benign_positive")


class FeedbackService:
    def __init__(self, store: Store) -> None:
        self.store = store

    def record(
        self,
        incident_id: str,
        verdict: str,
        analyst: str,
        now: datetime,
        comment: str = "",
        alert_ids: list[str] | None = None,
    ) -> int:
        """Label the incident's alerts (or the given ones); returns the number of rows written."""
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {', '.join(VERDICTS)}")
        if alert_ids is None:
            alert_ids = [
                a["alert_id"] for a in self.store.list_alerts(incident_id=incident_id, limit=10_000)
            ]
        if not alert_ids:
            raise ValueError(f"incident {incident_id!r} has no alerts to label")
        rows = [
            {"incident_id": incident_id, "alert_id": alert_id, "analyst": analyst, "verdict": verdict,
             "comment": comment[:2000], "created_at": now}
            for alert_id in alert_ids
        ]  # fmt: skip
        self.store.add_feedback(rows)
        self.store.audit(f"analyst:{analyst}", "feedback", "incident", incident_id,
                         {"verdict": verdict, "alerts": len(rows), "comment": comment[:200]}, ts=now)  # fmt: skip
        return len(rows)

    def latest(self) -> dict[str, dict[str, Any]]:
        """The most recent analyst verdict per alert."""
        out: dict[str, dict[str, Any]] = {}
        for row in self.store.list_feedback(limit=1_000_000):
            if row["alert_id"]:
                out[row["alert_id"]] = row
        return out

    def detector_stats(self) -> list[dict[str, Any]]:
        """Per detector and feature kind: alerts raised, reviewed, and how reviews went."""
        latest = self.latest()
        alerts = {a["alert_id"]: a for a in self.store.alerts_by_ids(latest)}
        reviewed: dict[tuple[str, str], Counter[str]] = {}
        for alert_id, row in latest.items():
            alert = alerts.get(alert_id)
            if alert is not None:
                key = (alert["detector"], alert["model_version"] or alert["detector"])
                reviewed.setdefault(key, Counter())[row["verdict"]] += 1
        out = []
        for row in self.store.alert_counts():
            key = (row["detector"], row["model_version"] or row["detector"])
            counts = reviewed.get(key, Counter())
            n = sum(counts.values())
            out.append({
                "detector": key[0], "kind": key[1], "alerts": int(row["alerts"]), "reviewed": n,
                **{v: counts[v] for v in VERDICTS},
                "false_positive_share": round(counts["false_positive"] / n, 4) if n else None,
                "precision": round(counts["true_positive"] / n, 4) if n else None,
            })  # fmt: skip
        return sorted(out, key=lambda r: (r["detector"], r["kind"]))

    def labels(self) -> list[dict[str, Any]]:
        """Alert-level labels for retraining: 1 = attack, 0 = false or benign positive."""
        latest = self.latest()
        out = []
        for alert in self.store.alerts_by_ids(latest):
            row = latest[alert["alert_id"]]
            out.append({
                "alert_id": alert["alert_id"], "detector": alert["detector"],
                "kind": alert["model_version"], "window_start": alert["window_start"],
                "window_end": alert["window_end"], "entity_keys": alert["entity_keys"].split(),
                "event_ids": alert["event_ids"], "verdict": row["verdict"],
                "label": int(row["verdict"] == "true_positive"), "analyst": row["analyst"],
            })  # fmt: skip
        return out

    def export_labels(self, path: str | Path) -> int:
        import pyarrow as pa
        import pyarrow.parquet as pq

        rows = self.labels()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(pa.Table.from_pylist(rows), path)
        return len(rows)
