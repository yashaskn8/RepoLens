"""Small vendor-neutral structured telemetry authority."""

from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.platform import TelemetryMetricModel
from app.security.redaction import sanitize_metadata


class TelemetryRecorder:
    @staticmethod
    def record(
        db: Session,
        *,
        metric_name: str,
        value: float,
        unit: str,
        tenant_id: str | None = None,
        request_id: str | None = None,
        work_item_id: str | None = None,
        dimensions: dict[str, Any] | None = None,
    ) -> TelemetryMetricModel:
        model = TelemetryMetricModel(
            tenant_id=tenant_id,
            request_id=request_id[:128] if request_id else None,
            work_item_id=work_item_id,
            metric_name=metric_name[:128],
            metric_value=float(value),
            unit=unit[:32],
            dimensions=sanitize_metadata(dimensions or {}),
        )
        db.add(model)
        db.flush()
        try:
            from app.observability.metrics import emit_sql_metric

            emit_sql_metric(metric_name, float(value), unit, dimensions or {})
        except Exception:
            # SQL remains the durable authority; optional metric export is best effort.
            pass
        return model

    @staticmethod
    def aggregate(db: Session, metric_name: str, tenant_id: str | None = None) -> dict[str, float]:
        query = db.query(
            func.count(TelemetryMetricModel.id),
            func.sum(TelemetryMetricModel.metric_value),
            func.avg(TelemetryMetricModel.metric_value),
            func.max(TelemetryMetricModel.metric_value),
        ).filter(TelemetryMetricModel.metric_name == metric_name)
        if tenant_id is not None:
            query = query.filter(TelemetryMetricModel.tenant_id == tenant_id)
        count, total, average, maximum = query.one()
        return {
            "count": float(count or 0),
            "sum": float(total or 0),
            "average": float(average or 0),
            "maximum": float(maximum or 0),
        }
