"""Keyset-paged reclamation under the canonical catalog writer fence.

Only unpinned expired snapshots and unreachable extraction rows are removed.
Every committed page is restartable; shared subtrees require no global mark set.
Database free pages are reused by subsequent indexing, without blocking VACUUM.
"""

import time
from uuid import UUID
from sqlalchemy import delete, select, or_, and_

from app.models.intelligence import (IndexEntryModel, IndexFactModel, IndexPinModel,
    IndexPostingModel, IndexProjectionModel, IndexSignalModel, IndexSnapshotModel,
    IndexTreeModel, IndexWriterModel)


def collect_catalog(index) -> dict:
    from app.ingestion.git_inventory import InventoryBound
    if not index.writer_owned:
        raise InventoryBound("catalog_gc_requires_writer")
    index._fence_writer()
    db = index.db
    writer = db.get(IndexWriterModel, index.writer_id, populate_existing=True)
    cursors = dict(writer.gc_state or {})
    remaining = index.limits.gc_rows
    deadline = time.monotonic() + index.limits.gc_seconds
    summary = {"examined": 0, "deleted_rows": 0, "snapshots": 0, "trees": 0, "projections": 0}

    def exists(model, *conditions):
        return db.scalar(select(next(iter(model.__table__.primary_key.columns))).where(*conditions).limit(1)) is not None

    def remove(model, *conditions):
        nonlocal remaining
        count = db.execute(delete(model).where(*conditions).execution_options(synchronize_session=False)).rowcount
        remaining -= count
        summary["deleted_rows"] += count

    # Legacy UUID pins are scan owners. Unrecognized/manual owners fail closed.
    # Ownership records, not age alone, decide whether protected evidence lives.
    from app.models.scan import ScanModel
    from app.models.report import ReportModel
    from app.models.finding import FindingModel
    from app.models.change_analysis import ChangeAnalysisModel, ChangeImpactModel
    from app.models.execution import WorkItemModel
    from app.models.artifact import ArtifactReferenceModel, ArtifactReferenceReleaseModel
    from app.execution.types import TERMINAL_STATES
    pin_cursor = cursors.get("pins", ["", ""])
    pins = db.scalars(select(IndexPinModel).join(IndexSnapshotModel, IndexPinModel.snapshot_id == IndexSnapshotModel.id)
        .where(IndexPinModel.tenant_id == index.tenant_id, IndexSnapshotModel.repository_id == index.repository_id,
            or_(IndexPinModel.referrer_id > pin_cursor[0], and_(IndexPinModel.referrer_id == pin_cursor[0], IndexPinModel.snapshot_id > pin_cursor[1])))
        .order_by(IndexPinModel.referrer_id, IndexPinModel.snapshot_id).limit(min(32, remaining))).all()
    summary["released_pins"] = 0
    if not pins:
        cursors["pins"] = ["", ""]
    for pin in pins:
        if remaining <= 0 or time.monotonic() >= deadline:
            break
        kind, separator, owner_id = pin.referrer_id.partition(":")
        if not separator:
            kind, owner_id = "scan", pin.referrer_id
        try:
            UUID(owner_id)
        except ValueError:
            cursors["pins"] = [pin.referrer_id, pin.snapshot_id]
            continue
        # Append-only canonical artifact references remain authoritative even
        # after their original domain owner disappears.
        retained = db.scalar(select(ArtifactReferenceModel.id).where(
            ArtifactReferenceModel.tenant_id == index.tenant_id,
            ArtifactReferenceModel.referrer_id == owner_id,
            ~select(ArtifactReferenceReleaseModel.id).where(
                ArtifactReferenceReleaseModel.reference_id == ArtifactReferenceModel.id).exists()).limit(1))
        live = True
        if not retained and kind in {"scan", "evidence"}:
            owner = db.get(ScanModel, owner_id)
            if owner is None:
                live = False
            elif str(owner.owner_user_id or "legacy-local") == index.tenant_id:
                live = (owner.status not in {"COMPLETED", "FAILED", "CANCELLED"} or
                    exists(FindingModel, FindingModel.scan_id == owner_id) or
                    exists(ReportModel, ReportModel.scan_id == owner_id))
        elif not retained and kind in {"work", "report", "change"}:
            model = {"work": WorkItemModel, "report": ReportModel, "change": ChangeAnalysisModel}[kind]
            owner = db.get(model, owner_id)
            if owner is None:
                live = False
            elif kind == "work" and owner.tenant_id == index.tenant_id:
                live = owner.state not in {state.value for state in TERMINAL_STATES}
            elif kind == "change" and owner.owner_user_id == index.tenant_id:
                # Completed analyses remain protected only while they have
                # canonical impact evidence; failed/empty work can be reclaimed.
                live = owner.status not in {"COMPLETED", "FAILED"} or exists(
                    ChangeImpactModel, ChangeImpactModel.analysis_id == owner_id,
                )
        if not live:
            remove(IndexPinModel, IndexPinModel.tenant_id == pin.tenant_id,
                IndexPinModel.referrer_id == pin.referrer_id, IndexPinModel.snapshot_id == pin.snapshot_id)
            summary["released_pins"] += 1
        cursors["pins"] = [pin.referrer_id, pin.snapshot_id]

    for model, label in ((IndexSnapshotModel, "snapshots"), (IndexTreeModel, "trees"), (IndexProjectionModel, "projections")):
        if remaining <= 0 or time.monotonic() >= deadline:
            break
        page = db.execute(select(model).where(model.tenant_id == index.tenant_id,
            model.repository_id == index.repository_id, model.id > cursors.get(label, ""))
            .order_by(model.id).limit(min(32, index.limits.page_size))).scalars().all()
        if not page:
            cursors[label] = ""
            continue
        for row in page:
            if remaining <= 0 or time.monotonic() >= deadline:
                break
            summary["examined"] += 1
            if model is IndexSnapshotModel:
                protected = row.id in {index.snapshot_id, index.base_snapshot_id}
                if not protected and row.accessed_at < time.time() - index.limits.retention_seconds:
                    if not exists(IndexPinModel, IndexPinModel.snapshot_id == row.id):
                        remove(model, model.id == row.id)
                        summary[label] += 1
            elif model is IndexTreeModel:
                if not exists(IndexSnapshotModel, IndexSnapshotModel.root_tree_id == row.id) and not exists(IndexEntryModel, IndexEntryModel.child_tree_id == row.id):
                    names = db.scalars(select(IndexEntryModel.name).where(IndexEntryModel.tree_id == row.id)
                        .order_by(IndexEntryModel.name).limit(remaining)).all()
                    if names:
                        remove(IndexEntryModel, IndexEntryModel.tree_id == row.id, IndexEntryModel.name.in_(names))
                    if not remaining or exists(IndexEntryModel, IndexEntryModel.tree_id == row.id):
                        break  # Keep the cursor before a partially reclaimed tree.
                    remove(model, model.id == row.id)
                    summary[label] += 1
            elif not exists(IndexEntryModel, IndexEntryModel.projection_id == row.id):
                pending = False
                for child in (IndexPostingModel, IndexSignalModel, IndexFactModel):
                    keys = list(child.__table__.primary_key.columns)
                    records = db.execute(select(*keys).where(child.projection_id == row.id)
                        .order_by(*keys).limit(remaining)).all()
                    for record in records:
                        if time.monotonic() >= deadline:
                            break
                        remove(child, *(column == value for column, value in zip(keys, record)))
                    if not remaining or exists(child, child.projection_id == row.id):
                        pending = True
                        break
                if pending:
                    break
                remove(model, model.id == row.id)
                summary[label] += 1
            cursors[label] = row.id
    writer.gc_state = cursors
    summary["partial"] = True  # One maintenance page never attests global emptiness.
    summary["row_budget"] = index.limits.gc_rows
    index._commit(force=True)
    db.expire_all()
    return summary
