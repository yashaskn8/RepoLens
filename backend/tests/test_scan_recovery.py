"""Unit tests for durable outer scan dispatch and startup recovery."""

import asyncio
from datetime import datetime, timezone
import os
import tempfile
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.scan import ScanModel
from app.schemas.enums import ScanStatus
from app.services.scan_recovery import ScanDispatcher, ScanRecoveryService


@pytest.mark.asyncio
async def test_startup_recovery_resumes_interrupted_scans(db_session):
    """Verify that scans in PENDING or RUNNING status on startup are dispatched to resume."""
    scan1 = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo1",
        status=ScanStatus.RUNNING.value,
        commit_hash="1111111111111111111111111111111111111111",
    )
    scan2 = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo2",
        status=ScanStatus.PENDING.value,
        commit_hash="2222222222222222222222222222222222222222",
    )
    scan3 = ScanModel(
        id=str(uuid4()),
        repository_url="https://github.com/org/repo3",
        status=ScanStatus.COMPLETED.value,
        commit_hash="3333333333333333333333333333333333333333",
    )
    db_session.add_all([scan1, scan2, scan3])
    db_session.commit()

    dispatched_scans = []

    def mock_dispatch(scan_id, repo_url, branch=None, checkpoint_db_path=None):
        dispatched_scans.append(scan_id)
        return MagicMock()

    with patch.object(ScanDispatcher, "dispatch_scan", side_effect=mock_dispatch):
        recovered = ScanRecoveryService.recover_unfinished_scans(db_session)

        assert len(recovered) == 2
        assert scan1.id in dispatched_scans
        assert scan2.id in dispatched_scans
        assert scan3.id not in dispatched_scans


@pytest.mark.asyncio
async def test_scan_dispatcher_deduplicates_in_process_active_tasks():
    """Verify that duplicate dispatch requests for the same scan_id in the same process return existing task."""
    scan_id = str(uuid4())
    
    with patch("app.api.routes.scans.execute_background_scan", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = None

        task1 = ScanDispatcher.dispatch_scan(
            scan_id=scan_id,
            repo_url="https://github.com/org/repo",
        )
        task2 = ScanDispatcher.dispatch_scan(
            scan_id=scan_id,
            repo_url="https://github.com/org/repo",
        )

        assert task1 == task2
        assert ScanDispatcher.is_scan_active(scan_id)

        # Wait for task completion
        await task1
        assert not ScanDispatcher.is_scan_active(scan_id)
