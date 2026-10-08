"""Scanner subprocess failures must terminate spawned descendants as well."""

import asyncio
from pathlib import Path
import subprocess
import sys

import pytest

from app.analysis.base import BaseScannerAdapter, ScannerOutputError
from app.analysis.schemas import StaticFinding


class _ProcessTreeScanner(BaseScannerAdapter):
    @property
    def tool_name(self) -> str:
        return "process-tree-fixture"

    @property
    def tool_path(self) -> str:
        return sys.executable

    @property
    def is_enabled(self) -> bool:
        return True

    def _build_command(self, repo_dir: str) -> list[str]:
        return [
            sys.executable,
            str(Path(repo_dir) / "parent.py"),
            str(Path(repo_dir) / "child.py"),
            str(Path(repo_dir) / "child-finished.txt"),
            str(Path(repo_dir) / "child-started.txt"),
        ]

    def parse_output(self, raw_json_str: str, repo_dir: str) -> list[StaticFinding]:
        return []


def _write_process_fixture(directory: Path, *, output_flood: bool) -> tuple[Path, Path]:
    marker = directory / "child-finished.txt"
    started = directory / "child-started.txt"
    (directory / "child.py").write_text(
        "import pathlib, sys, time\n"
        "time.sleep(1.5)\n"
        "pathlib.Path(sys.argv[1]).write_text('survived')\n",
        encoding="utf-8",
    )
    flood = "sys.stdout.buffer.write(b'x' * 131072); sys.stdout.flush()\n" if output_flood else ""
    (directory / "parent.py").write_text(
        "import pathlib, subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
        "pathlib.Path(sys.argv[3]).write_text('started')\n"
        f"{flood}"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    return marker, started


@pytest.mark.asyncio
async def test_timeout_terminates_scanner_descendant_before_cleanup(tmp_path):
    marker, started = _write_process_fixture(tmp_path, output_flood=False)
    scanner = _ProcessTreeScanner()

    with pytest.raises(subprocess.TimeoutExpired):
        await scanner._execute_command(scanner._build_command(str(tmp_path)), cwd=str(tmp_path), timeout_seconds=1)

    assert started.exists(), "fixture child must be launched for this test to be meaningful"
    await asyncio.sleep(1.7)
    assert not marker.exists(), "scanner descendant survived the timed-out parent"


@pytest.mark.asyncio
async def test_cancellation_terminates_scanner_descendant_before_return(tmp_path):
    marker, started = _write_process_fixture(tmp_path, output_flood=False)
    scanner = _ProcessTreeScanner()
    task = asyncio.create_task(
        scanner._execute_command(scanner._build_command(str(tmp_path)), cwd=str(tmp_path), timeout_seconds=8)
    )

    deadline = asyncio.get_running_loop().time() + 3
    while not started.exists() and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.01)
    assert started.exists(), "fixture child must be launched before cancellation"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await asyncio.sleep(1.7)
    assert not marker.exists(), "scanner descendant survived cancelled analysis"


@pytest.mark.asyncio
async def test_output_limit_terminates_scanner_descendant_before_cleanup(tmp_path, monkeypatch):
    marker, started = _write_process_fixture(tmp_path, output_flood=True)
    monkeypatch.setattr("app.analysis.base.MAX_SCANNER_STDOUT_BYTES", 32)
    scanner = _ProcessTreeScanner()

    with pytest.raises(ScannerOutputError):
        await scanner._execute_command(scanner._build_command(str(tmp_path)), cwd=str(tmp_path), timeout_seconds=5)

    assert started.exists(), "fixture child must be launched for this test to be meaningful"
    await asyncio.sleep(1.7)
    assert not marker.exists(), "scanner descendant survived the output-limit termination"
