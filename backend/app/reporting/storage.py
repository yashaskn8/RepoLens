"""Opaque report artifact storage with a confined local implementation."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, Protocol

from app.core.config import Settings, get_settings


class ArtifactStorageError(RuntimeError):
    pass


class ReportArtifactStorage(Protocol):
    def publish_document(self, report_id: str, payload: bytes) -> tuple[str, str]: ...
    def discard_document(self, locator: str, digest: str) -> bool: ...
    def create_pdf_temp(self, report_id: str) -> Path: ...
    def publish_pdf(self, report_id: str, digest: str, temp_path: Path) -> str: ...
    def resolve_document(self, locator: str) -> Path: ...
    def resolve_pdf(self, locator: str) -> Path: ...
    def verify(self, locator: str, digest: str, *, kind: str) -> bool: ...


def stream_sha256(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class LocalReportArtifactStorage:
    """Filesystem adapter. Every path is server-generated and root-confined."""

    root: Path

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "LocalReportArtifactStorage":
        configured = (settings or get_settings()).REPORT_ARTIFACT_DIR
        return cls(root=Path(configured).expanduser().resolve())

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / ".tmp").mkdir(parents=True, exist_ok=True)

    def _resolve(self, locator: str, suffix: str) -> Path:
        if not locator or Path(locator).is_absolute() or not locator.endswith(suffix):
            raise ArtifactStorageError("Invalid report artifact locator.")
        candidate = (self.root / locator).resolve()
        if candidate == self.root or self.root not in candidate.parents:
            raise ArtifactStorageError("Report artifact locator escaped its configured root.")
        return candidate

    @staticmethod
    def _validate_identity(value: str) -> str:
        normalized = value.replace("-", "")
        if not normalized or not normalized.isalnum() or len(value) > 128:
            raise ArtifactStorageError("Invalid server-generated report identity.")
        return value

    def publish_document(self, report_id: str, payload: bytes) -> tuple[str, str]:
        self._ensure_root()
        report_id = self._validate_identity(report_id)
        digest = hashlib.sha256(payload).hexdigest()
        locator = f"documents/{report_id[:2]}/{report_id}/{digest}.json"
        destination = self._resolve(locator, ".json")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            with destination.open("rb") as existing:
                if stream_sha256(existing) != digest:
                    raise ArtifactStorageError("Existing report document failed digest verification.")
            return locator, digest

        handle = tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f"{report_id}.",
            suffix=".json.tmp",
            dir=self.root / ".tmp",
            delete=False,
        )
        temp_path = Path(handle.name)
        try:
            with handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, destination)
        finally:
            temp_path.unlink(missing_ok=True)
        return locator, digest

    def create_pdf_temp(self, report_id: str) -> Path:
        self._ensure_root()
        report_id = self._validate_identity(report_id)
        fd, name = tempfile.mkstemp(prefix=f"{report_id}.", suffix=".pdf.tmp", dir=self.root / ".tmp")
        os.close(fd)
        return Path(name)

    def discard_document(self, locator: str, digest: str) -> bool:
        """Remove only an unpublished document whose content still matches its digest."""
        path = self.resolve_document(locator)
        if not path.is_file():
            return False
        with path.open("rb") as stream:
            if stream_sha256(stream) != digest:
                raise ArtifactStorageError("Refused to discard a report document with a digest mismatch.")
        path.unlink()
        return True

    def publish_pdf(self, report_id: str, digest: str, temp_path: Path) -> str:
        self._ensure_root()
        report_id = self._validate_identity(report_id)
        if not re_full_sha256(digest):
            raise ArtifactStorageError("Invalid PDF digest.")
        temp_resolved = temp_path.resolve()
        temp_root = (self.root / ".tmp").resolve()
        if temp_root not in temp_resolved.parents:
            raise ArtifactStorageError("PDF temporary file escaped the artifact root.")
        if not temp_resolved.is_file():
            raise ArtifactStorageError("PDF temporary file was unavailable.")
        with temp_resolved.open("rb") as stream:
            if stream_sha256(stream) != digest:
                raise ArtifactStorageError("PDF temporary file failed digest verification.")
        locator = f"pdf/{report_id[:2]}/{report_id}/{digest}.pdf"
        destination = self._resolve(locator, ".pdf")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            with destination.open("rb") as existing:
                if stream_sha256(existing) != digest:
                    raise ArtifactStorageError("Existing PDF failed digest verification.")
            temp_resolved.unlink(missing_ok=True)
            return locator
        os.replace(temp_resolved, destination)
        return locator

    def resolve_document(self, locator: str) -> Path:
        return self._resolve(locator, ".json")

    def resolve_pdf(self, locator: str) -> Path:
        return self._resolve(locator, ".pdf")

    def verify(self, locator: str, digest: str, *, kind: str) -> bool:
        try:
            path = self.resolve_pdf(locator) if kind == "pdf" else self.resolve_document(locator)
            if not path.is_file():
                return False
            with path.open("rb") as stream:
                return stream_sha256(stream) == digest
        except (OSError, ArtifactStorageError):
            return False


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())
