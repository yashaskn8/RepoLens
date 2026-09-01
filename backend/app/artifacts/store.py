"""Content-addressed artifact storage contracts and adapters.

The production adapter depends only on a small conditional-object client
contract.  An S3, GCS, Azure Blob, or compatible implementation can satisfy
that contract without leaking vendor concepts into artifact lifecycle code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
from typing import BinaryIO, Mapping, Protocol, runtime_checkable

from app.artifacts.schemas import ArtifactSensitivity, RetentionClass


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_LOCATOR_RE = re.compile(
    r"^objects/[0-9a-f]{32}/[A-Za-z0-9_-]{1,2}/[A-Za-z0-9_-]{1,128}/[0-9a-f]{64}$"
)
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ArtifactStoreError(RuntimeError):
    pass


class ArtifactNotFoundError(ArtifactStoreError):
    pass


class ArtifactTombstonedError(ArtifactStoreError):
    pass


class ArtifactIntegrityError(ArtifactStoreError):
    pass


class ArtifactConflictError(ArtifactStoreError):
    pass


class BlobAlreadyExists(ArtifactConflictError):
    """Raised by a BlobClient when conditional create loses a race."""


@dataclass(frozen=True)
class ArtifactPutRequest:
    tenant_id: str
    artifact_id: str
    expected_digest: str
    content_type: str
    sensitivity: ArtifactSensitivity
    retention_class: RetentionClass
    expected_size_bytes: int | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.artifact_id, "artifact_id")
        _require_digest(self.expected_digest)
        if not self.tenant_id or len(self.tenant_id) > 128:
            raise ValueError("tenant_id must contain between 1 and 128 characters")
        if not self.content_type or len(self.content_type) > 128:
            raise ValueError("content_type must contain between 1 and 128 characters")
        if self.expected_size_bytes is not None and self.expected_size_bytes < 0:
            raise ValueError("expected_size_bytes cannot be negative")


@dataclass(frozen=True)
class ArtifactObjectMetadata:
    locator: str
    content_digest: str
    size_bytes: int
    content_type: str
    etag: str | None
    created_at: datetime
    sensitivity: ArtifactSensitivity
    retention_class: RetentionClass
    tombstoned: bool = False


@dataclass(frozen=True)
class ArtifactDeleteResult:
    deleted: bool
    already_absent: bool


@runtime_checkable
class ArtifactStore(Protocol):
    """Atomic, content-addressed payload store used by every artifact type."""

    def put(self, request: ArtifactPutRequest, payload: BinaryIO) -> ArtifactObjectMetadata: ...
    def publish_atomic(self, request: ArtifactPutRequest, payload: BinaryIO) -> ArtifactObjectMetadata: ...
    def get(self, locator: str) -> BinaryIO: ...
    def exists(self, locator: str, *, include_tombstoned: bool = False) -> bool: ...
    def verify_digest(self, locator: str, expected_digest: str) -> bool: ...
    def metadata(
        self, locator: str, *, include_tombstoned: bool = False
    ) -> ArtifactObjectMetadata: ...
    def tombstone(self, locator: str, *, reason_code: str) -> bool: ...
    def delete(self, locator: str, *, expected_digest: str) -> ArtifactDeleteResult: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_digest(value: str) -> str:
    normalized = value.lower()
    if not _DIGEST_RE.fullmatch(normalized):
        raise ValueError("expected_digest must be a lowercase SHA-256 value")
    return normalized


def _require_identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{field_name} contains unsupported characters")
    return value


def _require_locator(locator: str) -> str:
    if not _LOCATOR_RE.fullmatch(locator):
        raise ArtifactStoreError("artifact locator is not a server-generated object locator")
    return locator


def _require_reason(reason_code: str) -> str:
    if not _REASON_RE.fullmatch(reason_code):
        raise ValueError("reason_code must be a bounded uppercase machine code")
    return reason_code


def artifact_locator(request: ArtifactPutRequest) -> str:
    tenant_segment = hashlib.sha256(request.tenant_id.encode("utf-8")).hexdigest()[:32]
    prefix = request.artifact_id[:2]
    return f"objects/{tenant_segment}/{prefix}/{request.artifact_id}/{request.expected_digest}"


def _tombstone_locator(locator: str) -> str:
    locator_digest = hashlib.sha256(locator.encode("utf-8")).hexdigest()
    return f"tombstones/{locator_digest[:2]}/{locator_digest}.json"


def _copy_and_hash(source: BinaryIO, destination: BinaryIO, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise ArtifactStoreError("artifact payload stream must be opened in binary mode")
        size += len(chunk)
        if size > max_bytes:
            raise ArtifactStoreError("artifact payload exceeds the configured storage limit")
        digest.update(chunk)
        destination.write(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class LocalArtifactStore:
    """Root-confined local adapter with atomic publication and durable markers."""

    root: Path
    max_object_bytes: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be positive")
        object.__setattr__(self, "root", self.root.expanduser().resolve())

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / ".staging").mkdir(parents=True, exist_ok=True)

    def _resolve(self, locator: str, *, object_locator: bool = True) -> Path:
        if object_locator:
            _require_locator(locator)
        elif not locator.startswith("tombstones/") or ".." in Path(locator).parts:
            raise ArtifactStoreError("invalid tombstone locator")
        candidate = (self.root / locator).resolve()
        if candidate == self.root or self.root not in candidate.parents:
            raise ArtifactStoreError("artifact locator escaped the configured root")
        return candidate

    def _metadata_path(self, locator: str) -> Path:
        return self._resolve(locator).with_name(self._resolve(locator).name + ".meta.json")

    def _marker_path(self, locator: str) -> Path:
        return self._resolve(_tombstone_locator(locator), object_locator=False)

    def _write_json_atomic(self, destination: Path, payload: Mapping[str, object]) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="metadata.",
            suffix=".tmp",
            dir=self.root / ".staging",
            delete=False,
        )
        temporary = Path(handle.name)
        try:
            with handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    def put(self, request: ArtifactPutRequest, payload: BinaryIO) -> ArtifactObjectMetadata:
        return self.publish_atomic(request, payload)

    def publish_atomic(self, request: ArtifactPutRequest, payload: BinaryIO) -> ArtifactObjectMetadata:
        self._ensure_root()
        locator = artifact_locator(request)
        if self._marker_path(locator).exists():
            raise ArtifactTombstonedError("artifact locator has a durable tombstone")
        destination = self._resolve(locator)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix="payload.", suffix=".tmp", dir=self.root / ".staging")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as output:
                digest, size = _copy_and_hash(payload, output, max_bytes=self.max_object_bytes)
                output.flush()
                os.fsync(output.fileno())
            if digest != request.expected_digest:
                raise ArtifactIntegrityError("artifact payload did not match its declared digest")
            if request.expected_size_bytes is not None and size != request.expected_size_bytes:
                raise ArtifactIntegrityError("artifact payload did not match its declared size")
            if destination.exists():
                if not self._verify_path(destination, request.expected_digest):
                    raise ArtifactIntegrityError("existing artifact object failed digest verification")
            else:
                os.replace(temporary, destination)

            created_at = _utc_now()
            metadata_payload = {
                "locator": locator,
                "content_digest": request.expected_digest,
                "size_bytes": size,
                "content_type": request.content_type,
                "created_at": created_at.isoformat(),
                "sensitivity": request.sensitivity.value,
                "retention_class": request.retention_class.value,
            }
            metadata_path = self._metadata_path(locator)
            if not metadata_path.exists():
                self._write_json_atomic(metadata_path, metadata_payload)
            return self.metadata(locator)
        finally:
            temporary.unlink(missing_ok=True)

    def get(self, locator: str) -> BinaryIO:
        if self._marker_path(locator).exists():
            raise ArtifactTombstonedError("artifact payload is tombstoned")
        path = self._resolve(locator)
        if not path.is_file() or not self._metadata_path(locator).is_file():
            raise ArtifactNotFoundError("artifact payload was not found")
        return path.open("rb")

    def exists(self, locator: str, *, include_tombstoned: bool = False) -> bool:
        try:
            path = self._resolve(locator)
            physically_present = path.is_file() and self._metadata_path(locator).is_file()
            return physically_present and (include_tombstoned or not self._marker_path(locator).exists())
        except (OSError, ArtifactStoreError):
            return False

    def _verify_path(self, path: Path, expected_digest: str) -> bool:
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return False
        return digest.hexdigest() == expected_digest

    def verify_digest(self, locator: str, expected_digest: str) -> bool:
        try:
            expected_digest = _require_digest(expected_digest)
            return self._verify_path(self._resolve(locator), expected_digest)
        except (OSError, ValueError, ArtifactStoreError):
            return False

    def metadata(
        self, locator: str, *, include_tombstoned: bool = False
    ) -> ArtifactObjectMetadata:
        path = self._resolve(locator)
        metadata_path = self._metadata_path(locator)
        if not path.is_file() or not metadata_path.is_file():
            raise ArtifactNotFoundError("artifact payload metadata was not found")
        tombstoned = self._marker_path(locator).exists()
        if tombstoned and not include_tombstoned:
            raise ArtifactTombstonedError("artifact payload is tombstoned")
        try:
            raw = json.loads(metadata_path.read_text(encoding="utf-8"))
            if raw["locator"] != locator:
                raise ArtifactIntegrityError("artifact metadata locator mismatch")
            return ArtifactObjectMetadata(
                locator=locator,
                content_digest=_require_digest(str(raw["content_digest"])),
                size_bytes=int(raw["size_bytes"]),
                content_type=str(raw["content_type"]),
                etag=None,
                created_at=datetime.fromisoformat(str(raw["created_at"])),
                sensitivity=ArtifactSensitivity(str(raw["sensitivity"])),
                retention_class=RetentionClass(str(raw["retention_class"])),
                tombstoned=tombstoned,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ArtifactIntegrityError("artifact metadata is invalid") from exc

    def tombstone(self, locator: str, *, reason_code: str) -> bool:
        self._ensure_root()
        _require_locator(locator)
        _require_reason(reason_code)
        marker = self._marker_path(locator)
        if marker.exists():
            return False
        self._write_json_atomic(
            marker,
            {
                "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
                "reason_code": reason_code,
                "tombstoned_at": _utc_now().isoformat(),
            },
        )
        return True

    def delete(self, locator: str, *, expected_digest: str) -> ArtifactDeleteResult:
        expected_digest = _require_digest(expected_digest)
        if not self._marker_path(locator).is_file():
            raise ArtifactStoreError("physical deletion requires a durable tombstone marker")
        path = self._resolve(locator)
        metadata_path = self._metadata_path(locator)
        if not path.exists():
            metadata_path.unlink(missing_ok=True)
            return ArtifactDeleteResult(deleted=False, already_absent=True)
        if not self._verify_path(path, expected_digest):
            raise ArtifactIntegrityError("refused to delete an artifact with a digest mismatch")
        path.unlink()
        metadata_path.unlink(missing_ok=True)
        return ArtifactDeleteResult(deleted=True, already_absent=False)


@dataclass(frozen=True)
class BlobObjectHead:
    key: str
    size_bytes: int
    etag: str
    content_type: str
    metadata: Mapping[str, str]
    last_modified: datetime


@runtime_checkable
class ConditionalBlobClient(Protocol):
    """Vendor adapter contract. Credentials remain inside its implementation."""

    def put_if_absent(
        self,
        key: str,
        payload: BinaryIO,
        *,
        content_length: int,
        content_type: str,
        metadata: Mapping[str, str],
        require_server_side_encryption: bool,
    ) -> BlobObjectHead: ...

    def open_read(self, key: str) -> BinaryIO: ...
    def head(self, key: str) -> BlobObjectHead | None: ...
    def delete_if_match(self, key: str, *, etag: str) -> bool: ...


@dataclass(frozen=True)
class ProductionBlobStoreConfig:
    namespace: str = "repolens/v1"
    max_object_bytes: int = 512 * 1024 * 1024
    spool_memory_bytes: int = 8 * 1024 * 1024
    require_server_side_encryption: bool = True
    digest_metadata_key: str = "repolens-sha256"

    def __post_init__(self) -> None:
        segments = self.namespace.split("/")
        if not segments or any(not _IDENTIFIER_RE.fullmatch(segment) for segment in segments):
            raise ValueError("namespace must contain only bounded safe path segments")
        if self.max_object_bytes <= 0 or self.spool_memory_bytes <= 0:
            raise ValueError("blob storage size limits must be positive")
        if not _IDENTIFIER_RE.fullmatch(self.digest_metadata_key):
            raise ValueError("digest_metadata_key contains unsupported characters")


@dataclass(frozen=True)
class ProductionBlobArtifactStore:
    """Multi-host adapter over conditional create and conditional delete."""

    config: ProductionBlobStoreConfig
    client: ConditionalBlobClient

    def _key(self, locator: str) -> str:
        _require_locator(locator)
        return f"{self.config.namespace}/{locator}"

    def _marker_key(self, locator: str) -> str:
        _require_locator(locator)
        return f"{self.config.namespace}/{_tombstone_locator(locator)}"

    def _is_tombstoned(self, locator: str) -> bool:
        return self.client.head(self._marker_key(locator)) is not None

    def put(self, request: ArtifactPutRequest, payload: BinaryIO) -> ArtifactObjectMetadata:
        return self.publish_atomic(request, payload)

    def publish_atomic(self, request: ArtifactPutRequest, payload: BinaryIO) -> ArtifactObjectMetadata:
        locator = artifact_locator(request)
        if self._is_tombstoned(locator):
            raise ArtifactTombstonedError("artifact locator has a durable tombstone")
        with tempfile.SpooledTemporaryFile(max_size=self.config.spool_memory_bytes, mode="w+b") as spool:
            digest, size = _copy_and_hash(payload, spool, max_bytes=self.config.max_object_bytes)
            if digest != request.expected_digest:
                raise ArtifactIntegrityError("artifact payload did not match its declared digest")
            if request.expected_size_bytes is not None and size != request.expected_size_bytes:
                raise ArtifactIntegrityError("artifact payload did not match its declared size")
            spool.seek(0)
            metadata = {
                self.config.digest_metadata_key: digest,
                "repolens-sensitivity": request.sensitivity.value,
                "repolens-retention": request.retention_class.value,
            }
            try:
                head = self.client.put_if_absent(
                    self._key(locator),
                    spool,
                    content_length=size,
                    content_type=request.content_type,
                    metadata=metadata,
                    require_server_side_encryption=self.config.require_server_side_encryption,
                )
            except BlobAlreadyExists:
                head = self.client.head(self._key(locator))
                if head is None:
                    raise ArtifactConflictError("artifact publication raced with object removal")
            if head.metadata.get(self.config.digest_metadata_key) != digest or head.size_bytes != size:
                raise ArtifactIntegrityError("published blob metadata did not match the artifact")
        return self.metadata(locator)

    def get(self, locator: str) -> BinaryIO:
        if self._is_tombstoned(locator):
            raise ArtifactTombstonedError("artifact payload is tombstoned")
        if self.client.head(self._key(locator)) is None:
            raise ArtifactNotFoundError("artifact payload was not found")
        return self.client.open_read(self._key(locator))

    def exists(self, locator: str, *, include_tombstoned: bool = False) -> bool:
        try:
            return self.client.head(self._key(locator)) is not None and (
                include_tombstoned or not self._is_tombstoned(locator)
            )
        except ArtifactStoreError:
            return False

    def verify_digest(self, locator: str, expected_digest: str) -> bool:
        try:
            expected_digest = _require_digest(expected_digest)
            stream = self.client.open_read(self._key(locator))
            with stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest() == expected_digest
        except (OSError, ValueError, ArtifactStoreError):
            return False

    def metadata(
        self, locator: str, *, include_tombstoned: bool = False
    ) -> ArtifactObjectMetadata:
        head = self.client.head(self._key(locator))
        if head is None:
            raise ArtifactNotFoundError("artifact payload metadata was not found")
        tombstoned = self._is_tombstoned(locator)
        if tombstoned and not include_tombstoned:
            raise ArtifactTombstonedError("artifact payload is tombstoned")
        try:
            digest = _require_digest(head.metadata[self.config.digest_metadata_key])
            sensitivity = ArtifactSensitivity(head.metadata["repolens-sensitivity"])
            retention = RetentionClass(head.metadata["repolens-retention"])
        except (KeyError, ValueError) as exc:
            raise ArtifactIntegrityError("blob metadata is incomplete or invalid") from exc
        return ArtifactObjectMetadata(
            locator=locator,
            content_digest=digest,
            size_bytes=head.size_bytes,
            content_type=head.content_type,
            etag=head.etag,
            created_at=head.last_modified,
            sensitivity=sensitivity,
            retention_class=retention,
            tombstoned=tombstoned,
        )

    def tombstone(self, locator: str, *, reason_code: str) -> bool:
        _require_reason(reason_code)
        marker = json.dumps(
            {
                "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
                "reason_code": reason_code,
                "tombstoned_at": _utc_now().isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            self.client.put_if_absent(
                self._marker_key(locator),
                io.BytesIO(marker),
                content_length=len(marker),
                content_type="application/json",
                metadata={"repolens-marker": "tombstone"},
                require_server_side_encryption=self.config.require_server_side_encryption,
            )
            return True
        except BlobAlreadyExists:
            return False

    def delete(self, locator: str, *, expected_digest: str) -> ArtifactDeleteResult:
        expected_digest = _require_digest(expected_digest)
        if not self._is_tombstoned(locator):
            raise ArtifactStoreError("physical deletion requires a durable tombstone marker")
        head = self.client.head(self._key(locator))
        if head is None:
            return ArtifactDeleteResult(deleted=False, already_absent=True)
        if head.metadata.get(self.config.digest_metadata_key) != expected_digest:
            raise ArtifactIntegrityError("refused to delete a blob with a digest metadata mismatch")
        if not self.verify_digest(locator, expected_digest):
            raise ArtifactIntegrityError("refused to delete a blob with a content digest mismatch")
        deleted = self.client.delete_if_match(self._key(locator), etag=head.etag)
        if not deleted:
            raise ArtifactConflictError("blob changed during conditional deletion")
        return ArtifactDeleteResult(deleted=True, already_absent=False)
