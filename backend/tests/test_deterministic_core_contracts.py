"""Regression coverage for RepoLens-owned security and request-contract analysis."""

from pathlib import Path

from app.analysis.core import analyze_core_repository
from app.graph.builder import build_repository_graph
from app.graph.schemas import ContractMatchStatus
from app.ingestion.parser import parse_file_with_calls
from app.ingestion.schemas import FileEntry, RepositoryManifest


def _entry(path: str, language: str | None, source: str) -> FileEntry:
    symbols, calls = parse_file_with_calls(path, language, source.encode()) if language else ([], [])
    return FileEntry(
        path=path,
        language=language,
        size_bytes=len(source.encode()),
        lines_count=len(source.splitlines()),
        symbols=symbols,
        calls=calls,
    )


def _manifest(entries: list[FileEntry]) -> RepositoryManifest:
    return RepositoryManifest(
        repository_url="https://github.com/example/repo",
        commit_hash="a" * 40,
        total_files=len(entries),
        files=entries,
    )


def test_client_controlled_identity_is_detected_but_verified_identity_is_not(tmp_path: Path):
    unsafe = """from fastapi import Header, Request
async def set_tenant(request: Request):
    tenant_id = request.headers.get("X-Tenant-ID")
    current_tenant_id.set(tenant_id)

def require_role(x_user_roles: str = Header(None, alias="X-User-Roles")):
    roles = x_user_roles.split(",")
    if not any(role in allowed_roles for role in roles):
        raise ForbiddenError()
"""
    safe = """from fastapi import Header
def set_tenant(x_tenant_id: str = Header(None, alias="X-Tenant-ID")):
    identity = verify_signed_identity(x_tenant_id)
    current_tenant_id.set(identity.tenant_id)
"""
    (tmp_path / "unsafe.py").write_text(unsafe, encoding="utf-8")
    (tmp_path / "safe.py").write_text(safe, encoding="utf-8")
    result = analyze_core_repository(
        str(tmp_path),
        _manifest([_entry("unsafe.py", "python", unsafe), _entry("safe.py", "python", safe)]),
    )

    assert result.status.value == "COMPLETED"
    assert {finding.raw_details["header"] for finding in result.findings} == {"X-Tenant-ID", "X-User-Roles"}
    assert all(finding.evidence.file_path == "unsafe.py" for finding in result.findings)


def test_hardcoded_terraform_credential_is_detected_but_secret_reference_is_not(tmp_path: Path):
    terraform = """resource "aws_db_instance" "primary" {
  password = "FixedProductionPassword123!"
  backup_password = var.database_password
}
"""
    path = tmp_path / "main.tf"
    path.write_text(terraform, encoding="utf-8")
    yaml = """api_key: fixed-yaml-key-1234
password: ${DB_PASSWORD}
secretName: public-tls-certificate-name
secret_id: aws_secretsmanager_secret.database.id
"""
    (tmp_path / "config.yaml").write_text(yaml, encoding="utf-8")
    result = analyze_core_repository(
        str(tmp_path),
        _manifest([_entry("main.tf", None, terraform), _entry("config.yaml", None, yaml)]),
    )

    assert len(result.findings) == 2
    terraform_finding = next(finding for finding in result.findings if finding.evidence.file_path == "main.tf")
    assert terraform_finding.detector_kind == "deterministic_secret"
    assert terraform_finding.evidence.start_line == 2
    serialized = str([finding.model_dump() for finding in result.findings])
    assert "FixedProductionPassword123" not in serialized
    assert "fixed-yaml-key-1234" not in serialized


def test_ci_fixture_credentials_are_not_reported_as_production_secrets(tmp_path: Path):
    workflow = """env:
  POSTGRES_PASSWORD: postgres
  JWT_SECRET_KEY: ci-test-secret-key-min-32-characters
"""
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True)
    path.write_text(workflow, encoding="utf-8")

    result = analyze_core_repository(
        str(tmp_path),
        _manifest([_entry(".github/workflows/ci.yml", None, workflow)]),
    )

    assert result.findings == []


def test_shell_configuration_is_passively_checked_without_flagging_runtime_references(tmp_path: Path):
    script = """#!/bin/sh
DB_PASSWORD=${DB_PASSWORD:?required}
ADMIN_PASSWORD=FixedProductionAdmin987!
"""
    path = tmp_path / "init.sh"
    path.write_text(script, encoding="utf-8")

    result = analyze_core_repository(
        str(tmp_path),
        _manifest([_entry("init.sh", "shell", script)]),
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence.start_line == 3
    assert "FixedProductionAdmin987" not in str(result.findings[0].model_dump())


def test_routes_prefixes_parameters_and_missing_endpoints_match_exactly():
    backend = """from fastapi import APIRouter
router = APIRouter(prefix="/api/v1/items")
@router.get("/{item_id}")
async def get_item(item_id: str):
    return item_id
"""
    frontend = """export async function load(itemId: string) {
  await apiClient.get(`/api/v1/items/${itemId}`)
  await apiClient.get("/api/v1/orders")
}
"""
    graph = build_repository_graph(_manifest([
        _entry("services/items/router.py", "python", backend),
        _entry("frontend/api.ts", "typescript", frontend),
    ]))
    report = graph.evaluate_route_contracts()

    assert report.total_frontend_requests == 2
    statuses = {match.frontend_url: match.status for match in report.matches}
    assert statuses["/api/v1/items/${itemId}"] == ContractMatchStatus.MATCHED
    assert statuses["/api/v1/orders"] == ContractMatchStatus.UNMATCHED_FRONTEND_REQUEST


def test_payload_type_required_nested_and_optional_contracts():
    schemas = """from pydantic import BaseModel, Field
class ReserveItem(BaseModel):
    product_id: str
    quantity: int

class ReserveRequest(BaseModel):
    items: list[ReserveItem] = Field(..., min_length=1)

class OrderItem(BaseModel):
    product_id: str
    quantity: int
    unit_price: float

class OrderCreate(BaseModel):
    items: list[OrderItem]
    idempotency_key: str
    note: str | None = None
"""
    backend = """from fastapi import APIRouter
from .schemas import ReserveRequest, OrderCreate
router = APIRouter(prefix="/api/v1")
@router.post("/reserve")
async def reserve(payload: ReserveRequest):
    return payload

@router.post("/orders")
async def order(payload: OrderCreate):
    return payload
"""
    frontend = """const reserveItems = [{ product_id: "p1", quantity: 1 }]
const lineItems = products.map((item) => ({ product_id: item.id, quantity: item.quantity }))
export async function submit() {
  await apiClient.post("/api/v1/reserve", reserveItems)
  await apiClient.post("/api/v1/orders", { items: lineItems })
}
"""
    graph = build_repository_graph(_manifest([
        _entry("services/orders/schemas.py", "python", schemas),
        _entry("services/orders/router.py", "python", backend),
        _entry("frontend/checkout.ts", "typescript", frontend),
    ]))
    report = graph.evaluate_route_contracts()
    matches = {match.frontend_url: match for match in report.matches}

    reserve = matches["/api/v1/reserve"]
    assert reserve.status == ContractMatchStatus.REQUEST_BODY_TYPE_MISMATCH
    orders = matches["/api/v1/orders"]
    assert orders.status == ContractMatchStatus.REQUEST_BODY_MISSING_REQUIRED_FIELDS
    assert orders.missing_required_fields == ["idempotency_key"]
    assert orders.missing_item_fields == {"items": ["unit_price"]}
    assert "note" not in orders.missing_required_fields
    assert report.payload_mismatch_count == 2


def test_matching_payload_omits_only_optional_field_without_finding():
    source = """from fastapi import APIRouter
from pydantic import BaseModel
class CreateItem(BaseModel):
    name: str
    note: str | None = None
router = APIRouter(prefix="/api")
@router.post("/items")
async def create(payload: CreateItem):
    return payload
"""
    frontend = 'apiClient.post("/api/items", { name: "item" })'
    graph = build_repository_graph(_manifest([
        _entry("app.py", "python", source),
        _entry("client.ts", "typescript", frontend),
    ]))

    report = graph.evaluate_route_contracts()
    assert report.matched_count == 1
    assert report.payload_mismatch_count == 0
    assert report.matches[0].status == ContractMatchStatus.MATCHED


def test_dynamic_and_test_only_requests_do_not_create_endpoint_claims():
    source = """export async function load(url: string) {
  await fetch(url)
}
"""
    test_source = 'apiClient.get("/api/v1/test-only")'
    graph = build_repository_graph(_manifest([
        _entry("frontend/client.ts", "typescript", source),
        _entry("frontend/client.test.ts", "typescript", test_source),
    ]))

    report = graph.evaluate_route_contracts()
    assert report.total_frontend_requests == 0
    assert report.matches == []


def test_fetch_json_body_is_checked_against_required_schema_fields():
    backend = """from fastapi import APIRouter
from pydantic import BaseModel, Field
class CreateItem(BaseModel):
    name: str
    labels: list[str] = Field(default_factory=list)
router = APIRouter(prefix="/api")
@router.post("/items")
async def create(payload: CreateItem):
    return payload
"""
    frontend = """fetch("/api/items", {
  method: "POST",
  body: JSON.stringify({ labels: [] })
})
"""
    graph = build_repository_graph(_manifest([
        _entry("app.py", "python", backend),
        _entry("client.ts", "typescript", frontend),
    ]))

    report = graph.evaluate_route_contracts()
    assert report.payload_mismatch_count == 1
    assert report.matches[0].missing_required_fields == ["name"]
    assert "labels" not in report.matches[0].missing_required_fields
