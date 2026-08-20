"""Evidence schema capturing localized code references and contextual snippets."""

from typing import Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class EvidenceBase(BaseModel):
    """Base fields for an evidence item."""

    file_path: str = Field(..., description="Relative or absolute path of the affected file")
    start_line: Optional[int] = Field(default=None, ge=1, description="Starting line number (1-indexed)")
    end_line: Optional[int] = Field(default=None, ge=1, description="Ending line number (1-indexed)")
    code_snippet: Optional[str] = Field(default=None, description="Relevant extract or excerpt of code")
    context_notes: Optional[str] = Field(default=None, description="Additional contextual explanation or annotations")


class EvidenceCreate(EvidenceBase):
    """Schema used when creating an evidence item."""

    pass


class Evidence(EvidenceBase):
    """Canonical domain schema for an evidence item."""

    id: UUID = Field(default_factory=uuid4, description="Unique identifier of the evidence record")

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "file_path": "src/auth/jwt.py",
                "start_line": 42,
                "end_line": 48,
                "code_snippet": "jwt.decode(token, verify=False)",
                "context_notes": "Unverified JWT signature allows forged authentication tokens."
            }
        }
    }
