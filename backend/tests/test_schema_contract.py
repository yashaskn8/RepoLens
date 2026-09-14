"""Test that the published JSON Schema for CallRelationshipClaim structurally
encodes the exact-one endpoint XOR rules, and that the contract version is 2.0.0."""

from __future__ import annotations

import json

from app.agent_tools.schemas import (
    AGENT_TOOL_CONTRACT_VERSION,
    AGENT_TOOL_VERSION,
    CallRelationshipClaim,
    ToolInvocationResult,
    VerifyFindingInput,
)


class TestSchemaFidelity:
    """Defect A: XOR constraints must appear in the JSON Schema."""

    def test_call_relationship_schema_has_allof_with_two_oneof_groups(self):
        schema = CallRelationshipClaim.model_json_schema(mode="validation")
        assert "allOf" in schema, "allOf missing from CallRelationshipClaim schema"
        all_of = schema["allOf"]
        assert len(all_of) == 2, f"Expected 2 allOf groups (source, target), got {len(all_of)}"

    def test_source_oneof_covers_symbol_and_entity(self):
        schema = CallRelationshipClaim.model_json_schema(mode="validation")
        source_oneof = schema["allOf"][0]["oneOf"]
        assert len(source_oneof) == 2
        required_fields = {tuple(alt["required"]) for alt in source_oneof}
        assert ("source_symbol_id",) in required_fields
        assert ("source_entity_id",) in required_fields

    def test_target_oneof_covers_symbol_and_entity(self):
        schema = CallRelationshipClaim.model_json_schema(mode="validation")
        target_oneof = schema["allOf"][1]["oneOf"]
        assert len(target_oneof) == 2
        required_fields = {tuple(alt["required"]) for alt in target_oneof}
        assert ("target_symbol_id",) in required_fields
        assert ("target_entity_id",) in required_fields

    def test_oneof_alternatives_enforce_null_exclusion(self):
        """Each oneOf branch requires one field non-null and the other null."""
        schema = CallRelationshipClaim.model_json_schema(mode="validation")
        for group in schema["allOf"]:
            for alt in group["oneOf"]:
                props = alt["properties"]
                # One field must have {"not": {"type": "null"}} (non-null)
                non_null = [k for k, v in props.items() if "not" in v]
                # One field must have {"type": "null"}
                null_only = [k for k, v in props.items() if v.get("type") == "null"]
                assert len(non_null) == 1, f"Expected 1 non-null field, got {non_null}"
                assert len(null_only) == 1, f"Expected 1 null-only field, got {null_only}"

    def test_verify_finding_input_inherits_call_relationship_constraints(self):
        """VerifyFindingInput's schema must include the CallRelationshipClaim constraints."""
        schema = VerifyFindingInput.model_json_schema(mode="validation")
        schema_str = json.dumps(schema)
        # The allOf/oneOf structure must appear somewhere in the discriminated union schema
        assert "oneOf" in schema_str
        assert "source_symbol_id" in schema_str
        assert "source_entity_id" in schema_str


class TestContractVersion:
    """Defect B: Contract version must be 2.0.0."""

    def test_contract_version_constant(self):
        assert AGENT_TOOL_CONTRACT_VERSION == "2.0.0"

    def test_tool_version_constant(self):
        assert AGENT_TOOL_VERSION == "2.0.0"

    def test_invocation_result_contract_version_field(self):
        result = ToolInvocationResult(
            tool="test",
            tool_version="2.0.0",
            status="SUCCESS",
        )
        assert result.contract_version == "2.0.0"

    def test_invocation_result_schema_enforces_2_0_0(self):
        schema = ToolInvocationResult.model_json_schema(mode="validation")
        cv = schema["properties"]["contract_version"]
        assert cv.get("const") == "2.0.0" or cv.get("default") == "2.0.0"
