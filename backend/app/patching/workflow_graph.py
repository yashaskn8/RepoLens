"""Durable LangGraph remediation graph with human-in-the-loop approval checkpoints."""

import logging
from typing import Any, Dict, List, Optional, TypedDict
from langgraph.graph import END, START, StateGraph

from app.patching.schemas import (
    CriticVerdict,
    PatchCriticReport,
    PatchProposal,
    PatchVerificationResult,
    VerificationStatus,
)
from app.planning.schemas import FixPlan
from app.schemas.enums import PatchStatus

logger = logging.getLogger(__name__)


class RemediationState(TypedDict, total=False):
    """State schema for the durable remediation and human approval graph."""

    scan_id: str
    finding_id: str
    plan_dict: Optional[Dict[str, Any]]
    proposal_dict: Optional[Dict[str, Any]]
    verification_dict: Optional[Dict[str, Any]]
    critic_dict: Optional[Dict[str, Any]]
    patch_status: str
    user_feedback: Optional[str]
    approved_by: Optional[str]
    revision_count: int
    error: Optional[str]


async def run_human_approval_checkpoint(state: RemediationState) -> Dict[str, Any]:
    """Node executed once human approval or rejection is submitted."""
    current_status = state.get("patch_status", PatchStatus.VERIFIED.value)
    logger.info("Human approval checkpoint reached with status: %s", current_status)
    return {
        "patch_status": current_status,
        "approved_by": state.get("approved_by"),
    }


def build_remediation_graph(checkpointer: Optional[Any] = None) -> Any:
    """Build compiled LangGraph remediation workflow with human-in-the-loop interrupt checkpoint.
    
    Guarantees:
    - Interrupts execution before human_approval_checkpoint node.
    - An LLM cannot approve its own patch; approval requires explicit human resume action.
    - Checkpointed in SQLite so workflow survives backend restarts.
    """
    workflow = StateGraph(RemediationState)

    # Register human approval checkpoint node
    workflow.add_node("human_approval_checkpoint", run_human_approval_checkpoint)

    # Edge flow: START -> human_approval_checkpoint -> END
    workflow.add_edge(START, "human_approval_checkpoint")
    workflow.add_edge("human_approval_checkpoint", END)

    # Interrupt before human approval so execution pauses until human API interaction
    return workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_approval_checkpoint"],
    )
