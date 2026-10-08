"""Fail-closed gate for repository acquisition without hard isolation.

The application currently has reactive Git object-store monitoring but no
quota-provisioned workspace or enforced egress transport. Those controls must
not be represented as production hard quotas. Until a trusted boundary is
integrated, production acquisition is unavailable; development retains the
existing explicitly weaker protections.
"""

from __future__ import annotations

from typing import Any


class AcquisitionEnforcementUnavailable(RuntimeError):
    """Production acquisition is disabled because its hard boundary is absent."""

    failure_code = "ACQUISITION_ENFORCEMENT_UNAVAILABLE"

    def __init__(self) -> None:
        super().__init__(
            "Repository acquisition is unavailable: a quota-enforced workspace "
            "and controlled-egress boundary have not been provisioned."
        )


def require_acquisition_boundary(settings: Any) -> None:
    """Prevent production Git acquisition from silently using reactive controls."""
    if bool(getattr(settings, "is_production", False)):
        raise AcquisitionEnforcementUnavailable()
