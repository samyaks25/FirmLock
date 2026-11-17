"""Scanner-internal data structures.

These lightweight dataclasses are shared across scanner modules so that each
inspector can return structured findings without importing the SQLAlchemy
models. The scan manager is responsible for persisting them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """A single scanner finding.

    Attributes:
        check_code: Stable identifier for the check (see ``CheckCodes``).
        title: Short human-readable title.
        description: Explanation of what was observed.
        severity: One of ``critical``/``high``/``medium``/``low``/``info``.
        recommendation: Suggested remediation.
        evidence: Optional supporting evidence (values, headers, ...).
    """

    check_code: str
    title: str
    description: str
    severity: str
    recommendation: str
    evidence: Optional[str] = None