"""Modular, read-only security scanner for authorised public assets.

Modules:
    * ``config``            - limits, check codes and severity heuristics.
    * ``findings``          - shared ``Finding`` dataclass.
    * ``target_validator``  - hostname validation, DNS resolution, SSRF checks.
    * ``pinned_http``       - DNS-pinned HTTP(S) transport (no re-resolution).
    * ``tls_inspector``     - certificate inspection.
    * ``https_inspector``   - HTTPS reachability and redirect validation.
    * ``header_inspector``  - HTTP security header inspection.
    * ``dns_inspector``     - SPF/DMARC/CAA inspection.
    * ``scan_manager``      - orchestration and persistence.
"""

from app.services.scanner.findings import Finding

__all__ = ["Finding"]