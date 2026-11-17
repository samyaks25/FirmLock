# FirmLock Backend

Backend API for **FirmLock**, a cybersecurity monitoring platform for small and
medium-sized businesses.

This stage implements the FastAPI foundation plus a SQLite/SQLAlchemy 2.x data
layer, ORM models, Pydantic schemas, service modules, and REST endpoints for
businesses, assets, on-demand read-only security scans (TLS/SSL, HTTPS,
security headers, and SPF/DMARC/CAA DNS records), and an explainable **risk
assessment and security scoring engine**. It is a **local MVP** and is **not**
production-ready multi-tenant infrastructure.

## Project layout

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── businesses.py
│   │       ├── assets.py
│   │       ├── scans.py
│   │       └── risk.py            # risk assessment endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py
│   ├── database/
│   │   ├── __init__.py
│   │   └── connection.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── models.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── business.py
│   │   ├── asset.py
│   │   ├── scan.py
│   │   └── risk.py                # risk assessment response schemas
│   └── services/
│       ├── __init__.py
│       ├── business_service.py
│       ├── asset_service.py
│       ├── risk_config.py         # configurable scoring weights
│       ├── risk_service.py        # scoring, coverage, assessment snapshots
│       └── scanner/
│           ├── __init__.py
│           ├── config.py            # limits, check codes, severity heuristics
│           ├── findings.py          # shared Finding dataclass
│           ├── check_catalog.py     # expected checks + outcome derivation
│           ├── target_validator.py  # domain/DNS validation + SSRF protection
│           ├── pinned_http.py       # DNS-pinned HTTP(S) transport
│           ├── tls_inspector.py     # SSL/TLS certificate inspection
│           ├── https_inspector.py   # HTTPS + HTTP->HTTPS redirect checks
│           ├── header_inspector.py  # HTTP security header checks
│           ├── dns_inspector.py     # SPF / DMARC / CAA checks
│           └── scan_manager.py      # orchestration + persistence + scoring
├── data/                    # local SQLite DB (gitignored, auto-created)
├── tests/
│   ├── test_api.py
│   ├── test_database.py
│   ├── test_business_asset_api.py
│   ├── test_scanner_validators.py
│   ├── test_scanner_inspectors.py
│   ├── test_scan_manager.py
│   ├── test_scan_api.py
│   ├── test_risk_engine.py
│   └── test_risk_api.py
├── requirements.txt
└── README.md
```

## Database architecture

- **Engine/ORM:** SQLAlchemy 2.x (`DeclarativeBase`, typed `mapped_column`/`Mapped`).
- **Database:** SQLite by default, URL configurable via `FIRMLOCK_DATABASE_URL`.
- **Location:** default file `backend/data/firmlock.db`; `data/` is created automatically and gitignored.
- **Sessions:** `SessionLocal` factory and FastAPI `get_db` dependency (per-request session, closed in `finally`).
- **SQLite specifics:** `check_same_thread=False` and `PRAGMA foreign_keys=ON` enforced on every connection.
- **Initialization:** tables are created automatically at app startup via `init_db()` / `Base.metadata.create_all(...)`.
- **Migrations:** **not** implemented. `create_all` is an initial development approach only; Alembic (or equivalent) migrations are required before production deployment and schema evolution.

## Database models

| Model | Key fields | Constraints/notes |
|---|---|---|
| **Business** | `id`, `name` (required), `industry` (optional), `created_at`, `updated_at` (UTC) | Root tenant-like entity for MVP |
| **Asset** | `id`, `business_id` (FK), `domain`, `authorization_confirmed`, `authorization_confirmed_at`, `monitoring_enabled` (default true), `status` (`active`/`paused`), `last_scanned_at`, timestamps | Unique `(business_id, domain)`; status check; authorization is a user attestation, **not** proof of ownership |
| **Scan** | `id`, `asset_id` (FK), `status` (`pending/running/completed/failed`), `security_score` (0–100, nullable), `started_at`, `completed_at`, `created_at` | Score/status checks. `security_score` is written once when the scan is assessed and is never overwritten |
| **Finding** | `id`, `scan_id` (FK), `check_code`, `title`, `description`, `severity` (`critical/high/medium/low/info`), `evidence`, `recommendation`, `created_at` | Unique `(scan_id, check_code)`; duplicate check codes cannot be persisted |
| **CheckResult** | `id`, `scan_id` (FK), `check_id`, `module` (`tls/https/headers/dns`), `outcome` (`passed/failed/unknown/not_applicable`), `severity`, `check_code`, `detail`, `finding_id` (FK, optional, `SET NULL`), `created_at` | Unique `(scan_id, check_id)`; records every expected check, including passes and technical failures, so coverage can be measured |
| **RiskAssessment** | `id`, `scan_id` (FK, unique), `security_score`, `risk_level`, `grade`, coverage fields, `severity_counts` (JSON), `deductions` (JSON), `highest_priority` (JSON), `recommendations` (JSON), `score_available`, `unavailable_reason`, `score_source`, `risk_config` (JSON), `created_at` | One immutable snapshot per completed scan; previous scores are never recomputed |
| **Alert** | `id`, `business_id` (FK), `asset_id` (FK), `finding_id` (FK, optional, `SET NULL`), `title`, `message`, `severity`, `status` (`unread/read/resolved`), timestamps | Links business/asset and optional finding |

## Relationships

- `Business 1—* Asset` (`assets`, `business`)
- `Asset 1—* Scan` (`scans`, `asset`)
- `Scan 1—* Finding` (`findings`, `scan`)
- `Scan 1—* CheckResult` (`check_results`, `scan`)
- `Scan 1—1 RiskAssessment` (`risk_assessment`, `scan`)
- `Finding 1—* CheckResult` (`check_results`, `finding`; optional link)
- `Business 1—* Alert` and `Asset 1—* Alert`; `Finding 1—* Alert` (nullable link)

Foreign keys use `RESTRICT` on core history-bearing links to avoid destructive cascading deletion of business security history. Finding deletion (if ever allowed) nulls `alerts.finding_id`. Frequently queried foreign keys are indexed.

## Security scanner

The scanner performs **read-only, non-intrusive** security checks against
**registered, authorised, active** assets. It never exploits, brute-forces or
performs intrusive scanning, and it never downloads response bodies (only
status line and headers are read).

### Modules (`app/services/scanner/`)

| Module | Responsibility |
|---|---|
| `target_validator.py` | Domain/DNS validation, SSRF protection, connection pinning, redirect re-validation |
| `pinned_http.py` | DNS-pinned HTTP(S) transport (connects to a validated IP, preserves Host/SNI/cert verification) |
| `tls_inspector.py` | Certificate validity, hostname match, issuer, expiry, expiring-within-30-days |
| `https_inspector.py` | HTTPS availability and HTTP→HTTPS redirect validation |
| `header_inspector.py` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `dns_inspector.py` | SPF, DMARC and CAA records (missing / malformed / present) |
| `scan_manager.py` | Orchestration, status transitions, finding persistence, failure handling |

### Scan workflow

1. `POST /api/assets/{asset_id}/scan` validates that the asset exists, is
   authorised, active and has monitoring enabled, then creates a `Scan` row
   (`pending`) and queues a background task (`202 Accepted`).
2. The background `scan_manager.run_scan` uses its **own** database session and
   is serialised through a small semaphore (never aggressive parallel
   scanning). It transitions the scan `pending → running → completed/failed`
   and always records `started_at` / `completed_at`.
3. The hostname is resolved and validated; every resolved address must be
   public. One public IP is **pinned**; all HTTP(S) and TLS connections use
   the pinned IP while preserving the original hostname for the `Host` header,
   TLS SNI and certificate verification.
4. Each inspector returns structured `Finding`s; duplicates (same
   `check_code`) are removed and the rest are persisted to the `findings`
   table. A failing module is isolated so it cannot abort the whole scan.
5. The scan manager derives and persists one `CheckResult` for every expected
   check group (passed, failed or unknown), marks the scan `completed`, and
   writes an immutable `RiskAssessment` snapshot with the security score,
   coverage and explanations.
6. `GET /api/scans/{scan_id}` returns the scan and its findings;
   `GET /api/assets/{asset_id}/scans` returns scan history.
7. `GET /api/scans/{scan_id}/risk` returns the risk assessment for a scan;
   `GET /api/assets/{asset_id}/risk` returns the latest completed scan's
   assessment; `GET /api/assets/{asset_id}/risk/history` returns historical
   assessments for comparison.

Severity values (`critical/high/medium/low/info`) are assigned by documented
scanner heuristics. The **risk assessment engine** (below) converts those
findings into an explainable security score and only displays a numerical score
when the scan completed with sufficient coverage.

### Scan security protections

- Requires registered, authorised (`authorization_confirmed`) and active
  assets with monitoring enabled; otherwise `403`/`404`.
- DNS validation with fail-closed behaviour: malformed hosts and unresolvable
  names are rejected.
- Rejects private, loopback, link-local, multicast, reserved, unspecified and
  cloud-metadata IP destinations (SSRF protection).
- **Connection pinning:** the socket connects to the validated IP, not a
  re-resolved hostname.
- **Redirects are never followed automatically.** Each `Location` is parsed and
  re-validated with the same SSRF rules before any conclusion is drawn.
- TLS certificate hostname verification is preserved (verification is never
  disabled for the assessment).
- Bounded request/read/connect timeouts and response-size limits; only headers
  are read.
- If safe network validation cannot be guaranteed, the scan fails closed.

## Risk assessment engine

The risk engine converts persisted findings into an explainable assessment. It
is implemented in `app/services/risk_service.py`, with configurable weights in
`app/services/risk_config.py` and check definitions in
`app/services/scanner/check_catalog.py`.

### Scoring methodology

1. Every **completed** scan starts at **100**.
2. Each confirmed finding deducts a fixed penalty based on its severity:

   | Severity | Penalty |
   |---|---|
   | Critical | -25 |
   | High | -15 |
   | Medium | -8 |
   | Low | -3 |
   | Informational | 0 |

3. The score is clamped to the range **0–100**. Once the score reaches 0,
   further findings are still listed but deduct 0 points.
4. **Duplicate protection:** findings are unique per `(scan_id, check_code)` in
   the database, and the engine also de-duplicates by `check_code` (keeping the
   most severe) before scoring. A check can therefore never be penalised twice.
5. **Unknown results are never penalised.** A technical failure (for example a
   DNS timeout or a module that raised an exception) produces an `unknown`
   check result, not a security finding, so it does not reduce the score.
   Technical-failure markers such as `DNS_TIMEOUT` and `HEADERS_UNAVAILABLE`
   are excluded from the risk finding counts and deductions even if their
   stored severity changes; they are represented only as unknown coverage.
6. **No misleading scores:** a numerical score is only produced when the scan
   status is `completed` **and** coverage is at least the configured threshold
   (default **80%**). Failed, pending and running scans return
   `score_available: false` with an explanation.
7. Every deduction is returned with its check code, severity, configured
   penalty, applied penalty, score before/after and a human-readable reason.

The weights and threshold are configurable through environment variables (see
[Environment configuration](#environment-configuration)) and through the
`RiskConfig` dataclass.

### Risk classifications

**Finding severity** (`critical`, `high`, `medium`, `low`, `info`) is assigned
by the scanner heuristics and is preserved in the assessment.

**Overall risk level** is derived from the most severe confirmed finding:

| Highest finding severity | Overall risk level |
|---|---|
| Critical | `critical` |
| High | `high` |
| Medium | `medium` |
| Low | `low` |
| Only informational / none | `minimal` |

**Grade** is derived from the numerical score when one is available:

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

The grade is intentionally independent of the risk level: a scan can have a
`critical` finding (risk level `critical`) while the numerical score is still,
for example, 75 (grade C).

### Coverage calculation

A scan evaluates **14 expected check groups**:

| Module | Check ID | Covers |
|---|---|---|
| TLS | `TLS_HANDSHAKE` | TLS connection and certificate verification |
| TLS | `TLS_CERTIFICATE` | Certificate validity, expiry and hostname match |
| TLS | `TLS_ISSUER` | Certificate issuer |
| HTTPS | `HTTPS_REACHABILITY` | HTTPS availability |
| HTTPS | `HTTP_REDIRECT` | HTTP→HTTPS redirect behaviour |
| Headers | `HSTS` | Strict-Transport-Security |
| Headers | `CSP` | Content-Security-Policy |
| Headers | `X_CONTENT_TYPE_OPTIONS` | MIME sniffing protection |
| Headers | `X_FRAME_OPTIONS` | Clickjacking protection |
| Headers | `REFERRER_POLICY` | Referrer leakage |
| Headers | `PERMISSIONS_POLICY` | Powerful browser features |
| DNS | `SPF` | SPF TXT record |
| DNS | `DMARC` | DMARC TXT record |
| DNS | `CAA` | CAA records |

Each group has exactly one persisted `CheckResult`:

- `passed` – the check ran and no issue was found (including informational
  observations such as a valid certificate or a present CAA record);
- `failed` – the check ran and a finding was produced;
- `unknown` – the check could not be evaluated because of a technical failure
  (module exception, DNS timeout, unavailable headers, or a blocking check such
  as a failed TLS handshake);
- `not_applicable` – reserved for checks that do not apply (excluded from the
  denominator).

Coverage is calculated as:

```text
coverage % = conclusive checks / (total checks - not_applicable) * 100
```

Unknown checks are **not** counted as passed, but they remain in the
denominator, so technical failures lower coverage. A scan with 11 conclusive
checks and 3 unknown checks reports **78.6%** coverage. With the default 80%
threshold, no numerical score is displayed; the response still includes the
findings, risk level and unknown check IDs.

### Historical analysis

- Each completed scan receives one immutable `RiskAssessment` snapshot when it
  is assessed (at scan completion for new scans, or on the first risk request
  for legacy scans). The snapshot is created once and is **never recomputed or
  overwritten**, even if the scoring configuration or findings change later.
- `Scan.security_score` is written when the scan is first assessed and is not
  overwritten for existing scans.
- `GET /api/assets/{asset_id}/risk` returns the latest completed scan plus the
  previous assessment and `score_change` (latest score minus previous score).
- `GET /api/assets/{asset_id}/risk/history` returns all completed-scan
  assessments, newest first, for side-by-side comparison.
- `score_source` is `calculated` when the assessment produced the score, or
  `stored` when a pre-existing historical score was preserved rather than
  recomputed.

### Risk API endpoints

| Method | Path | Description | Success | Errors |
|---|---|---|---|---|
| GET | `/api/scans/{scan_id}/risk` | Risk assessment for one scan | 200 | 404 scan not found |
| GET | `/api/assets/{asset_id}/risk` | Latest completed scan's assessment for an asset | 200 | 404 asset, 404 no completed scan |
| GET | `/api/assets/{asset_id}/risk/history` | Completed-scan assessment history (newest first) | 200 | 404 asset |

A failed, pending or running scan still returns `200` from
`/api/scans/{scan_id}/risk` with `score_available: false`, `security_score:
null` and an `unavailable_reason`.

**Example: scan risk assessment**

```http
GET /api/scans/1/risk
```

Response `200`:
```json
{
  "scan_id": 1,
  "asset_id": 1,
  "scan_status": "completed",
  "scan_started_at": "2026-11-17T07:00:01Z",
  "scan_completed_at": "2026-11-17T07:00:12Z",
  "security_score": 77,
  "score_available": true,
  "unavailable_reason": null,
  "base_score": 100,
  "total_penalty": 23,
  "risk_level": "high",
  "grade": "C",
  "coverage": {
    "percentage": 100.0,
    "evaluated": 14,
    "total": 14,
    "unknown": 0,
    "not_applicable": 0,
    "threshold_percent": 80.0,
    "sufficient": true,
    "unknown_checks": []
  },
  "findings_by_severity": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 3,
    "total": 5
  },
  "findings_total": 5,
  "deductions": [
    {
      "check_code": "HSTS_MISSING",
      "title": "Strict-Transport-Security (HSTS) header is missing",
      "severity": "high",
      "penalty": 15,
      "applied_penalty": 15,
      "score_before": 100,
      "score_after": 85,
      "reason": "High finding 'Strict-Transport-Security (HSTS) header is missing' deducts 15 points.",
      "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    {
      "check_code": "DMARC_MISSING",
      "title": "DMARC record is missing",
      "severity": "medium",
      "penalty": 8,
      "applied_penalty": 8,
      "score_before": 85,
      "score_after": 77,
      "reason": "Medium finding 'DMARC record is missing' deducts 8 points.",
      "recommendation": "Publish a DMARC TXT record at _dmarc.example.com, ..."
    }
  ],
  "highest_priority_issues": [
    {
      "rank": 1,
      "check_code": "HSTS_MISSING",
      "title": "Strict-Transport-Security (HSTS) header is missing",
      "severity": "high",
      "penalty": 15,
      "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    }
  ],
  "recommended_actions": [
    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "Publish a DMARC TXT record at _dmarc.example.com, ..."
  ],
  "score_weights": {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
    "minimum_score": 0,
    "maximum_score": 100
  },
  "score_source": "calculated",
  "generated_at": "2026-11-17T07:00:12Z"
}
```

**Example: asset risk with previous score**

```http
GET /api/assets/1/risk
```

Response `200` includes all scan-risk fields plus:
```json
{
  "asset_domain": "example.com",
  "previous_assessment": {
    "scan_id": 1,
    "completed_at": "2026-11-10T07:00:12Z",
    "security_score": 85,
    "score_available": true,
    "risk_level": "high",
    "grade": "B",
    "coverage_percent": 100.0,
    "findings_total": 4,
    "severity_counts": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 3,
      "total": 4
    },
    "unavailable_reason": null,
    "score_source": "calculated"
  },
  "score_change": -8
}
```

**Example: insufficient coverage**

```json
{
  "scan_id": 2,
  "security_score": null,
  "score_available": false,
  "unavailable_reason": "Scan coverage 78.6% is below the required 80.0%.",
  "coverage": {
    "percentage": 78.6,
    "evaluated": 11,
    "total": 14,
    "unknown": 3,
    "not_applicable": 0,
    "threshold_percent": 80.0,
    "sufficient": false,
    "unknown_checks": ["SPF", "DMARC", "CAA"]
  }
}
```

### Risk engine limitations

- Coverage measures the scanner's fixed check catalogue, not the security of
  the entire application or infrastructure.
- Check outcomes are derived from each inspector's findings and from module
  errors. An inspector that returns no finding for a group is treated as a
  pass, which matches the current inspectors' behaviour but means a future
  inspector must emit a finding (or an explicit unknown marker) when it cannot
  evaluate a check.
- A scan is a point-in-time observation from one network vantage point.
- Unknown checks reduce coverage and may hide a real issue; they are never
  treated as secure.
- The score is a relative prioritisation aid, not a certification or a
  guarantee of security.
- Penalty weights are global configuration, not per-asset or per-industry.
- Historical snapshots are immutable; re-scanning creates a new scan and a new
  assessment rather than updating an old one.

## Environment configuration

Settings live in `app/core/config.py` (no secrets in source).

| Variable | Default | Purpose |
|---|---|---|
| `FIRMLOCK_APP_NAME` | `FirmLock API` | Service name |
| `FIRMLOCK_API_VERSION` | `0.1.0` | API version |
| `FIRMLOCK_ENV` | `development` | Environment label |
| `FIRMLOCK_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Allowed CORS origins (comma-separated) |
| `FIRMLOCK_DATABASE_URL` | `sqlite:///<backend>/data/firmlock.db` | Database URL (configurable; no credentials) |
| `FIRMLOCK_DATA_DIR` | `<backend>/data` | Data directory (auto-created) |
| `FIRMLOCK_SCORE_PENALTY_CRITICAL` | `25` | Points deducted per critical finding |
| `FIRMLOCK_SCORE_PENALTY_HIGH` | `15` | Points deducted per high finding |
| `FIRMLOCK_SCORE_PENALTY_MEDIUM` | `8` | Points deducted per medium finding |
| `FIRMLOCK_SCORE_PENALTY_LOW` | `3` | Points deducted per low finding |
| `FIRMLOCK_SCORE_PENALTY_INFO` | `0` | Points deducted per informational finding |
| `FIRMLOCK_RISK_MIN_COVERAGE_PERCENT` | `80` | Minimum conclusive coverage before a numerical score is shown |

## Installation

### Development (recommended for running tests)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

### Production/runtime only

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If activation is blocked: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

Dependencies (`requirements.txt`): `fastapi`, `uvicorn[standard]`, `pydantic`, `sqlalchemy`, `dnspython` (DNS/SPF/DMARC/CAA lookups). No new dependencies were added for the risk assessment engine; it uses the existing stack.

Testing dependency (`requirements-dev.txt`): `httpx` (required by FastAPI/Starlette `TestClient`), plus all production requirements.

## Database initialization

- The `backend/data/` directory is created automatically from config/startup.
- Tables are created automatically on application startup (`lifespan` → `init_db()`).
- Default DB file: `backend/data/firmlock.db` (gitignored). Override with `FIRMLOCK_DATABASE_URL`.

## Running the backend

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- Root: <http://127.0.0.1:8000/>
- Health: <http://127.0.0.1:8000/api/health>
- Docs: <http://127.0.0.1:8000/docs>

## API endpoints

| Method | Path | Description | Success | Errors |
|---|---|---|---|---|
| GET | `/` | Welcome message | 200 | — |
| GET | `/api/health` | Health/service/version/environment | 200 | — |
| POST | `/api/businesses` | Create business | 201 | 422 validation |
| GET | `/api/businesses` | List businesses | 200 | — |
| GET | `/api/businesses/{business_id}` | Get business | 200 | 404 not found |
| POST | `/api/businesses/{business_id}/assets` | Register authorised website | 201 | 404 business, 409 duplicate domain, 422 validation |
| GET | `/api/businesses/{business_id}/assets` | List assets for business | 200 | 404 business |
| GET | `/api/assets/{asset_id}` | Get asset | 200 | 404 not found |
| PATCH | `/api/assets/{asset_id}` | Update monitoring status (`status`, `monitoring_enabled`) | 200 | 404, 422 |
| POST | `/api/assets/{asset_id}/scan` | Queue a read-only security scan for an authorised, active asset | 202 | 404 asset, 403 unauthorised/paused/monitoring-off |
| GET | `/api/scans/{scan_id}` | Get a scan and its findings | 200 | 404 not found |
| GET | `/api/assets/{asset_id}/scans` | List scan history for an asset | 200 | 404 asset |
| GET | `/api/scans/{scan_id}/risk` | Risk assessment for a scan | 200 | 404 not found |
| GET | `/api/assets/{asset_id}/risk` | Latest completed scan's risk assessment for an asset | 200 | 404 asset, 404 no completed scan |
| GET | `/api/assets/{asset_id}/risk/history` | Completed-scan risk assessment history (newest first) | 200 | 404 asset |

`PATCH /api/assets/{asset_id}` only updates monitoring fields; it does **not** allow changing business ownership or authorization records.

### Example requests/responses

**Create business**
```http
POST /api/businesses
Content-Type: application/json

{"name": "Acme Co", "industry": "Retail"}
```
Response `201`:
```json
{
  "id": 1,
  "name": "Acme Co",
  "industry": "Retail",
  "created_at": "2026-11-17T07:00:00Z",
  "updated_at": "2026-11-17T07:00:00Z"
}
```

**Register asset (domain normalised)**
```http
POST /api/businesses/1/assets
Content-Type: application/json

{"domain": "  HTTPS://Example.COM/  ", "authorization_confirmed": true}
```
Response `201`:
```json
{
  "id": 1,
  "business_id": 1,
  "domain": "example.com",
  "authorization_confirmed": true,
  "authorization_confirmed_at": "2026-11-17T07:00:01Z",
  "monitoring_enabled": true,
  "status": "active",
  "last_scanned_at": null,
  "created_at": "2026-11-17T07:00:01Z",
  "updated_at": "2026-11-17T07:00:01Z"
}
```

**Update monitoring**
```http
PATCH /api/assets/1
Content-Type: application/json

{"status": "paused"}
```
Response `200` includes `"status":"paused"` and `"monitoring_enabled": false`.

**Start a security scan**
```http
POST /api/assets/1/scan
```
Response `202`:
```json
{"scan_id": 1, "asset_id": 1, "status": "pending"}
```
Poll `GET /api/scans/1` until `status` becomes `completed` (or `failed`); the
response then includes a `findings` array. `GET /api/assets/1/scans` returns the
full history.

**Read the risk assessment**
```http
GET /api/scans/1/risk
GET /api/assets/1/risk
GET /api/assets/1/risk/history
```

`GET /api/assets/1/risk` returns the latest completed scan, the previous
assessment and the score change. If the latest scan has insufficient coverage,
`security_score` is `null` and `unavailable_reason` explains why; findings and
coverage are still returned. If the asset has no completed scan, the endpoint
returns `404`.

## Testing

```powershell
cd backend
python -m unittest discover -s tests -v
```

- `tests/test_api.py`: foundation smoke tests (8) — starts uvicorn on `127.0.0.1:8765`.
- `tests/test_database.py`: DB connection/tables/FK enforcement and model relationships (isolated temp SQLite).
- `tests/test_business_asset_api.py`: business/asset API and validation (isolated temp SQLite via `TestClient`; requires `httpx` for Starlette/FastAPI `TestClient`).
- `tests/test_scanner_validators.py`: hostname validation, SSRF/IP safety, DNS resolution + pinning, redirect validation, pinned HTTP transport (37).
- `tests/test_scanner_inspectors.py`: TLS, HTTPS, header and DNS inspectors with mocked network (28).
- `tests/test_scan_manager.py`: orchestration, status transitions, failure handling and DB persistence with an isolated temp SQLite DB (10).
- `tests/test_scan_api.py`: scan endpoints, authorization guards, lifecycle and history via `TestClient` with the network mocked (10).
- `tests/test_risk_engine.py`: severity penalties, multiple/duplicate findings, minimum score, informational findings, unknown results, failed/incomplete scans, coverage, historical preservation, configurable weights, classification, priorities and scan-manager integration (29).
- `tests/test_risk_api.py`: scan risk, asset risk, history, previous-score comparison, 404 handling and historical preservation via `TestClient` (12).

Tests use isolated temporary SQLite databases and must not modify local development data.
Scanner tests never make real network requests: the resolver, TLS probe, HTTP transport and DNS query functions are injected or patched.
Risk tests persist findings and check results directly and never call the network.

## Current security limitations

- **No authentication/authorization:** endpoints are open; no login, sessions, or tokens.
- **Not multi-tenant safe:** no server-side tenant isolation/authorization; APIs must not be presented as production-ready multi-tenant APIs.
- **Authorization is attestation only:** `authorization_confirmed` is a user claim, not independent proof of domain ownership.
- **No rate limiting/abuse protection, no CSRF controls, no audit logging.**
- **SQLite for local dev:** not suited for concurrent multi-user production workloads.
- **No migrations:** `create_all` only; schema changes require migration tooling before production.
- **CORS:** explicit local origins only; review before deployment.
- **Scanner scope:** checks are a fixed, non-exhaustive set (TLS/SSL, HTTPS behaviour, six security headers, SPF/DMARC/CAA). No port scanning, content inspection, vulnerability exploitation, or intrusive testing.
- **Risk score is relative:** the score and coverage reflect the fixed check catalogue and a single point-in-time observation. They are prioritisation aids, not a certification or guarantee of security. Unknown checks reduce coverage and may hide real issues; they are never treated as secure.
- **Global scoring weights:** penalty weights and the coverage threshold are process-wide configuration, not per-asset or per-industry. Historical assessment snapshots are immutable, so changing the configuration affects only new scans.
- **Scans are manual and asynchronous:** no scheduled/periodic scans and no background worker/queue; scans run as FastAPI background tasks inside the API process. If the process restarts mid-scan, the scan is left in its last persisted state (no automatic resume/retry).
- **Single-process concurrency bound:** at most `max_concurrent_scans` (2) scans run concurrently per process, guarded by an in-process semaphore (not suitable for multi-worker deployments without external coordination).
- **Best-effort network assumptions:** a scan reflects a single point-in-time observation from one network vantage point; transient DNS/TLS failures are reported as unknown, not as confirmed vulnerabilities. Redirects are validated but not followed, so multi-hop redirect chains are only partially assessed.
- **Authorization is attestation only (scanner-relevant):** a scan only verifies the stored `authorization_confirmed` flag; it does not independently prove domain ownership, so the platform relies on the asset registration step for authorization.

## Out of scope (future stages)

Authentication/login, password storage, alert generation logic, PDF reporting, payments, automated/scheduled scanning, and multi-tenant isolation are intentionally not implemented.

## Running the scanner

1. Register a business and an authorised asset (see the asset endpoints above).
2. Start a scan:

   ```powershell
   curl -X POST http://127.0.0.1:8000/api/assets/1/scan
   ```

3. Poll the scan until it completes and read the findings:

   ```powershell
   curl http://127.0.0.1:8000/api/scans/1
   curl http://127.0.0.1:8000/api/assets/1/scans
   ```

4. Read the risk assessment and score:

   ```powershell
   curl http://127.0.0.1:8000/api/scans/1/risk
   curl http://127.0.0.1:8000/api/assets/1/risk
   curl http://127.0.0.1:8000/api/assets/1/risk/history
   ```

The scan performs a bounded number of outbound requests (HTTPS/HTTP `GET /`,
TLS handshake, and a few DNS TXT/CAA lookups). It never downloads response
bodies and never follows redirects automatically.
