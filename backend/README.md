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
│   │   ├── deps.py                  # auth dependencies (get_current_user)
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── auth.py              # register, login, /me
│   │       ├── businesses.py
│   │       ├── assets.py
│   │       ├── scans.py
│   │       ├── risk.py
│   │       └── alerts.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── auth.py                  # JWT create/decode
│   │   └── security.py              # Argon2 hash/verify/validate
│   ├── database/
│   │   ├── __init__.py
│   │   └── connection.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── models.py                # User, BusinessMembership added
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py                  # UserCreate, UserLogin, Token, UserResponse
│   │   ├── business.py
│   │   ├── asset.py
│   │   ├── scan.py
│   │   ├── risk.py
│   │   ├── alert.py
│   │   ├── report.py
│   │   └── dashboard.py
│   └── services/
│       ├── __init__.py
│       ├── auth_service.py          # registration, login, user lookup
│       ├── membership_service.py    # membership CRUD, role checks, permissions
│       ├── business_service.py
│       ├── asset_service.py
│       ├── risk_config.py
│       ├── risk_service.py
│       ├── alert_service.py
│       ├── report_service.py
│       ├── dashboard_service.py
│       └── scanner/
│           ├── __init__.py
│           ├── config.py
│           ├── findings.py
│           ├── check_catalog.py
│           ├── target_validator.py
│           ├── pinned_http.py
│           ├── tls_inspector.py
│           ├── https_inspector.py
│           ├── header_inspector.py
│           ├── dns_inspector.py
│           └── scan_manager.py
├── data/
├── migrations/
│   ├── env.py
│   ├── script.py.mako
│   ├── alembic.ini
│   └── versions/
│       └── 02e294bfb1aa_initial_migration_all_models.py
├── tests/
│   ├── conftest.py                  # pytest fixtures (test_db, db_session, client)
│   ├── test_auth.py                 # 25 tests: register, login, tokens, /me
│   ├── test_authz.py                # 18 tests: RBAC matrix, cross-tenant isolation
│   ├── test_auth_helpers.py         # 9 tests: security/membership service units
│   ├── test_api.py
│   ├── test_database.py
│   ├── test_business_asset_api.py
│   ├── test_scanner_validators.py
│   ├── test_scanner_inspectors.py
│   ├── test_scan_manager.py
│   ├── test_scan_api.py
│   ├── test_risk_engine.py
│   ├── test_risk_api.py
│   ├── test_alerts_api.py
│   ├── test_reports_api.py
│   └── test_dashboard_api.py
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Database architecture

- **Engine/ORM:** SQLAlchemy 2.x (`DeclarativeBase`, typed `mapped_column`/`Mapped`).
- **Database:** SQLite by default, URL configurable via `FIRMLOCK_DATABASE_URL`.
- **Location:** default file `backend/data/firmlock.db`; `data/` is created automatically and gitignored.
- **Sessions:** `SessionLocal` factory and FastAPI `get_db` dependency (per-request session, closed in `finally`).
- **SQLite specifics:** `check_same_thread=False` and `PRAGMA foreign_keys=ON` enforced on every connection.
- **Migrations:** **Alembic** is used for schema management. The `migrations/` directory contains the migration environment, script template, and versioned migration scripts.
- **Initialization:** The application **does not** automatically create tables on startup. Instead, it checks the migration version and logs a warning if the schema is outdated. Fresh databases are initialized with `alembic upgrade head`. Existing databases created with `create_all()` can be adopted using `alembic stamp head`.
- **Version tracking:** The `alembic_version` table tracks the current migration revision.

## Database models

| Model | Key fields | Constraints/notes |
|---|---|---|
| **User** | `id`, `email` (unique), `full_name`, `hashed_password`, `is_active`, `created_at` | Email unique index; password min 12 chars (Argon2id) |
| **BusinessMembership** | `id`, `business_id` (FK), `user_id` (FK), `role` (`owner`/`admin`/`analyst`/`viewer`), `joined_at` | Unique `(business_id, user_id)`; role check constraint |
| **Business** | `id`, `name` (required), `industry` (optional), `created_at`, `updated_at` (UTC) | Root tenant-like entity for MVP |
| **Asset** | `id`, `business_id` (FK), `domain`, `authorization_confirmed`, `authorization_confirmed_at`, `monitoring_enabled` (default true), `status` (`active`/`paused`), `last_scanned_at`, timestamps | Unique `(business_id, domain)`; status check; authorization is a user attestation, **not** proof of ownership |
| **Scan** | `id`, `asset_id` (FK), `status` (`pending/running/completed/failed`), `security_score` (0–100, nullable), `started_at`, `completed_at`, `created_at` | Score/status checks. `security_score` is written once when the scan is assessed and is never overwritten |
| **Finding** | `id`, `scan_id` (FK), `check_code`, `title`, `description`, `severity` (`critical/high/medium/low/info`), `evidence`, `recommendation`, `created_at` | Unique `(scan_id, check_code)`; duplicate check codes cannot be persisted |
| **CheckResult** | `id`, `scan_id` (FK), `check_id`, `module` (`tls/https/headers/dns`), `outcome` (`passed/failed/unknown/not_applicable`), `severity`, `check_code`, `detail`, `finding_id` (FK, optional, `SET NULL`), `created_at` | Unique `(scan_id, check_id)`; records every expected check, including passes and technical failures, so coverage can be measured |
| **RiskAssessment** | `id`, `scan_id` (FK, unique), `security_score`, `risk_level`, `grade`, coverage fields, `severity_counts` (JSON), `deductions` (JSON), `highest_priority` (JSON), `recommendations` (JSON), `score_available`, `unavailable_reason`, `score_source`, `risk_config` (JSON), `created_at` | One immutable snapshot per completed scan; previous scores are never recomputed |
| **Alert** | `id`, `business_id` (FK), `asset_id` (FK), `finding_id` (FK, optional, `SET NULL`), `title`, `message`, `severity`, `status` (`unread/read/resolved`), timestamps | Links business/asset and optional finding |

## Relationships

- `User 1—* BusinessMembership` (`business_memberships`, `user`)
- `Business 1—* BusinessMembership` (`memberships`, `business`; cascade delete)
- `Business *—* User` via `BusinessMembership` (`members`, `business_memberships`; association proxy)
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
| `FIRMLOCK_JWT_SECRET` | **required** | HS256 JWT signing key (min 32 chars recommended) |
| `FIRMLOCK_JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `FIRMLOCK_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime |
| `FIRMLOCK_PASSWORD_MIN_LENGTH` | `12` | Minimum password length |
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

Dependencies (`requirements.txt`): `fastapi`, `uvicorn[standard]`, `pydantic`, `sqlalchemy`, `dnspython` (DNS/SPF/DMARC/CAA lookups), `argon2-cffi`, `python-jose[cryptography]`, `passlib[argon2]`, `email-validator`.

Testing dependency (`requirements-dev.txt`): `httpx` (required by FastAPI/Starlette `TestClient`), plus all production requirements.

## Database migrations (Alembic)

Schema changes are managed through **Alembic** migrations. The migration files are located in `migrations/versions/`.

### Migration commands

```powershell
# Apply all pending migrations (fresh database or upgrade)
alembic upgrade head

# Roll back the last migration
alembic downgrade -1

# Create a new migration (auto-generates from model changes)
alembic revision --autogenerate -m "Description of changes"

# Show current migration version
alembic current

# Show migration history
alembic history

# Show migration history with details
alembic history --verbose
```

### Fresh database setup

For a new database (no existing data):

```powershell
# 1. Ensure FIRMLOCK_DATABASE_URL points to the desired database file
$env:FIRMLOCK_DATABASE_URL = "sqlite:///backend/data/firmlock.db"

# 2. Run migrations to create all tables with correct schema version
alembic upgrade head
```

The `alembic upgrade head` command creates all tables, indexes, constraints, and the `alembic_version` table tracking the current revision.

### Existing database adoption

If you have an existing database created with the old `create_all()` approach (no `alembic_version` table):

**⚠️ BACKUP FIRST** — Always back up your database before running migration commands.

```powershell
# 1. Back up the database file
cp backend/data/firmlock.db backend/data/firmlock.db.backup.$(Get-Date -Format "yyyyMMdd_HHmmss")

# 2. Verify schema compatibility
#    The database must match the initial migration schema exactly.
#    If you have made manual schema changes, resolve them before stamping.

# 3. Stamp the database with the baseline revision (no schema changes applied)
alembic stamp head

# 4. Verify the stamp succeeded
alembic current
# Should show: 02e294bfb1aa (head)
```

**Important:** `alembic stamp head` does **not** modify the schema — it only records the current revision in `alembic_version`. The database schema must already match the migration. If the schema diverges, you must manually reconcile it before stamping.

### Backup instructions

```powershell
# SQLite file backup (database must not be in use)
cp backend/data/firmlock.db backend/data/firmlock.db.backup.$(Get-Date -Format "yyyyMMdd_HHmmss")

# Or use SQLite's backup API for live databases
sqlite3 backend/data/firmlock.db ".backup 'backend/data/firmlock.db.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')'"
```

### Rollback instructions

To roll back the last migration (use with caution — may lose data):

```powershell
# 1. BACKUP the database first
cp backend/data/firmlock.db backend/data/firmlock.db.pre-rollback.$(Get-Date -Format "yyyyMMdd_HHmmss")

# 2. Downgrade one revision
alembic downgrade -1

# 3. Verify
alembic current
```

**Warning:** Downgrades are destructive for `DROP TABLE` / `DROP COLUMN` operations. The initial migration creates all tables, so downgrading from the initial revision will drop all tables. Only downgrade if you have a backup and understand the data loss implications.

### Development setup

For local development with a fresh database:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

# Initialize database with migrations
alembic upgrade head

# Run the application
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

For running tests (uses temporary databases with Alembic migrations):

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

## Database initialization (legacy)

The `init_db()` function in `app/database/connection.py` remains available but is **deprecated** for production use. It uses `Base.metadata.create_all()` and does not create the `alembic_version` table. It is retained only for:

- Automated test environments (see `tests/conftest.py` — now uses Alembic)
- Fresh database initialization when migrations are explicitly not used

**Do not use `init_db()` on a database that will be managed by Alembic.** Doing so will create tables without version tracking, causing future migrations to fail or behave unexpectedly.

## Running the backend

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- Root: <http://127.0.0.1:8000/>
- Health: <http://127.0.0.1:8000/api/health> (includes database migration status)
- Docs: <http://127.0.0.1:8000/docs>

## API endpoints

| Method | Path | Description | Success | Errors |
|---|---|---|---|---|
| GET | `/` | Welcome message | 200 | — |
| GET | `/api/health` | Health/service/version/environment + database migration status | 200 | — |
| POST | `/api/auth/register` | Register new user | 201 | 422 validation, 409 email exists |
| POST | `/api/auth/login` | Obtain JWT (form-encoded) | 200 | 401 invalid credentials |
| GET | `/api/auth/me` | Current user profile | 200 | 401 missing/invalid token |
| POST | `/api/businesses` | Create business (becomes owner) | 201 | 401, 422 validation |
| GET | `/api/businesses` | List user's businesses | 200 | 401 |
| GET | `/api/businesses/{business_id}` | Get business (member only) | 200 | 401, 403 not member, 404 |
| GET | `/api/businesses/{business_id}/dashboard` | Business dashboard (member only) | 200 | 401, 403, 404 |
| POST | `/api/businesses/{business_id}/assets` | Register authorised website (analyst+) | 201 | 401, 403, 404 business, 409 duplicate, 422 |
| GET | `/api/businesses/{business_id}/assets` | List assets (member only) | 200 | 401, 403, 404 |
| GET | `/api/assets/{asset_id}` | Get asset (member of business) | 200 | 401, 403, 404 |
| PATCH | `/api/assets/{asset_id}` | Update monitoring (analyst+) | 200 | 401, 403, 404, 422 |
| GET | `/api/assets/{asset_id}/reports` | Historical scan reports (member only) | 200 | 401, 403, 404 |
| POST | `/api/assets/{asset_id}/scan` | Queue scan (analyst+) | 202 | 401, 403, 404, 403 unauth/paused/off |
| GET | `/api/scans/{scan_id}` | Get scan with findings (member) | 200 | 401, 403, 404 |
| GET | `/api/scans/{scan_id}/report` | Structured scan report (member) | 200 | 401, 403, 404 |
| GET | `/api/scans/{scan_id}/report.csv` | Download CSV report (member) | 200 | 401, 403, 404 |
| GET | `/api/assets/{asset_id}/scans` | Scan history (member) | 200 | 401, 403, 404 |
| GET | `/api/scans/{scan_id}/risk` | Scan risk assessment (member) | 200 | 401, 403, 404 |
| GET | `/api/assets/{asset_id}/risk` | Latest asset risk (member) | 200 | 401, 403, 404 |
| GET | `/api/assets/{asset_id}/risk/history` | Asset risk history (member) | 200 | 401, 403, 404 |
| GET | `/api/businesses/{business_id}/alerts` | List alerts (member, filters/page) | 200 | 401, 403, 404, 422 |
| GET | `/api/alerts/{alert_id}` | Alert details (member) | 200 | 401, 403, 404 |
| PATCH | `/api/alerts/{alert_id}` | Mark read/resolve (analyst+) | 200 | 401, 403, 404, 422 |
| GET | `/api/businesses/{business_id}/alerts/summary` | Alert counts (member) | 200 | 401, 403, 404 |

`PATCH /api/assets/{asset_id}` only updates monitoring fields; it does **not** allow changing business ownership or authorization records. Alert, report and dashboard endpoints are MVP endpoints (no authentication/tenant isolation).

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

## Alerts and reporting (Stage 05)

### Alert generation logic

In-app alerts are generated automatically from stored, actionable scan findings after a scan is finalised and its risk assessment is persisted (`app/services/alert_service.py`, invoked by the scan manager).

Rules:

- **Alertable severities:** `critical`, `high`, `medium`, `low`. `info` findings never create alerts.
- **Excluded technical markers:** findings whose `check_code` is a technical scanning failure marker (for example `DNS_TIMEOUT`, `HEADERS_UNAVAILABLE`, as defined in `app/services/scanner/check_catalog.py`) never create alerts.
- **No duplicate unresolved alerts:** if an unresolved alert (`unread` or `read`) already exists for the same asset and `check_code`, no new alert is created for a later scan.
- **Reappearing resolved issues:** if a previously resolved issue is detected again in a later completed scan, a **new** alert is created. Previously resolved alerts are preserved.
- **History preserved:** alerts are never deleted by generation or lifecycle updates.
- **Alert contents:** each alert stores `title`, `message`, `severity`, `status`, `business_id`, `asset_id`, `finding_id`, and timestamps. The message is built from the finding description, evidence (when present) and recommendation, scoped to the asset domain.
- **Isolation:** alert generation runs in its own guarded step after scan/risk completion; generation failures are logged and do not invalidate the completed scan or its risk assessment.

### Alert lifecycle

- `unread` (default): newly generated, not yet reviewed.
- `read`: reviewed but not resolved (`read_at` set).
- `resolved`: issue addressed/acknowledged (`resolved_at` set; also marked read). Resolved alerts cannot be reopened; a reappearing issue creates a new alert instead.

### Reporting functionality

Reports are built from **actual stored** scan records, findings and risk assessments (`app/services/report_service.py`). No findings or scores are invented.

- **Scan report** (`GET /api/scans/{scan_id}/report`): scan metadata, business/website details, security score/risk classification (when available), scan coverage, findings grouped by severity counts, evidence, recommendations, and timestamps.
- **Missing/unavailable scores:** failed, pending, running scans, or completed scans with insufficient coverage return `security_score: null`, `score_available: false`, and an explicit `unavailable_reason`. Findings and available metadata are still returned.
- **Historical reports** (`GET /api/assets/{asset_id}/reports`): per-scan summaries for an asset including status, security score (if available), risk classification/grade, coverage, scan dates and finding counts. Historical risk assessments are immutable snapshots and are not modified.
- **Missing entities:** unknown scan/asset IDs return `404`.

### CSV export

`GET /api/scans/{scan_id}/report.csv` returns a downloadable CSV (`text/csv; charset=utf-8`, `Content-Disposition: attachment`) with scan/business/asset context, score/availability fields and one row per finding (or one context row when there are no findings). Uses stored results only.

### Dashboard API

`GET /api/businesses/{business_id}/dashboard` aggregates actual database records (`app/services/dashboard_service.py`):

- Total monitored websites, active and paused website counts.
- Latest scan information (most recent scan for the business).
- Latest security scores/overview (average over latest completed per-asset assessments with available scores, scored-asset count, overall risk level).
- Critical security findings from latest completed scans per asset.
- Alert counts: total unread, total, critical/high/medium/low, resolved.
- Recent security activity (recent scans and alerts).
- Overall business security overview.

Empty businesses return zeroed counts, `null` latest-scan/score fields, and empty lists (not invented data).

### Stage 05 API endpoints

| Method | Path | Description | Success | Errors |
|---|---|---|---|---|
| GET | `/api/businesses/{business_id}/alerts` | List business alerts (filters: `severity`, `status`; pagination: `page`, `page_size`) | 200 | 404 business, 422 invalid filter |
| GET | `/api/alerts/{alert_id}` | Retrieve alert details | 200 | 404 not found |
| PATCH | `/api/alerts/{alert_id}` | Mark alert read (`{"read": true}`) or resolve (`{"resolved": true}`) | 200 | 404, 422 invalid update |
| GET | `/api/businesses/{business_id}/alerts/summary` | Alert summary counts | 200 | 404 business |
| GET | `/api/scans/{scan_id}/report` | Structured scan security report | 200 | 404 scan/asset |
| GET | `/api/scans/{scan_id}/report.csv` | Download scan findings as CSV | 200 | 404 scan/asset |
| GET | `/api/assets/{asset_id}/reports` | Historical scan report summaries for an asset | 200 | 404 asset |
| GET | `/api/businesses/{business_id}/dashboard` | Business dashboard summary | 200 | 404 business |

### Stage 05 example requests/responses

**List alerts (filtered, paginated)**
```http
GET /api/businesses/1/alerts?severity=high&status=unread&page=1&page_size=20
```
Response `200`:
```json
{
  "items": [
    {
      "id": 10,
      "business_id": 1,
      "asset_id": 1,
      "finding_id": 42,
      "title": "Strict-Transport-Security (HSTS) header is missing",
      "message": "Security issue detected on example.com. ...",
      "severity": "high",
      "status": "unread",
      "created_at": "2026-11-17T07:00:12Z",
      "read_at": null,
      "resolved_at": null
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "pages": 1
}
```

**Get/patch alert**
```http
GET /api/alerts/10
PATCH /api/alerts/10
Content-Type: application/json

{"resolved": true}
```
Response `200` includes `"status": "resolved"` with `read_at`/`resolved_at` timestamps.

**Alert summary**
```http
GET /api/businesses/1/alerts/summary
```
Response `200`:
```json
{
  "total": 4,
  "unread": 3,
  "read": 0,
  "resolved": 1,
  "critical": 1,
  "high": 1,
  "medium": 1,
  "low": 1,
  "info": 0
}
```

**Scan report**
```http
GET /api/scans/1/report
```
Response `200` (shape): `scan_id`, `scan_status`, timestamps, `business_id/name`, `asset_id/domain`, `security_score`, `score_available`, `unavailable_reason`, `risk_assessment` (score/risk/grade/coverage/counts/priorities/recommendations when available), `scan_coverage`, `findings_total`, `findings_by_severity`, `findings[]` (id, check_code, title, description, severity, evidence, recommendation), `recommendations[]`.

**CSV export**
```http
GET /api/scans/1/report.csv
```
Response `200` (`text/csv`): header + rows with scan/business/asset/score context and finding fields.

**Asset historical reports**
```http
GET /api/assets/1/reports
```
Response `200`: asset/business identity and `scans[]` summaries with scan status, dates, `security_score`, `score_available`, `risk_level`, `grade`, `coverage_percent`, and finding counts.

**Dashboard**
```http
GET /api/businesses/1/dashboard
```
Response `200`: `total_monitored_websites`, `active_websites`, `paused_websites`, `latest_scan`, `latest_security_scores`, `critical_security_findings`, `alert_counts`, `recent_security_activity`, `security_overview`.

## Testing

```powershell
cd backend
python -m pytest tests/ -v
```

Run with the project virtual environment when dependencies are installed there:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

- `tests/test_api.py`: foundation smoke tests (8) — starts uvicorn on `127.0.0.1:8765`.
- `tests/test_database.py`: DB connection/tables/FK enforcement and model relationships (isolated temp SQLite) (18).
- `tests/test_business_asset_api.py`: business/asset API and validation (isolated temp SQLite via `TestClient`; requires `httpx`) (16).
- `tests/test_scanner_validators.py`: hostname validation, SSRF/IP safety, DNS resolution + pinning, redirect validation, pinned HTTP transport (37).
- `tests/test_scanner_inspectors.py`: TLS, HTTPS, header and DNS inspectors with mocked network (28).
- `tests/test_scan_manager.py`: orchestration, status transitions, failure handling and DB persistence with an isolated temp SQLite DB (10).
- `tests/test_scan_api.py`: scan endpoints, authorization guards, lifecycle and history via `TestClient` with the network mocked (10).
- `tests/test_risk_engine.py`: severity penalties, multiple/duplicate findings, minimum score, informational findings, unknown results, failed/incomplete scans, coverage, historical preservation, configurable weights, classification, priorities and scan-manager integration (29).
- `tests/test_risk_api.py`: scan risk, asset risk, history, previous-score comparison, 404 handling and historical preservation via `TestClient` (12).
- `tests/test_alerts_api.py`: automatic alert creation, severity classification, info exclusion, duplicate prevention, reappearing resolved issues, read/resolve, filtering, pagination, summary, and 404/422 handling (11).
- `tests/test_reports_api.py`: scan report generation, findings/recommendations, missing-score handling, CSV export, historical asset reports, and missing-asset/scan handling (9).
- `tests/test_dashboard_api.py`: dashboard counts, latest scan/overview, alert counts/activity, and empty/missing business handling (3).
- `tests/test_auth.py`: registration, login, password validation, token flow, current user (25).
- `tests/test_authz.py`: RBAC matrix, cross-tenant isolation, membership guards (18).
- `tests/test_auth_helpers.py`: direct security/membership service unit tests (9).

**Total: 234 tests**

Tests use isolated temporary SQLite databases and must not modify local development data. Fixtures in `tests/conftest.py` provide `test_db`, `db_session`, and `client` for per-test isolation, avoiding SQLAlchemy registry conflicts.
Scanner tests never make real network requests: the resolver, TLS probe, HTTP transport and DNS query functions are injected or patched.
Risk/report/alert/dashboard tests persist findings and check results directly and never call the network.

## Known limitations (Stage 05)

- **No authentication/authorization and not multi-tenant safe:** alert, report and dashboard endpoints are open and scoped only by IDs in the URL; they must not be presented as production-ready multi-tenant APIs.
- **Alerts are in-app records only:** no email/SMS/push notifications, no scheduling, and no external delivery.
- **Alert generation is scan-driven:** alerts are created when scans complete; there is no background remediation polling or automatic closure when a finding disappears (a reappearing resolved issue creates a new alert).
- **Reports are JSON/CSV only:** no PDF reports.
- **Dashboard aggregates stored data only:** it reflects latest completed assessments per asset and stored alerts; it does not trigger scans or recompute historical assessments.
- **Existing scanner/risk limitations remain:** fixed passive check catalogue, single point-in-time observation, global scoring weights, immutable historical snapshots, and best-effort coverage semantics.

## Current security limitations

- **Authentication implemented (Stage 06):** JWT-based auth with Argon2 password hashing, RBAC, and tenant isolation. Tokens expire in 15 minutes.
- **Not production-ready multi-tenant:** RBAC and isolation are enforced at the application layer; no row-level security, audit logging, or advanced session management.
- **Authorization is attestation only:** `authorization_confirmed` is a user claim, not independent proof of domain ownership.
- **No rate limiting/abuse protection, no CSRF controls, no audit logging.**
- **SQLite for local dev:** not suited for concurrent multi-user production workloads.
- **Migrations implemented (Stage 07A):** Alembic migrations replace `create_all`. Schema changes require generating and applying migrations. Existing databases can be adopted via `alembic stamp head`.
- **CORS:** explicit local origins only; review before deployment.
- **Scanner scope:** checks are a fixed, non-exhaustive set (TLS/SSL, HTTPS behaviour, six security headers, SPF/DMARC/CAA). No port scanning, content inspection, vulnerability exploitation, or intrusive testing.
- **Risk score is relative:** the score and coverage reflect the fixed check catalogue and a single point-in-time observation. They are prioritisation aids, not a certification or guarantee of security. Unknown checks reduce coverage and may hide real issues; they are never treated as secure.
- **Global scoring weights:** penalty weights and the coverage threshold are process-wide configuration, not per-asset or per-industry. Historical assessment snapshots are immutable, so changing the configuration affects only new scans.
- **Scans are manual and asynchronous:** no scheduled/periodic scans and no background worker/queue; scans run as FastAPI background tasks inside the API process. If the process restarts mid-scan, the scan is left in its last persisted state (no automatic resume/retry).
- **Single-process concurrency bound:** at most `max_concurrent_scans` (2) scans run concurrently per process, guarded by an in-process semaphore (not suitable for multi-worker deployments without external coordination).
- **Best-effort network assumptions:** a scan reflects a single point-in-time observation from one network vantage point; transient DNS/TLS failures are reported as unknown, not as confirmed vulnerabilities. Redirects are validated but not followed, so multi-hop redirect chains are only partially assessed.
- **Authorization is attestation only (scanner-relevant):** a scan only verifies the stored `authorization_confirmed` flag; it does not independently prove domain ownership, so the platform relies on the asset registration step for authorization.

## Stage 06: Authentication and Business Access Control

This stage implements user authentication, JWT-based sessions, role-based access control (RBAC), and strict tenant isolation across all business-related APIs.

### Authentication architecture

- **Password hashing:** Argon2id via `passlib[argon2]` with minimum 12-character requirement, enforced at registration.
- **Tokens:** JWT HS256, 15-minute access token expiry, signed with `FIRMLOCK_JWT_SECRET` (required, no default). Tokens carry `sub` (user ID), `email`, and `exp`.
- **Auth endpoints:**
  - `POST /api/auth/register` — create account (`email`, `password`, `full_name`)
  - `POST /api/auth/login` — obtain JWT (`application/x-www-form-urlencoded` with `username`=`email`, `password`)
  - `GET /api/auth/me` — current user profile (requires `Authorization: Bearer <token>`)
- **Dependencies:** `get_current_user` (required) and `get_current_user_optional` (for public endpoints that personalize if authenticated).
- **Public endpoints unchanged:** `GET /` and `GET /api/health` remain unauthenticated.

### Role-based access control (RBAC)

Business membership links users to businesses with one of four roles:

| Role | Permissions |
|---|---|
| `owner` | Full control: manage memberships, delete business, all member/analyst/viewer actions |
| `admin` | Manage members (except owner), manage assets/scans/alerts, view everything |
| `analyst` | Create/manage assets, start scans, view scans/risk/reports/alerts, update alert status |
| `viewer` | Read-only: view assets, scans, risk, reports, alerts, dashboard |

**Role hierarchy:** `owner` > `admin` > `analyst` > `viewer`. Higher roles inherit all lower-role permissions.

### Tenant isolation

- **Business creation:** authenticated user becomes the `owner` automatically (membership created in same transaction).
- **Business listing (`GET /api/businesses`):** returns only businesses the user is a member of.
- **All business-scoped endpoints** (`/api/businesses/{business_id}...`, `/api/businesses/{business_id}/assets...`, `/api/assets/{asset_id}...`, `/api/scans...`, `/api/alerts...`, `/api/businesses/{business_id}/dashboard`, etc.) validate membership via `membership_service` before any data access.
- **Cross-tenant access returns 403** (not 404) to avoid business enumeration; membership checks use boolean `can_*` helpers to avoid 500 errors from exception-throwing guards.
- **Asset-scoped endpoints** resolve the asset's business and check membership.
- **Scan/alert/risk/dashboard endpoints** resolve the parent business and enforce membership.

### API changes from Stage 05

All previously open business/asset/scan/alert/risk/report/dashboard endpoints now require `Authorization: Bearer <token>` header.

| Method | Path | Auth required | RBAC notes |
|---|---|---|---|
| GET | `/api/businesses` | Yes | Returns user's businesses only |
| GET | `/api/businesses/{id}` | Yes | Member only |
| GET | `/api/businesses/{id}/dashboard` | Yes | Member only |
| POST | `/api/businesses/{id}/assets` | Yes | `analyst`+ |
| GET | `/api/businesses/{id}/assets` | Yes | Member only |
| GET | `/api/assets/{id}` | Yes | Member of asset's business |
| PATCH | `/api/assets/{id}` | Yes | `analyst`+ |
| POST | `/api/assets/{id}/scan` | Yes | `analyst`+ |
| GET | `/api/assets/{id}/scans` | Yes | Member only |
| GET | `/api/scans/{id}` | Yes | Member of scan's business |
| GET | `/api/scans/{id}/report` | Yes | Member only |
| GET | `/api/scans/{id}/report.csv` | Yes | Member only |
| GET | `/api/scans/{id}/risk` | Yes | Member only |
| GET | `/api/assets/{id}/risk` | Yes | Member only |
| GET | `/api/assets/{id}/risk/history` | Yes | Member only |
| GET | `/api/businesses/{id}/alerts` | Yes | Member only |
| GET | `/api/alerts/{id}` | Yes | Member of alert's business |
| PATCH | `/api/alerts/{id}` | Yes | `analyst`+ |
| GET | `/api/businesses/{id}/alerts/summary` | Yes | Member only |
| GET | `/api/assets/{id}/reports` | Yes | Member only |

**Error responses:** `401` (missing/invalid/expired token), `403` (authenticated but insufficient role or not a member), `404` (resource genuinely not found within accessible scope).

### Membership management (internal)

`app/services/membership_service.py` provides:
- `add_member(business_id, user_id, role)` — idempotent upsert, prevents duplicate memberships, self-management guards
- `remove_member(business_id, user_id, actor_id)` — prevents owner self-removal, last-owner protection
- `get_membership(business_id, user_id)` — returns membership or None
- `list_memberships(business_id)` — all memberships with user details
- `list_user_businesses(user_id)` — businesses user belongs to
- `can_manage_members`, `can_manage_assets`, `can_start_scans`, `can_view_scans`, `can_manage_alerts`, `can_view_alerts`, `can_view_reports`, `can_view_dashboard` — boolean permission checks used by routes

### Database models added

| Model | Key fields | Constraints |
|---|---|---|
| **User** | `id`, `email` (unique), `full_name`, `hashed_password`, `is_active`, `created_at` | Email unique index |
| **BusinessMembership** | `id`, `business_id` (FK), `user_id` (FK), `role` (`owner`/`admin`/`analyst`/`viewer`), `joined_at` | Unique `(business_id, user_id)`, FK cascade, role check constraint |

**Relationships:**
- `User.business_memberships` → `BusinessMembership`
- `Business.memberships` → `BusinessMembership` (cascade delete)
- `Business.members` → association proxy to `User` via memberships

### New environment variables

| Variable | Required | Purpose |
|---|---|---|
| `FIRMLOCK_JWT_SECRET` | **Yes** | HS256 signing key (min 32 chars recommended) |
| `FIRMLOCK_JWT_ALGORITHM` | No (default `HS256`) | JWT algorithm |
| `FIRMLOCK_ACCESS_TOKEN_EXPIRE_MINUTES` | No (default `15`) | Token lifetime |
| `FIRMLOCK_PASSWORD_MIN_LENGTH` | No (default `12`) | Minimum password length |

### New dependencies (`requirements.txt`)

- `argon2-cffi` — Argon2id password hashing
- `python-jose[cryptography]` — JWT encode/decode
- `passlib[argon2]` — Passlib Argon2 integration
- `email-validator` — Email syntax validation

### Testing

All 234 tests pass using pytest fixtures in `tests/conftest.py` that provide isolated temporary SQLite databases per test function (`test_db`, `db_session`, `client`), avoiding SQLAlchemy registry conflicts from module reloading.

Key test files:
- `tests/test_auth.py` — registration, login, password validation, token flow, current user (25 tests)
- `tests/test_authz.py` — RBAC matrix, cross-tenant isolation, membership guards (18 tests)
- `tests/test_auth_helpers.py` — direct security/membership service unit tests (9 tests)
- Remaining test files converted to pytest fixtures (business, asset, scan, risk, alert, report, dashboard, database)

### Example flow

```bash
# Register
curl -X POST http://127.0.0.1:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123","full_name":"Test User"}'

# Login (form-encoded)
curl -X POST http://127.0.0.1:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=user@example.com&password=SecurePass123'
# → {"access_token":"eyJ...","token_type":"bearer"}

# Use token
curl -H "Authorization: Bearer eyJ..." http://127.0.0.1:8000/api/businesses

# Create business (becomes owner)
curl -X POST -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Co"}' http://127.0.0.1:8000/api/businesses

# Add team member (owner only)
curl -X POST -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","role":"analyst"}' \
  http://127.0.0.1:8000/api/businesses/1/members
```

## Stage 07A: Database Migrations and Production Configuration

This stage replaces the MVP-only `create_all()` database initialization with **Alembic migrations** for production-ready schema management.

### What was implemented

- **Alembic installation and configuration** (`alembic.ini`, `migrations/env.py`, `migrations/script.py.mako`)
- **Initial migration** (`02e294bfb1aa_initial_migration_all_models.py`) covering all 9 SQLAlchemy models:
  - `Business`, `User`, `BusinessMembership`
  - `Asset`, `Scan`, `Finding`, `CheckResult`
  - `RiskAssessment`, `Alert`
- **Full constraint preservation:** Foreign keys (`RESTRICT`/`CASCADE`/`SET NULL`), unique constraints, check constraints, and indexes
- **UTC timestamp behavior** preserved with `DateTime(timezone=True)` and `utcnow()` default factory
- **Migration version tracking** via `alembic_version` table
- **Upgrade/downgrade support** (downgrade drops all tables for the initial migration)

### Application startup changes

- **No automatic schema changes** on startup — the application only checks migration status
- **Health endpoint** (`/api/health`) now reports database migration status:
  ```json
  {
    "status": "ok",
    "service": "FirmLock API",
    "version": "0.1.0",
    "environment": "development",
    "database_migration": {
      "up_to_date": true,
      "message": "Database schema is up to date (revision: 02e294bfb1aa)."
    }
  }
  ```
- **Clear error reporting** when schema is outdated (logs warning, does not crash)
- **Test database initialization** uses Alembic migrations for schema consistency

### Database transition procedures

See [Database migrations (Alembic)](#database-migrations-alembic) for:
- Fresh database setup: `alembic upgrade head`
- Existing database adoption: backup → verify schema → `alembic stamp head`
- Backup and rollback instructions
- Development setup with migrations

### Testing

All 234 existing tests pass with the new Alembic-based test fixtures:
- Migration from empty database verified
- Migration upgrade/downgrade verified
- Existing database adoption procedure verified
- Schema consistency (foreign keys, unique constraints, indexes, UTC timestamps) verified
- All API, authentication, and business logic tests pass

### Known limitations

- **Downgrade from initial revision drops all tables** — only use with backups
- **Single linear migration history** — no branching/merging support yet
- **SQLite-only** — PostgreSQL/MySQL would require dialect-specific adjustments
- **No automatic migration generation on model changes** — developers must run `alembic revision --autogenerate` manually

## Out of scope (future stages)

Payment systems, email/SMS notifications, scheduled/automated monitoring, PDF reports, machine learning, and frontend modifications are intentionally not implemented.

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

