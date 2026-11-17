# FirmLock Backend

Backend API for **FirmLock**, a cybersecurity monitoring platform for small and
medium-sized businesses.

This stage implements the FastAPI foundation plus a SQLite/SQLAlchemy 2.x data
layer, ORM models, Pydantic schemas, service modules, and REST endpoints for
businesses, assets and on-demand, read-only security scans (TLS/SSL, HTTPS,
security headers, and SPF/DMARC/CAA DNS records). It is a **local MVP** and is
**not** production-ready multi-tenant infrastructure.

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
│   │       └── scans.py
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
│   │   └── scan.py
│   └── services/
│       ├── __init__.py
│       ├── business_service.py
│       ├── asset_service.py
│       └── scanner/
│           ├── __init__.py
│           ├── config.py            # limits, check codes, severity heuristics
│           ├── findings.py          # shared Finding dataclass
│           ├── target_validator.py  # domain/DNS validation + SSRF protection
│           ├── pinned_http.py       # DNS-pinned HTTP(S) transport
│           ├── tls_inspector.py     # SSL/TLS certificate inspection
│           ├── https_inspector.py   # HTTPS + HTTP->HTTPS redirect checks
│           ├── header_inspector.py  # HTTP security header checks
│           ├── dns_inspector.py     # SPF / DMARC / CAA checks
│           └── scan_manager.py      # orchestration + persistence
├── data/                    # local SQLite DB (gitignored, auto-created)
├── tests/
│   ├── test_api.py
│   ├── test_database.py
│   ├── test_business_asset_api.py
│   ├── test_scanner_validators.py
│   ├── test_scanner_inspectors.py
│   ├── test_scan_manager.py
│   └── test_scan_api.py
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
| **Scan** | `id`, `asset_id` (FK), `status` (`pending/running/completed/failed`), `security_score` (0–100, nullable), `started_at`, `completed_at`, `created_at` | Score/status checks |
| **Finding** | `id`, `scan_id` (FK), `check_code`, `title`, `description`, `severity` (`critical/high/medium/low/info`), `evidence`, `recommendation`, `created_at` | Unique `(scan_id, check_code)` |
| **Alert** | `id`, `business_id` (FK), `asset_id` (FK), `finding_id` (FK, optional, `SET NULL`), `title`, `message`, `severity`, `status` (`unread/read/resolved`), timestamps | Links business/asset and optional finding |

## Relationships

- `Business 1—* Asset` (`assets`, `business`)
- `Asset 1—* Scan` (`scans`, `asset`)
- `Scan 1—* Finding` (`findings`, `scan`)
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
5. `GET /api/scans/{scan_id}` returns the scan and its findings;
   `GET /api/assets/{asset_id}/scans` returns scan history.

Severity values (`critical/high/medium/low/info`) are a **preliminary,
documented heuristic only** — this stage does **not** compute a security score
(`security_score` remains `NULL`).

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

Dependencies (`requirements.txt`): `fastapi`, `uvicorn[standard]`, `pydantic`, `sqlalchemy`, `dnspython` (DNS/SPF/DMARC/CAA lookups).  
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

Tests use isolated temporary SQLite databases and must not modify local development data.
Scanner tests never make real network requests: the resolver, TLS probe, HTTP transport and DNS query functions are injected or patched.

## Current security limitations

- **No authentication/authorization:** endpoints are open; no login, sessions, or tokens.
- **Not multi-tenant safe:** no server-side tenant isolation/authorization; APIs must not be presented as production-ready multi-tenant APIs.
- **Authorization is attestation only:** `authorization_confirmed` is a user claim, not independent proof of domain ownership.
- **No rate limiting/abuse protection, no CSRF controls, no audit logging.**
- **SQLite for local dev:** not suited for concurrent multi-user production workloads.
- **No migrations:** `create_all` only; schema changes require migration tooling before production.
- **CORS:** explicit local origins only; review before deployment.
- **Scanner scope:** checks are a fixed, non-exhaustive set (TLS/SSL, HTTPS behaviour, six security headers, SPF/DMARC/CAA). No port scanning, content inspection, vulnerability exploitation, or intrusive testing.
- **No security scoring:** findings are recorded with a heuristic severity only; `security_score` is not computed in this stage.
- **Scans are manual and asynchronous:** no scheduled/periodic scans and no background worker/queue; scans run as FastAPI background tasks inside the API process. If the process restarts mid-scan, the scan is left in its last persisted state (no automatic resume/retry).
- **Single-process concurrency bound:** at most `max_concurrent_scans` (2) scans run concurrently per process, guarded by an in-process semaphore (not suitable for multi-worker deployments without external coordination).
- **Best-effort network assumptions:** a scan reflects a single point-in-time observation from one network vantage point; transient DNS/TLS failures are reported as unknown, not as confirmed vulnerabilities. Redirects are validated but not followed, so multi-hop redirect chains are only partially assessed.
- **Authorization is attestation only (scanner-relevant):** a scan only verifies the stored `authorization_confirmed` flag; it does not independently prove domain ownership, so the platform relies on the asset registration step for authorization.

## Out of scope (future stages)

Authentication/login, password storage, security scoring, alert generation logic, PDF reporting, payments, automated/scheduled scanning, and multi-tenant isolation are intentionally not implemented.

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

The scan performs a bounded number of outbound requests (HTTPS/HTTP `GET /`,
TLS handshake, and a few DNS TXT/CAA lookups). It never downloads response
bodies and never follows redirects automatically.
