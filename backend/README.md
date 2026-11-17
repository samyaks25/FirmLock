# FirmLock Backend

Backend API for **FirmLock**, a cybersecurity monitoring platform for small and
medium-sized businesses.

This stage contains only the application foundation: a FastAPI app with a
welcome endpoint, a health endpoint, interactive documentation and CORS
configured for local frontend development.

## Requirements

- Python 3.10+ (developed and tested with Python 3.15)
- Windows PowerShell (commands below) or any POSIX shell

## Project layout

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, routes, CORS
│   ├── api/                 # HTTP layer (routers/dependencies)
│   ├── core/
│   │   ├── __init__.py
│   │   └── config.py        # Settings, kept out of application logic
│   ├── database/            # Placeholder for SQLAlchemy setup
│   ├── models/              # Placeholder for ORM models
│   ├── schemas/             # Placeholder for Pydantic schemas
│   └── services/
│       ├── __init__.py
│       └── scanner/         # Placeholder for future read-only checks
├── tests/
│   └── test_api.py          # Smoke tests (stdlib + uvicorn only)
├── requirements.txt
└── README.md
```

## Setup (Windows PowerShell)

```powershell
# 1. Move into the backend directory
cd backend

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks the activation script, run this once in the current
session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Run the backend

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open:

- Welcome message: <http://127.0.0.1:8000/>
- Health status: <http://127.0.0.1:8000/api/health>
- Interactive docs (Swagger UI): <http://127.0.0.1:8000/docs>
- OpenAPI schema: <http://127.0.0.1:8000/openapi.json>

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The tests start the app with uvicorn on `127.0.0.1:8765` automatically and
shut it down afterwards. They need no extra test dependencies.

## API endpoints

| Method | Path          | Description                              |
| ------ | ------------- | ---------------------------------------- |
| GET    | `/`           | Welcome message identifying FirmLock API |
| GET    | `/api/health` | Health status, service name, API version |
| GET    | `/docs`       | Swagger UI interactive documentation     |

## CORS

Local frontend development origins are allowed explicitly (no wildcard):

- `http://localhost:5173`
- `http://127.0.0.1:5173`

Override with the `FIRMLOCK_CORS_ORIGINS` environment variable
(comma separated) if the frontend port changes.

## Configuration

Settings live in `app/core/config.py` and can be overridden with environment
variables:

| Variable                | Default                                   | Purpose                     |
| ----------------------- | ----------------------------------------- | --------------------------- |
| `FIRMLOCK_APP_NAME`     | `FirmLock API`                            | Application/service name    |
| `FIRMLOCK_API_VERSION`  | `0.1.0`                                   | API version                 |
| `FIRMLOCK_ENV`          | `development`                             | Environment label           |
| `FIRMLOCK_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Allowed CORS origins   |

No secrets or credentials are stored in the source code.

## Out of scope for this stage

Database models, authentication, website registration, scanning, vulnerability
detection, scoring, alerts, reports and payments are intentionally **not**
implemented yet. They will be added in later stages after review.