# SLA-Aware Incident Ticket API

A REST API for logging support/operations incidents, assigning them to agents, and tracking them against priority-based SLA deadlines. Built with **FastAPI**, **SQLAlchemy**, and **JWT authentication** with role-based access control.

The design is based on my experience in a live, SLA-driven dispatch operation, where delays had to be caught and escalated before an SLA was breached and recurring delays needed a root cause.

## Features
- **Incident tickets:** create, list, assign, update status, close, and delete, with priority (P1 to P3) and category.
- **SLA tracking:** every ticket gets a deadline from its priority. `GET /tickets/breached` lists open tickets past their deadline, and each ticket carries a live `is_breached` flag.
- **Root cause required to close:** a ticket can't be closed without a root cause.
- **Authentication and roles:** JWT login with bcrypt-hashed passwords; `agent` and `admin` roles.

| Priority | SLA deadline |
|----------|--------------|
| P1 | 4 hours |
| P2 | 24 hours |
| P3 | 72 hours |

## Security
- Passwords hashed with bcrypt; never returned by the API.
- Public registration always creates an `agent`. Admins are created only through the `ADMIN_EMAIL` / `ADMIN_PASSWORD` environment variables.
- JWT signing key read from the `SECRET_KEY` environment variable (no hardcoded secret).
- Input validation on every endpoint using Pydantic models.
- Role checks: only admins can assign or delete tickets; agents can only change tickets that are unassigned or assigned to them.
- Login is blocked after 5 failed attempts per minute (per IP and email).
- ORM queries only (no string-built SQL).

## Endpoints
| Method | Path | Access | Purpose |
|--------|------|--------|---------|
| POST | `/auth/register` | public | Create an agent account |
| POST | `/auth/login` | public | Get a JWT |
| POST | `/tickets` | logged in | Create a ticket |
| GET | `/tickets` | logged in | List tickets (`skip`, `limit`) |
| GET | `/tickets/breached` | logged in | Open tickets past their SLA |
| PATCH | `/tickets/{id}/assign?user_id=` | admin | Assign a ticket |
| PATCH | `/tickets/{id}/status` | logged in* | Move a ticket to `open` or `in_progress` |
| POST | `/tickets/{id}/close` | logged in* | Close with a required root cause |
| DELETE | `/tickets/{id}` | admin | Delete a ticket |

\* Agents can only act on unassigned tickets or tickets assigned to them; admins can act on any.

Interactive docs are available at `/docs` when the server is running.

## Run locally
```bash
pip install -r requirements.txt

# Optional: create a first admin and set a stable signing key
export SECRET_KEY="change-me-to-a-long-random-string"
export ADMIN_EMAIL="admin@example.com"
export ADMIN_PASSWORD="a-strong-password"

python3 -m uvicorn main:app --reload
```
Then open `http://127.0.0.1:8000/docs`.

To use MySQL instead of SQLite, set `DATABASE_URL=mysql+pymysql://user:password@localhost:3306/incident_db` and install `pymysql`.

## Run the tests
```bash
python3 -m pytest -v --cov=main --cov-report=term-missing
```
Tests use an in-memory SQLite database and cover authentication, the privilege-escalation fix, login rate limiting, SLA deadlines, breach detection, closing rules, and role permissions.

## Tech stack
Python, FastAPI, SQLAlchemy, Pydantic, python-jose (JWT), passlib/bcrypt, pytest, SQLite (MySQL supported).

## Known limitations and next steps
- The login attempt tracker is in memory, so it resets on restart and isn't shared across multiple servers (a shared store such as Redis would fix that).
- No refresh tokens or token revocation yet.
- No database migrations (Alembic) yet.
- Planned: Docker setup and a deployed demo.
