import os

# Use a throwaway in-memory database for tests. Must be set BEFORE importing main.
os.environ["DATABASE_URL"] = "sqlite://"

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from main import (
    Base, SessionLocal, Ticket, User, UserRole, app, engine, failed_logins, hash_password, utcnow,
)

PASSWORD = "Passw0rd!123"
TICKET = {
    "title": "Sample app not loading",
    "description": "Collection app fails to load in one zone",
    "priority": "P1",
    "category": "Outage",
}


@pytest.fixture(autouse=True)
def clean_state():
    """Fresh tables and login tracker for every test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    failed_logins.clear()
    yield


@pytest.fixture
def client():
    return TestClient(app)


# ---------- helpers ----------
def register(client, email, password=PASSWORD, **extra):
    return client.post("/auth/register", json={"email": email, "password": password, **extra})


def login(client, email, password=PASSWORD):
    return client.post("/auth/login", data={"username": email, "password": password})


def headers_for(client, email, password=PASSWORD):
    token = login(client, email, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def make_agent(client, email="agent@example.com"):
    """Register an agent through the API. Returns (auth headers, user id)."""
    user_id = register(client, email).json()["id"]
    return headers_for(client, email), user_id


def make_admin(client, email="admin@example.com"):
    """Admins can't self-register, so insert one directly. Returns (auth headers, user id)."""
    with SessionLocal() as db:
        admin = User(email=email, hashed_password=hash_password(PASSWORD), role=UserRole.ADMIN)
        db.add(admin)
        db.commit()
        user_id = admin.id
    return headers_for(client, email), user_id


def create_ticket(client, headers, **overrides):
    return client.post("/tickets", json={**TICKET, **overrides}, headers=headers)


def make_overdue(ticket_id):
    with SessionLocal() as db:
        ticket = db.get(Ticket, ticket_id)
        ticket.sla_deadline = utcnow() - timedelta(hours=1)
        db.commit()


# ---------- root ----------
def test_root_returns_ok(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ---------- registration ----------
def test_register_creates_agent(client):
    response = register(client, "new@example.com")
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new@example.com"
    assert body["role"] == "agent"
    assert "password" not in body and "hashed_password" not in body


def test_register_cannot_self_assign_admin_role(client):
    """Regression test: a caller must not be able to make themselves an admin."""
    response = register(client, "sneaky@example.com", role="admin")
    assert response.status_code == 201
    assert response.json()["role"] == "agent"


def test_register_duplicate_email_rejected(client):
    register(client, "dup@example.com")
    assert register(client, "dup@example.com").status_code == 400


def test_register_short_password_rejected(client):
    assert register(client, "short@example.com", password="abc").status_code == 422


# ---------- login & rate limiting ----------
def test_login_returns_token(client):
    register(client, "user@example.com")
    response = login(client, "user@example.com")
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["access_token"]


def test_login_wrong_password_rejected(client):
    register(client, "user@example.com")
    assert login(client, "user@example.com", "WrongPassword1").status_code == 401


def test_login_blocked_after_repeated_failures(client):
    register(client, "user@example.com")
    for _ in range(5):
        assert login(client, "user@example.com", "WrongPassword1").status_code == 401
    # Locked out, even with the correct password
    assert login(client, "user@example.com").status_code == 429


def test_tickets_require_authentication(client):
    assert client.get("/tickets").status_code == 401
    assert client.post("/tickets", json=TICKET).status_code == 401


# ---------- ticket creation & SLA ----------
@pytest.mark.parametrize("priority,hours", [("P1", 4), ("P2", 24), ("P3", 72)])
def test_sla_deadline_matches_priority(client, priority, hours):
    headers, _ = make_agent(client)
    response = create_ticket(client, headers, priority=priority)
    assert response.status_code == 201
    body = response.json()
    created = datetime.fromisoformat(body["created_at"])
    deadline = datetime.fromisoformat(body["sla_deadline"])
    assert deadline - created == timedelta(hours=hours)
    assert body["status"] == "open"
    assert body["is_breached"] is False


def test_create_ticket_invalid_priority_rejected(client):
    headers, _ = make_agent(client)
    assert create_ticket(client, headers, priority="P9").status_code == 422


def test_list_tickets_supports_pagination(client):
    headers, _ = make_agent(client)
    for i in range(3):
        create_ticket(client, headers, title=f"Ticket number {i}")
    response = client.get("/tickets", params={"limit": 2}, headers=headers)
    assert response.status_code == 200
    assert len(response.json()) == 2


# ---------- breached tickets ----------
def test_overdue_open_ticket_is_listed_as_breached(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    make_overdue(ticket_id)

    breached = client.get("/tickets/breached", headers=headers).json()
    assert [t["id"] for t in breached] == [ticket_id]
    assert breached[0]["is_breached"] is True


def test_fresh_ticket_is_not_breached(client):
    headers, _ = make_agent(client)
    create_ticket(client, headers)
    assert client.get("/tickets/breached", headers=headers).json() == []


def test_closed_ticket_is_never_breached(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    make_overdue(ticket_id)
    client.post(f"/tickets/{ticket_id}/close", json={"root_cause": "Expired certificate"}, headers=headers)
    assert client.get("/tickets/breached", headers=headers).json() == []


# ---------- closing tickets ----------
def test_close_ticket_requires_root_cause(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    assert client.post(f"/tickets/{ticket_id}/close", json={}, headers=headers).status_code == 422
    assert client.post(f"/tickets/{ticket_id}/close", json={"root_cause": "abc"}, headers=headers).status_code == 422


def test_close_ticket_saves_root_cause(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    response = client.post(
        f"/tickets/{ticket_id}/close", json={"root_cause": "Expired API certificate"}, headers=headers
    )
    assert response.status_code == 200
    assert response.json()["status"] == "closed"
    assert response.json()["root_cause"] == "Expired API certificate"


def test_close_ticket_twice_returns_conflict(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    body = {"root_cause": "Expired API certificate"}
    client.post(f"/tickets/{ticket_id}/close", json=body, headers=headers)
    assert client.post(f"/tickets/{ticket_id}/close", json=body, headers=headers).status_code == 409


def test_close_missing_ticket_returns_404(client):
    headers, _ = make_agent(client)
    response = client.post("/tickets/999/close", json={"root_cause": "Expired certificate"}, headers=headers)
    assert response.status_code == 404


# ---------- status updates ----------
def test_status_can_move_to_in_progress(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    response = client.patch(f"/tickets/{ticket_id}/status", json={"status": "in_progress"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"


def test_status_update_cannot_close_ticket(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    response = client.patch(f"/tickets/{ticket_id}/status", json={"status": "closed"}, headers=headers)
    assert response.status_code == 400


# ---------- roles & permissions ----------
def test_agent_cannot_assign_tickets(client):
    headers, agent_id = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    response = client.patch(f"/tickets/{ticket_id}/assign", params={"user_id": agent_id}, headers=headers)
    assert response.status_code == 403


def test_admin_can_assign_tickets(client):
    agent_headers, agent_id = make_agent(client)
    admin_headers, _ = make_admin(client)
    ticket_id = create_ticket(client, agent_headers).json()["id"]
    response = client.patch(f"/tickets/{ticket_id}/assign", params={"user_id": agent_id}, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["assigned_to"] == agent_id


def test_agent_cannot_close_ticket_assigned_to_someone_else(client):
    agent1_headers, _ = make_agent(client, "agent1@example.com")
    agent2_headers, agent2_id = make_agent(client, "agent2@example.com")
    admin_headers, _ = make_admin(client)
    ticket_id = create_ticket(client, agent1_headers).json()["id"]
    client.patch(f"/tickets/{ticket_id}/assign", params={"user_id": agent2_id}, headers=admin_headers)

    response = client.post(
        f"/tickets/{ticket_id}/close", json={"root_cause": "Expired certificate"}, headers=agent1_headers
    )
    assert response.status_code == 403


def test_assigned_agent_can_close_own_ticket(client):
    agent_headers, agent_id = make_agent(client)
    admin_headers, _ = make_admin(client)
    ticket_id = create_ticket(client, agent_headers).json()["id"]
    client.patch(f"/tickets/{ticket_id}/assign", params={"user_id": agent_id}, headers=admin_headers)

    response = client.post(
        f"/tickets/{ticket_id}/close", json={"root_cause": "Expired certificate"}, headers=agent_headers
    )
    assert response.status_code == 200


def test_agent_cannot_delete_ticket(client):
    headers, _ = make_agent(client)
    ticket_id = create_ticket(client, headers).json()["id"]
    assert client.delete(f"/tickets/{ticket_id}", headers=headers).status_code == 403


def test_admin_can_delete_ticket(client):
    agent_headers, _ = make_agent(client)
    admin_headers, _ = make_admin(client)
    ticket_id = create_ticket(client, agent_headers).json()["id"]
    assert client.delete(f"/tickets/{ticket_id}", headers=admin_headers).status_code == 204
    assert client.delete(f"/tickets/{ticket_id}", headers=admin_headers).status_code == 404
