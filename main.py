"""SLA-Aware Incident Ticket API.

FastAPI + SQLAlchemy service for logging incidents, assigning them, and tracking
them against priority-based SLA deadlines. Uses JWT authentication with
role-based access control (agent / admin).
"""
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import (
    Column, DateTime, Enum as SQLEnum, ForeignKey, Integer, String, Text, create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

# ==========================================
# 1. CONFIGURATION
# ==========================================
# Demo default is SQLite. For MySQL set:
#   DATABASE_URL=mysql+pymysql://user:password@localhost:3306/incident_db
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./incidents.db")

# The signing key must come from the environment. If it is missing we generate a
# random one so the app still starts, but tokens stop working after a restart.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set; using a temporary random key (tokens reset on restart).")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Login protection: block after too many failed attempts inside the window.
MAX_FAILED_LOGINS = 5
LOGIN_WINDOW_SECONDS = 60


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite-friendly, avoids deprecated utcnow())."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ==========================================
# 2. DATABASE
# ==========================================
engine_kwargs: dict = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    if DATABASE_URL in ("sqlite://", "sqlite:///:memory:"):
        engine_kwargs["poolclass"] = StaticPool  # one shared in-memory DB (used by tests)

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==========================================
# 3. SECURITY HELPERS
# ==========================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# In-memory failed-login tracker: {"ip:email": [timestamps]}
failed_logins: Dict[str, List[float]] = {}


def _recent_failures(key: str) -> List[float]:
    now = time.monotonic()
    recent = [t for t in failed_logins.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    failed_logins[key] = recent
    return recent


# ==========================================
# 4. ENUMS & MODELS
# ==========================================
class UserRole(str, Enum):
    ADMIN = "admin"
    AGENT = "agent"


class PriorityLevel(str, Enum):
    P1 = "P1"  # 4 hours
    P2 = "P2"  # 24 hours
    P3 = "P3"  # 72 hours


SLA_DEADLINES_HOURS = {
    PriorityLevel.P1: 4,
    PriorityLevel.P2: 24,
    PriorityLevel.P3: 72,
}


class TicketStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.AGENT, nullable=False)


class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    priority = Column(SQLEnum(PriorityLevel), nullable=False)
    status = Column(SQLEnum(TicketStatus), default=TicketStatus.OPEN, nullable=False)
    category = Column(String(100), nullable=False)
    root_cause = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    sla_deadline = Column(DateTime, nullable=False)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)


Base.metadata.create_all(bind=engine)


def seed_admin() -> None:
    """Create the first admin from ADMIN_EMAIL / ADMIN_PASSWORD (if provided).

    Public registration can only create agents, so this is the only way to get an admin.
    """
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")
    if not email or not password:
        return
    with SessionLocal() as db:
        if not db.query(User).filter(User.email == email.lower()).first():
            db.add(User(email=email.lower(), hashed_password=hash_password(password), role=UserRole.ADMIN))
            db.commit()


seed_admin()


# ==========================================
# 5. SCHEMAS (input validation)
# ==========================================
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    # Note: no "role" field. Public registration always creates an agent.


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    role: UserRole


class Token(BaseModel):
    access_token: str
    token_type: str


class TicketCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=1)
    priority: PriorityLevel
    category: str = Field(..., min_length=1, max_length=100)


class TicketStatusUpdate(BaseModel):
    status: TicketStatus


class TicketClose(BaseModel):
    root_cause: str = Field(..., min_length=5, description="Required when closing a ticket.")


class TicketResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    description: str
    priority: PriorityLevel
    status: TicketStatus
    category: str
    root_cause: Optional[str]
    created_at: datetime
    sla_deadline: datetime
    is_breached: bool
    assigned_to: Optional[int]


# ==========================================
# 6. DEPENDENCIES & HELPERS
# ==========================================
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required.")
    return current_user


def format_ticket(ticket: Ticket) -> dict:
    """Ticket -> response dict, with a live SLA-breach check."""
    is_breached = ticket.status != TicketStatus.CLOSED and utcnow() > ticket.sla_deadline
    return {
        "id": ticket.id,
        "title": ticket.title,
        "description": ticket.description,
        "priority": ticket.priority,
        "status": ticket.status,
        "category": ticket.category,
        "root_cause": ticket.root_cause,
        "created_at": ticket.created_at,
        "sla_deadline": ticket.sla_deadline,
        "is_breached": is_breached,
        "assigned_to": ticket.assigned_to,
    }


def get_ticket_or_404(db: Session, ticket_id: int) -> Ticket:
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


def ensure_can_modify(ticket: Ticket, user: User) -> None:
    """Admins can modify any ticket. Agents only unassigned tickets or their own."""
    if user.role == UserRole.ADMIN:
        return
    if ticket.assigned_to is not None and ticket.assigned_to != user.id:
        raise HTTPException(status_code=403, detail="This ticket is assigned to another user.")


# ==========================================
# 7. APP & ENDPOINTS
# ==========================================
app = FastAPI(title="SLA-Aware Incident Ticket API", version="1.1.0")


@app.get("/", include_in_schema=False)
def root():
    return {"status": "ok", "docs": "/docs"}


# --- AUTH ---
@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    email = str(user_data.email).lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(email=email, hashed_password=hash_password(user_data.password), role=UserRole.AGENT)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/auth/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form_data.username.lower()
    client_host = request.client.host if request.client else "unknown"
    key = f"{client_host}:{email}"

    if len(_recent_failures(key)) >= MAX_FAILED_LOGINS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again in a minute.",
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        failed_logins.setdefault(key, []).append(time.monotonic())
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    failed_logins.pop(key, None)
    token = create_access_token({"sub": user.email}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}


# --- TICKETS ---
@app.post("/tickets", response_model=TicketResponse, status_code=status.HTTP_201_CREATED)
def create_ticket(
    ticket_in: TicketCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now = utcnow()
    ticket = Ticket(
        title=ticket_in.title,
        description=ticket_in.description,
        priority=ticket_in.priority,
        category=ticket_in.category,
        created_at=now,
        sla_deadline=now + timedelta(hours=SLA_DEADLINES_HOURS[ticket_in.priority]),
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)


@app.get("/tickets", response_model=List[TicketResponse])
def list_tickets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    tickets = db.query(Ticket).order_by(Ticket.id).offset(skip).limit(limit).all()
    return [format_ticket(t) for t in tickets]


@app.get("/tickets/breached", response_model=List[TicketResponse])
def list_breached_tickets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    breached = (
        db.query(Ticket)
        .filter(Ticket.status != TicketStatus.CLOSED, Ticket.sla_deadline < utcnow())
        .order_by(Ticket.sla_deadline)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [format_ticket(t) for t in breached]


@app.patch("/tickets/{ticket_id}/assign", response_model=TicketResponse)
def assign_ticket(
    ticket_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),  # admin only
):
    ticket = get_ticket_or_404(db, ticket_id)
    if not db.query(User).filter(User.id == user_id).first():
        raise HTTPException(status_code=404, detail="Target user not found")

    ticket.assigned_to = user_id
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)


@app.patch("/tickets/{ticket_id}/status", response_model=TicketResponse)
def update_ticket_status(
    ticket_id: int,
    update: TicketStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ticket = get_ticket_or_404(db, ticket_id)
    ensure_can_modify(ticket, current_user)

    if ticket.status == TicketStatus.CLOSED:
        raise HTTPException(status_code=409, detail="Ticket is already closed")
    if update.status == TicketStatus.CLOSED:
        raise HTTPException(status_code=400, detail="Use the close endpoint (a root cause is required).")

    ticket.status = update.status
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)


@app.post("/tickets/{ticket_id}/close", response_model=TicketResponse)
def close_ticket(
    ticket_id: int,
    close_data: TicketClose,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ticket = get_ticket_or_404(db, ticket_id)
    ensure_can_modify(ticket, current_user)

    if ticket.status == TicketStatus.CLOSED:
        raise HTTPException(status_code=409, detail="Ticket is already closed")

    ticket.status = TicketStatus.CLOSED
    ticket.root_cause = close_data.root_cause
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)


@app.delete("/tickets/{ticket_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ticket(
    ticket_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),  # admin only
):
    ticket = get_ticket_or_404(db, ticket_id)
    db.delete(ticket)
    db.commit()
    return None
