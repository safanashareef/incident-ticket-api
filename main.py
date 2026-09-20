import os
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Enum as SQLEnum, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt

# ==========================================
# 1. DATABASE CONFIGURATION
# ==========================================
# For testing/demo, using SQLite. For production, switch to:
# DATABASE_URL = "mysql+pymysql://user:password@localhost:3306/incident_db"
DATABASE_URL = "sqlite:///./incidents.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 2. SECURITY & AUTH SETUP
# ==========================================
SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_IN_PRODUCTION"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 3. ENUMS & DATABASE MODELS
# ==========================================
class UserRole(str, Enum):
    ADMIN = "admin"
    AGENT = "agent"

class PriorityLevel(str, Enum):
    P1 = "P1" # Deadline: 4 hours
    P2 = "P2" # Deadline: 24 hours
    P3 = "P3" # Deadline: 72 hours

SLA_DEADLINES_HOURS = {
    PriorityLevel.P1: 4,
    PriorityLevel.P2: 24,
    PriorityLevel.P3: 72
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
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    sla_deadline = Column(DateTime, nullable=False)
    
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)

Base.metadata.create_all(bind=engine)

# ==========================================
# 4. PYDANTIC SCHEMAS (Input Validation)
# ==========================================
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: UserRole = UserRole.AGENT

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: UserRole
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TicketCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str
    priority: PriorityLevel
    category: str

class TicketUpdate(BaseModel):
    status: Optional[TicketStatus] = None
    assigned_to: Optional[int] = None

class TicketClose(BaseModel):
    root_cause: str = Field(..., min_length=5, description="Root cause is required when closing a ticket.")

class TicketResponse(BaseModel):
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

    class Config:
        from_attributes = True

# ==========================================
# 5. AUTH DEPENDENCIES & PERMISSIONS
# ==========================================
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required."
        )
    return current_user

# Helper to transform Ticket model to response schema with live SLA check
def format_ticket(ticket: Ticket) -> dict:
    is_breached = (
        ticket.status != TicketStatus.CLOSED and 
        datetime.utcnow() > ticket.sla_deadline
    )
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
        "assigned_to": ticket.assigned_to
    }

# ==========================================
# 6. FASTAPI APPLICATION & ENDPOINTS
# ==========================================
app = FastAPI(title="SLA-Aware Incident Ticket API", version="1.0.0")

# --- AUTH ENDPOINTS ---
@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user_data.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role=user_data.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- TICKET ENDPOINTS ---
@app.post("/tickets", response_model=TicketResponse, status_code=status.HTTP_201_CREATED)
def create_ticket(
    ticket_in: TicketCreate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    now = datetime.utcnow()
    deadline = now + timedelta(hours=SLA_DEADLINES_HOURS[ticket_in.priority])
    
    ticket = Ticket(
        title=ticket_in.title,
        description=ticket_in.description,
        priority=ticket_in.priority,
        category=ticket_in.category,
        created_at=now,
        sla_deadline=deadline
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)

@app.get("/tickets", response_model=List[TicketResponse])
def list_tickets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    tickets = db.query(Ticket).all()
    return [format_ticket(t) for t in tickets]

@app.get("/tickets/breached", response_model=List[TicketResponse])
def list_breached_tickets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    now = datetime.utcnow()
    # Query non-closed tickets where deadline has passed
    breached = db.query(Ticket).filter(
        Ticket.status != TicketStatus.CLOSED,
        Ticket.sla_deadline < now
    ).all()
    return [format_ticket(t) for t in breached]

@app.patch("/tickets/{ticket_id}/assign", response_model=TicketResponse)
def assign_ticket(
    ticket_id: int, 
    user_id: int, 
    db: Session = Depends(get_db), 
    admin: User = Depends(require_admin)  # Restricted to Admin
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
        
    ticket.assigned_to = user_id
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)

@app.post("/tickets/{ticket_id}/close", response_model=TicketResponse)
def close_ticket(
    ticket_id: int, 
    close_data: TicketClose, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    ticket.status = TicketStatus.CLOSED
    ticket.root_cause = close_data.root_cause
    db.commit()
    db.refresh(ticket)
    return format_ticket(ticket)

@app.delete("/tickets/{ticket_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ticket(
    ticket_id: int, 
    db: Session = Depends(get_db), 
    admin: User = Depends(require_admin) # Restricted to Admin
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    db.delete(ticket)
    db.commit()
    return None
