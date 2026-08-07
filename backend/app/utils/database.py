"""
Database connection and session management.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from app.config import settings
import logging

logger = logging.getLogger(__name__)


# Database URL
DATABASE_URL = settings.database_url

# Engine configuration
engine = create_engine(
    DATABASE_URL,
    echo=settings.database_echo,
    poolclass=QueuePool,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_pre_ping=True,  # Test connections before using
    pool_recycle=3600,   # Recycle connections every hour
    connect_args={
        "connect_timeout": 10,
        "application_name": "asm_platform",
    }
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False
)


from fastapi import Request
from sqlalchemy import text

def get_db(request: Request = None) -> Session:
    """Dependency injection for database session with RLS support."""
    db = SessionLocal()
    try:
        # Reset session context variables to prevent connection pool leakage
        try:
            db.execute(text("SET app.current_user_id = ''"))
            db.execute(text("SET app.bypass_rls = 'false'"))
        except Exception:
            pass

        # If running inside a request context, attempt to extract and set the user ID for RLS
        if request:
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                try:
                    token = auth_header.split(" ")[1]
                    from app.security import JWTUtils
                    user_id = JWTUtils.extract_user_id(token)
                    if user_id:
                        db.execute(text("SET app.current_user_id = :user_id"), {"user_id": user_id})
                except Exception:
                    pass
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database schema and bootstrap super admin."""
    from app.models import Base, User
    from app.security import PasswordUtils
    
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized")
    
    # Bootstrap super admin if configured
    if settings.bootstrap_super_admin_email and settings.bootstrap_super_admin_password:
        email = settings.bootstrap_super_admin_email.strip()
        raw_password = settings.bootstrap_super_admin_password.strip()
        # Remove surrounding quotes from environment variable if present
        if (raw_password.startswith("'") and raw_password.endswith("'")) or \
           (raw_password.startswith('"') and raw_password.endswith('"')):
            raw_password = raw_password[1:-1]
            
        name = settings.bootstrap_super_admin_name or "Super Admin"
        
        db = SessionLocal()
        try:
            # Check if user already exists and delete them to recreate/reset
            existing_user = db.query(User).filter(User.email == email).first()
            if existing_user:
                logger.info(f"Removing existing super admin user {email} for recreation")
                db.delete(existing_user)
                db.commit()
                
            logger.info(f"Creating bootstrap super admin user: {email}")
            hashed_pw = PasswordUtils.hash_password(raw_password)
            super_admin = User(
                email=email,
                password_hash=hashed_pw,
                full_name=name,
                role="admin",
                is_active=True,
                is_verified=True
            )
            db.add(super_admin)
            db.commit()
            logger.info("Super admin user successfully bootstrapped")
        except Exception as e:
            logger.error(f"Error bootstrapping super admin: {str(e)}")
            db.rollback()
        finally:
            db.close()


def close_db():
    """Close database connections."""
    engine.dispose()
    logger.info("Database connections closed")


# Connection pool monitoring
@event.listens_for(engine, "connect")
def receive_connect(dbapi_conn, connection_record):
    """Log successful connections."""
    logger.debug("Database connection established")


@event.listens_for(engine, "close")
def receive_close(dbapi_conn, connection_record):
    """Log connection closure."""
    logger.debug("Database connection closed")
