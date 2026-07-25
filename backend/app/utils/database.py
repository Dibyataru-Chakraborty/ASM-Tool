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
    """Initialize database schema."""
    from app.models import Base
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized")


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
