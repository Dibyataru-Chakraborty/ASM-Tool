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
from sqlalchemy.orm import Session as SASession


def configure_session_rls(
    db: Session,
    *,
    user_id: str = "",
    organization_id: str = "",
    bypass: bool = False,
) -> None:
    """Attach RLS context to a SQLAlchemy session.

    Context is re-applied with SET LOCAL at the beginning of every database
    transaction. This prevents tenant state from leaking through pooled
    PostgreSQL connections and survives application rollbacks safely.
    """
    ctx = {
        "user_id": str(user_id or ""),
        "organization_id": str(organization_id or ""),
        "bypass": bool(bypass),
    }
    db.info["rls_context"] = ctx
    if db.in_transaction():
        connection = db.connection()
        connection.execute(text("SELECT set_config('app.current_user_id', :v, true)"), {"v": ctx["user_id"]})
        connection.execute(text("SELECT set_config('app.current_org_id', :v, true)"), {"v": ctx["organization_id"]})
        connection.execute(text("SELECT set_config('app.bypass_rls', :v, true)"), {"v": "true" if ctx["bypass"] else "false"})


@event.listens_for(SASession, "after_begin")
def _apply_session_rls_context(session, transaction, connection):
    """Apply transaction-local tenant context on every transaction start."""
    ctx = session.info.get("rls_context")
    if not ctx:
        # Default-deny context for sessions that were not explicitly configured.
        ctx = {"user_id": "", "organization_id": "", "bypass": False}
    connection.execute(text("SELECT set_config('app.current_user_id', :v, true)"), {"v": str(ctx.get("user_id") or "")})
    connection.execute(text("SELECT set_config('app.current_org_id', :v, true)"), {"v": str(ctx.get("organization_id") or "")})
    connection.execute(text("SELECT set_config('app.bypass_rls', :v, true)"), {"v": "true" if ctx.get("bypass") else "false"})


def get_db(request: Request = None) -> Session:
    """Database session with tenant RLS context derived from the signed JWT."""
    db = SessionLocal()
    try:
        user_id = ""
        organization_id = ""
        bypass = False
        if request:
            # Login/refresh need a privileged lookup before a user JWT exists.
            if request.url.path in {"/api/v1/auth/login", "/api/v1/auth/refresh"}:
                bypass = True
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                try:
                    token = auth_header.split(" ", 1)[1]
                    from app.security import JWTUtils
                    claims = JWTUtils.extract_claims(token)
                    user_id = claims.get("sub") or ""
                    platform_role = claims.get("platform_role") or "member"
                    token_org = claims.get("organization_id") or ""
                    if platform_role == "super_admin":
                        # Super Admin sees all tenants only in the platform console.
                        # Entering a tenant workspace turns RLS back on for that org.
                        selected_org = request.headers.get("X-Organization-ID") or ""
                        if selected_org:
                            organization_id = selected_org
                            bypass = False
                        else:
                            bypass = True
                    else:
                        organization_id = token_org
                        bypass = False
                except Exception:
                    # Invalid tokens are rejected by the auth dependency. Keep this
                    # DB session default-deny until then.
                    user_id = ""
                    organization_id = ""
                    bypass = False
        configure_session_rls(
            db,
            user_id=user_id,
            organization_id=organization_id,
            bypass=bypass,
        )
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
