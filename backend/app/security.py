"""
Security utilities for JWT token handling and password management.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.config import settings
from app.exceptions import AuthenticationError
import logging

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordUtils:
    """Password hashing and verification utilities."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hash."""
        return pwd_context.verify(plain_password, hashed_password)


class JWTUtils:
    """JWT token generation and verification."""

    @staticmethod
    def create_access_token(
        subject: str,
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a JWT access token."""
        if expires_delta is None:
            expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)

        expire = datetime.utcnow() + expires_delta
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.utcnow(),
        }

        if additional_claims:
            to_encode.update(additional_claims)

        encoded_jwt = jwt.encode(
            to_encode,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        )
        return encoded_jwt

    @staticmethod
    def create_refresh_token(subject: str) -> str:
        """Create a JWT refresh token with longer expiration."""
        expires_delta = timedelta(days=settings.jwt_refresh_token_expire_days)
        return JWTUtils.create_access_token(
            subject=subject,
            expires_delta=expires_delta,
            additional_claims={"type": "refresh"},
        )

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """Decode and verify a JWT token."""
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
            )
            return payload
        except JWTError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise AuthenticationError("Invalid or expired token")

    @staticmethod
    def extract_user_id(token: str) -> str:
        """Extract user ID from token."""
        payload = JWTUtils.decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Invalid token: no subject")
        return user_id

    @staticmethod
    def extract_claims(token: str) -> Dict[str, Any]:
        """Extract all claims from token."""
        return JWTUtils.decode_token(token)


class TokenResponse:
    """Standard token response."""

    def __init__(self, access_token: str, refresh_token: Optional[str] = None):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_type = "bearer"
        self.expires_in = settings.jwt_access_token_expire_minutes * 60

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response."""
        data = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }
        if self.refresh_token:
            data["refresh_token"] = self.refresh_token
        return data
