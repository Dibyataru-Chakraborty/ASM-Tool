"""
Authentication API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.auth_service import AuthService
from app.exceptions import AuthenticationError, ConflictError, ValidationError
from app.api.v1.auth.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    LoginResponse,
    RegisterResponse,
    RefreshTokenRequest,
    TokenResponse,
    ChangePasswordRequest,
)
from app.dependencies import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", status_code=status.HTTP_403_FORBIDDEN)
async def register():
    """Self-registration is disabled in multi-tenant mode."""
    raise HTTPException(
        status_code=403,
        detail="Self-registration is disabled. Contact your organization Admin or platform Super Admin.",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: UserLoginRequest,
    db: Session = Depends(get_db)
):
    """Login with email and password."""
    try:
        auth_service = AuthService(db)
        result = auth_service.login(
            email=request.email,
            password=request.password
        )
        return result
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token."""
    try:
        auth_service = AuthService(db)
        result = auth_service.refresh_access_token(request.refresh_token)
        result["expires_in"] = 30 * 60  # 30 minutes
        return result
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(status_code=500, detail="Token refresh failed")


@router.get("/me", response_model=dict)
async def get_current_user_info(
    current_user = Depends(get_current_user)
):
    """Get current authenticated user information."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.organization_role or current_user.platform_role,
        "platform_role": current_user.platform_role,
        "organization_id": current_user.current_organization_id,
        "organization_name": current_user.current_organization_name,
        "organization_role": current_user.organization_role,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "created_at": current_user.created_at.isoformat(),
    }


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password."""
    try:
        auth_service = AuthService(db)
        auth_service.change_password(
            user_id=current_user.id,
            old_password=request.old_password,
            new_password=request.new_password
        )
        return {"message": "Password changed successfully"}
    except (AuthenticationError, ValidationError) as e:
        raise HTTPException(status_code=400, detail=e.message)
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        raise HTTPException(status_code=500, detail="Password change failed")


@router.post("/logout")
async def logout(current_user = Depends(get_current_user)):
    """Logout (client-side token deletion)."""
    logger.info(f"User logged out: {current_user.id}")
    return {"message": "Logged out successfully"}
