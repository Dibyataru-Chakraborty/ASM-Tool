from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
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


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """Register a new user."""
    try:
        auth_service = AuthService(db)
        result = auth_service.register(
            email=request.email,
            password=request.password,
            full_name=request.full_name
        )
        return result
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


@router.post("/login", response_model=LoginResponse)
async def login(
    request: UserLoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    """Login with email and password."""
    try:
        auth_service = AuthService(db)
        result = auth_service.login(
            email=request.email,
            password=request.password
        )
        result["platform_role"] = "super_admin" if result["role"] == "admin" else result["role"]
        
        # Resolve organization details for normal user (superadmin login doesn't have org initially selected)
        from app.models import User, Tenant
        user = db.query(User).filter(User.id == result["user_id"]).first()
        org_id = user.tenant_id if user else None
        org_name = None
        if org_id:
            tenant = db.query(Tenant).filter(Tenant.id == org_id).first()
            if tenant:
                org_name = tenant.name
        result["organization_id"] = org_id
        result["organization_name"] = org_name
        
        # Set access_token in secure, http-only cookie
        response.set_cookie(
            key="access_token",
            value=result["access_token"],
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=30 * 60, # 30 minutes
            path="/"
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
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current authenticated user information."""
    org_id = current_user.tenant_id
    org_name = None
    
    # If the user is a super admin, check X-Organization-ID header
    is_super = current_user.role == "admin" and current_user.tenant_id is None
    if is_super:
        org_id = request.headers.get("X-Organization-ID")
        
    if org_id:
        from app.models import Tenant
        tenant = db.query(Tenant).filter(Tenant.id == org_id).first()
        if tenant:
            org_name = tenant.name
            
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "platform_role": "super_admin" if is_super else current_user.role,
        "organization_id": org_id,
        "organization_name": org_name,
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
async def logout(response: Response, current_user = Depends(get_current_user)):
    """Logout (client-side token deletion)."""
    logger.info(f"User logged out: {current_user.id}")
    response.delete_cookie(key="access_token", path="/")
    return {"message": "Logged out successfully"}
