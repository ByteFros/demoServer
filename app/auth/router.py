from fastapi import APIRouter, Depends, Request, Response, status

from app.auth.dependencies import get_auth_service, get_current_active_user
from app.auth.models import User
from app.auth.schemas import (
    ErrorResponse,
    LogoutAllResponse,
    PasswordChange,
    RefreshTokenRequest,
    TokenResponse,
    UserLogin,
    UserRead,
    UserRegister,
    UserUpdate,
)
from app.auth.service import AuthService
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

ERROR_RESPONSES = {
    401: {"model": ErrorResponse, "description": "Authentication failed."},
    403: {"model": ErrorResponse, "description": "The user cannot perform this action."},
    409: {"model": ErrorResponse, "description": "The request conflicts with existing state."},
    422: {"model": ErrorResponse, "description": "The request body is invalid."},
}


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a user",
    description="Create a user account with email, username, password and profile fields.",
    responses={409: ERROR_RESPONSES[409], 422: ERROR_RESPONSES[422]},
)
async def register(
    data: UserRegister,
    service: AuthService = Depends(get_auth_service),
) -> User:
    """Register a new user account."""
    return await service.register(data)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Authenticate with JSON email and password credentials.",
    responses={
        401: ERROR_RESPONSES[401],
        403: ERROR_RESPONSES[403],
        422: ERROR_RESPONSES[422],
    },
)
async def login(
    data: UserLogin,
    request: Request,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    """Authenticate a user and issue access and refresh tokens."""
    _user, access_token, refresh_token = await service.authenticate(
        email=str(data.email),
        password=data.password,
        user_agent=request.headers.get("user-agent"),
        ip=_client_ip(request),
    )
    return _token_response(access_token, refresh_token)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Rotate a refresh token and return a new access/refresh token pair.",
    responses={401: ERROR_RESPONSES[401], 403: ERROR_RESPONSES[403], 422: ERROR_RESPONSES[422]},
)
async def refresh(
    data: RefreshTokenRequest,
    request: Request,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    """Rotate a refresh token and issue a new token pair."""
    access_token, refresh_token = await service.refresh_access_token(
        refresh_token_plain=data.refresh_token,
        user_agent=request.headers.get("user-agent"),
        ip=_client_ip(request),
    )
    return _token_response(access_token, refresh_token)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout",
    description="Revoke one refresh token. The operation is idempotent.",
    responses={204: {"description": "Refresh token revoked."}, 422: ERROR_RESPONSES[422]},
)
async def logout(
    data: RefreshTokenRequest,
    service: AuthService = Depends(get_auth_service),
) -> Response:
    """Revoke a refresh token idempotently."""
    await service.logout(data.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/logout-all",
    response_model=LogoutAllResponse,
    summary="Logout all sessions",
    description="Revoke all active refresh tokens for the authenticated user.",
    responses={401: ERROR_RESPONSES[401], 403: ERROR_RESPONSES[403]},
)
async def logout_all(
    user: User = Depends(get_current_active_user),
    service: AuthService = Depends(get_auth_service),
) -> LogoutAllResponse:
    """Revoke every refresh token for the current user."""
    revoked_count = await service.logout_all(user.id)
    return LogoutAllResponse(revoked_count=revoked_count)


@router.get(
    "/me",
    response_model=UserRead,
    summary="Get current user",
    description="Return the authenticated user's public profile.",
    responses={401: ERROR_RESPONSES[401], 403: ERROR_RESPONSES[403]},
)
async def get_me(user: User = Depends(get_current_active_user)) -> User:
    """Return the current user."""
    return user


@router.patch(
    "/me",
    response_model=UserRead,
    summary="Update current user",
    description="Update mutable profile fields for the authenticated user.",
    responses={
        401: ERROR_RESPONSES[401],
        403: ERROR_RESPONSES[403],
        422: ERROR_RESPONSES[422],
    },
)
async def update_me(
    data: UserUpdate,
    user: User = Depends(get_current_active_user),
    service: AuthService = Depends(get_auth_service),
) -> User:
    """Update the current user's profile."""
    return await service.update_profile(user.id, data)


@router.post(
    "/me/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change password",
    description=(
        "Change the authenticated user's password and revoke all refresh tokens. "
        "Other devices must login again."
    ),
    responses={
        204: {"description": "Password changed and refresh tokens revoked."},
        401: ERROR_RESPONSES[401],
        403: ERROR_RESPONSES[403],
        422: ERROR_RESPONSES[422],
    },
)
async def change_password(
    data: PasswordChange,
    user: User = Depends(get_current_active_user),
    service: AuthService = Depends(get_auth_service),
) -> Response:
    """Change the current user's password."""
    await service.change_password(user.id, data.current_password, data.new_password)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _token_response(access_token: str, refresh_token: str) -> TokenResponse:
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


def _client_ip(request: Request) -> str | None:
    if request.client is None:
        return None
    return request.client.host
