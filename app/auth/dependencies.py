from collections.abc import Callable
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.exceptions import InvalidTokenError, TokenExpiredError
from app.auth.models import User, UserRole
from app.auth.repository import RefreshTokenRepository, UserRepository
from app.auth.service import AuthService
from app.core.security import decode_token
from app.db.session import get_db

bearer_scheme = HTTPBearer(auto_error=False)

ROLE_HIERARCHY = {
    UserRole.USER: 0,
    UserRole.MODERATOR: 1,
    UserRole.ADMIN: 2,
}


def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    """Create a user repository for the current request."""
    return UserRepository(db)


def get_refresh_token_repository(
    db: AsyncSession = Depends(get_db),
) -> RefreshTokenRepository:
    """Create a refresh token repository for the current request."""
    return RefreshTokenRepository(db)


def get_auth_service(
    user_repo: UserRepository = Depends(get_user_repository),
    rt_repo: RefreshTokenRepository = Depends(get_refresh_token_repository),
) -> AuthService:
    """Create the auth service for the current request."""
    return AuthService(user_repo, rt_repo)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    user_repo: UserRepository = Depends(get_user_repository),
) -> User:
    """Resolve the current user from a bearer access token."""
    if credentials is None:
        raise _unauthorized()

    try:
        claims = decode_token(credentials.credentials)
    except (InvalidTokenError, TokenExpiredError) as exc:
        raise _unauthorized() from exc

    if claims.get("type") != "access":
        raise _unauthorized()

    subject = claims.get("sub")
    if not isinstance(subject, str):
        raise _unauthorized()

    try:
        user_id = UUID(subject)
    except ValueError as exc:
        raise _unauthorized() from exc

    user = await user_repo.get_by_id(user_id)
    if user is None:
        raise _unauthorized()

    return user


async def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Resolve the current active user."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user.",
        )
    return user


def require_role(min_role: UserRole) -> Callable[[User], User]:
    """Return a dependency that enforces a minimum role."""

    def checker(user: User = Depends(get_current_active_user)) -> User:
        if ROLE_HIERARCHY[user.role] < ROLE_HIERARCHY[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions.",
            )
        return user

    return checker


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
