from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt

from app.auth.dependencies import get_current_user, require_role
from app.auth.models import User, UserRole
from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, hash_password


def make_user(role: UserRole = UserRole.USER, is_active: bool = True) -> User:
    return User(
        id=uuid4(),
        email="dependency@example.com",
        username="dependency_user",
        hashed_password=hash_password("StrongPass1!"),
        first_name="Dependency",
        last_name="User",
        role=role,
        is_active=is_active,
        is_verified=False,
        created_at=datetime.now(UTC),
    )


def credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def test_get_current_user_with_valid_token_returns_user() -> None:
    user = make_user()
    user_repo = SimpleNamespace(get_by_id=AsyncMock(return_value=user))

    resolved_user = await get_current_user(
        credentials=create_credentials_for_user(user),
        user_repo=user_repo,
    )

    assert resolved_user == user
    user_repo.get_by_id.assert_awaited_once_with(user.id)


async def test_get_current_user_with_expired_token_raises_401() -> None:
    user = make_user()
    expired_token = jwt.encode(
        {
            "sub": str(user.id),
            "exp": datetime.now(UTC) - timedelta(minutes=1),
            "iat": datetime.now(UTC) - timedelta(minutes=2),
            "type": "access",
        },
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(
            credentials=credentials(expired_token),
            user_repo=SimpleNamespace(get_by_id=AsyncMock(return_value=user)),
        )

    assert exc_info.value.status_code == 401


async def test_get_current_user_rejects_refresh_token() -> None:
    user = make_user()
    refresh_token, _token_hash = create_refresh_token(user.id)

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(
            credentials=credentials(refresh_token),
            user_repo=SimpleNamespace(get_by_id=AsyncMock(return_value=user)),
        )

    assert exc_info.value.status_code == 401


def test_require_role_allows_admin_for_moderator_dependency() -> None:
    admin = make_user(role=UserRole.ADMIN)
    checker = require_role(UserRole.MODERATOR)

    assert checker(admin) == admin


def test_require_role_blocks_user_for_moderator_dependency() -> None:
    user = make_user(role=UserRole.USER)
    checker = require_role(UserRole.MODERATOR)

    with pytest.raises(HTTPException) as exc_info:
        checker(user)

    assert exc_info.value.status_code == 403


def create_credentials_for_user(user: User) -> HTTPAuthorizationCredentials:
    return credentials(create_access_token(user.id))
