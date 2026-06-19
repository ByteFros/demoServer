from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.auth.exceptions import (
    InvalidCredentialsError,
    TokenRevokedError,
    UserAlreadyExistsError,
)
from app.auth.models import RefreshToken, User, UserRole
from app.auth.schemas import UserRegister, UserUpdate
from app.auth.service import AuthService
from app.core.security import create_refresh_token, hash_password


def make_user(password: str = "StrongPass1!", is_active: bool = True) -> User:
    return User(
        id=uuid4(),
        email="service@example.com",
        username="service_user",
        hashed_password=hash_password(password),
        first_name="Service",
        last_name="User",
        role=UserRole.USER,
        is_active=is_active,
        is_verified=False,
        created_at=datetime.now(UTC),
    )


def make_service() -> tuple[AuthService, SimpleNamespace, SimpleNamespace]:
    user_repo = SimpleNamespace(
        email_exists=AsyncMock(return_value=False),
        username_exists=AsyncMock(return_value=False),
        create=AsyncMock(side_effect=lambda user: user),
        get_by_email=AsyncMock(return_value=None),
        get_by_id=AsyncMock(return_value=None),
        update=AsyncMock(side_effect=lambda user: user),
        update_last_login=AsyncMock(return_value=None),
    )
    refresh_repo = SimpleNamespace(
        create=AsyncMock(side_effect=lambda token: token),
        get_by_hash=AsyncMock(return_value=None),
        revoke=AsyncMock(return_value=None),
        revoke_all_for_user=AsyncMock(return_value=0),
    )
    return AuthService(user_repo, refresh_repo), user_repo, refresh_repo


async def test_register_with_existing_email_raises_conflict() -> None:
    service, user_repo, _refresh_repo = make_service()
    user_repo.email_exists.return_value = True
    data = UserRegister(
        email="service@example.com",
        username="service_user",
        password="StrongPass1!",
        first_name="Service",
        last_name="User",
    )

    with pytest.raises(UserAlreadyExistsError):
        await service.register(data)

    user_repo.create.assert_not_awaited()


async def test_register_creates_user_with_hashed_password() -> None:
    service, user_repo, _refresh_repo = make_service()
    data = UserRegister(
        email="service@example.com",
        username="service_user",
        password="StrongPass1!",
        first_name="Service",
        last_name="User",
    )

    user = await service.register(data)

    user_repo.create.assert_awaited_once()
    assert user.email == "service@example.com"
    assert user.hashed_password != "StrongPass1!"


async def test_authenticate_with_wrong_password_raises_generic_credentials_error() -> None:
    service, user_repo, refresh_repo = make_service()
    user_repo.get_by_email.return_value = make_user()

    with pytest.raises(InvalidCredentialsError):
        await service.authenticate("service@example.com", "WrongPass1!", None, None)

    refresh_repo.create.assert_not_awaited()


async def test_authenticate_returns_tokens_and_persists_refresh_token() -> None:
    service, user_repo, refresh_repo = make_service()
    user = make_user()
    user_repo.get_by_email.return_value = user

    auth_user, access_token, refresh_token = await service.authenticate(
        "service@example.com",
        "StrongPass1!",
        "pytest",
        "127.0.0.1",
    )

    assert auth_user == user
    assert access_token
    assert refresh_token
    refresh_repo.create.assert_awaited_once()
    user_repo.update_last_login.assert_awaited_once_with(user.id)


async def test_refresh_reuse_of_revoked_token_triggers_mass_revocation() -> None:
    service, user_repo, refresh_repo = make_service()
    user = make_user()
    token_plain, token_storage_hash = create_refresh_token(user.id)
    stored_token = RefreshToken(
        id=uuid4(),
        user_id=user.id,
        token_hash=token_storage_hash,
        expires_at=datetime.now(UTC) + timedelta(days=1),
        revoked=True,
    )
    refresh_repo.get_by_hash.return_value = stored_token

    with pytest.raises(TokenRevokedError):
        await service.refresh_access_token(token_plain, None, None)

    user_repo.get_by_id.assert_not_awaited()
    refresh_repo.revoke_all_for_user.assert_awaited_once_with(user.id)


async def test_refresh_rotates_valid_token() -> None:
    service, user_repo, refresh_repo = make_service()
    user = make_user()
    token_plain, token_storage_hash = create_refresh_token(user.id)
    stored_token = RefreshToken(
        id=uuid4(),
        user_id=user.id,
        token_hash=token_storage_hash,
        expires_at=datetime.now(UTC) + timedelta(days=1),
        revoked=False,
    )
    user_repo.get_by_id.return_value = user
    refresh_repo.get_by_hash.return_value = stored_token

    access_token, new_refresh_token = await service.refresh_access_token(token_plain, None, None)

    assert access_token
    assert new_refresh_token != token_plain
    refresh_repo.revoke.assert_awaited_once_with(stored_token.id)
    assert refresh_repo.create.await_count == 1


async def test_logout_succeeds_silently_when_token_is_unknown() -> None:
    service, _user_repo, refresh_repo = make_service()

    await service.logout("unknown-refresh-token")

    refresh_repo.revoke.assert_not_awaited()


async def test_change_password_revokes_all_tokens_for_user() -> None:
    service, user_repo, refresh_repo = make_service()
    user = make_user()
    user_repo.get_by_id.return_value = user

    await service.change_password(user.id, "StrongPass1!", "NewStrongPass1!")

    user_repo.update.assert_awaited_once_with(user)
    refresh_repo.revoke_all_for_user.assert_awaited_once_with(user.id)


async def test_update_profile_applies_partial_changes() -> None:
    service, user_repo, _refresh_repo = make_service()
    user = make_user()
    user_repo.get_by_id.return_value = user

    updated_user = await service.update_profile(user.id, UserUpdate(first_name="Updated"))

    assert updated_user.first_name == "Updated"
    assert updated_user.last_name == "User"
    user_repo.update.assert_awaited_once_with(user)
