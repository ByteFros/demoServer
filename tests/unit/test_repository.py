from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import RefreshToken, User, UserRole
from app.auth.repository import RefreshTokenRepository, UserRepository
from app.core.security import hash_password, hash_token


async def test_user_repository_create_lookup_and_update_last_login(
    db_session: AsyncSession,
) -> None:
    user_repo = UserRepository(db_session)
    user = await user_repo.create(
        User(
            email="repo@example.com",
            username="repo_user",
            hashed_password=hash_password("StrongPass1!"),
            first_name="Repo",
            last_name="User",
            role=UserRole.USER,
            is_active=True,
            is_verified=False,
        )
    )

    assert await user_repo.get_by_id(user.id) == user
    assert await user_repo.get_by_email("repo@example.com") == user
    assert await user_repo.get_by_username("repo_user") == user
    assert await user_repo.email_exists("repo@example.com") is True
    assert await user_repo.username_exists("repo_user") is True

    await user_repo.update_last_login(user.id)
    await db_session.refresh(user)

    assert user.last_login_at is not None


async def test_refresh_token_repository_revokes_and_deletes_expired(
    db_session: AsyncSession,
) -> None:
    user_repo = UserRepository(db_session)
    refresh_repo = RefreshTokenRepository(db_session)
    user = await user_repo.create(
        User(
            email="tokens@example.com",
            username="token_user",
            hashed_password=hash_password("StrongPass1!"),
            first_name="Token",
            last_name="User",
            role=UserRole.USER,
            is_active=True,
            is_verified=False,
        )
    )
    active = await refresh_repo.create(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token("active-token"),
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    expired = await refresh_repo.create(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token("expired-token"),
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )

    assert await refresh_repo.get_by_hash(active.token_hash) == active

    await refresh_repo.revoke(active.id)
    await db_session.refresh(active)
    assert active.revoked is True

    revoked_count = await refresh_repo.revoke_all_for_user(user.id)
    assert revoked_count == 1
    await db_session.refresh(expired)
    assert expired.revoked is True

    deleted_count = await refresh_repo.delete_expired()
    assert deleted_count == 1
    assert await refresh_repo.get_by_hash(expired.token_hash) is None
