from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import RefreshToken, User


class UserRepository:
    """Database access for users."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_by_id(self, user_id: UUID) -> User | None:
        """Return a user by id, if present."""
        return await self.db.get(User, user_id)

    async def get_by_email(self, email: str) -> User | None:
        """Return a user by email, if present."""
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> User | None:
        """Return a user by username, if present."""
        result = await self.db.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def email_exists(self, email: str) -> bool:
        """Return whether an email is already registered."""
        result = await self.db.execute(
            select(func.count()).select_from(User).where(User.email == email)
        )
        return result.scalar_one() > 0

    async def username_exists(self, username: str) -> bool:
        """Return whether a username is already registered."""
        result = await self.db.execute(
            select(func.count()).select_from(User).where(User.username == username)
        )
        return result.scalar_one() > 0

    async def create(self, user: User) -> User:
        """Persist a user and load generated defaults."""
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def update(self, user: User) -> User:
        """Flush pending updates for a user and load generated defaults."""
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def update_last_login(self, user_id: UUID) -> None:
        """Set the user's last login timestamp."""
        await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(last_login_at=datetime.now(UTC), updated_at=datetime.now(UTC))
            .execution_options(synchronize_session=False)
        )
        await self.db.flush()


class RefreshTokenRepository:
    """Database access for refresh tokens."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, token: RefreshToken) -> RefreshToken:
        """Persist a refresh token and load generated defaults."""
        self.db.add(token)
        await self.db.flush()
        await self.db.refresh(token)
        return token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Return a refresh token by storage hash, if present."""
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def revoke(self, token_id: UUID) -> None:
        """Mark a refresh token as revoked."""
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.id == token_id)
            .values(revoked=True)
            .execution_options(synchronize_session=False)
        )
        await self.db.flush()

    async def revoke_all_for_user(self, user_id: UUID) -> int:
        """Revoke all active refresh tokens for a user."""
        result = await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
            .values(revoked=True)
            .execution_options(synchronize_session=False)
        )
        await self.db.flush()
        return cast(int, getattr(result, "rowcount", 0) or 0)

    async def delete_expired(self) -> int:
        """Delete expired refresh tokens."""
        result = await self.db.execute(
            delete(RefreshToken)
            .where(RefreshToken.expires_at < datetime.now(UTC))
            .execution_options(synchronize_session=False)
        )
        await self.db.flush()
        return cast(int, getattr(result, "rowcount", 0) or 0)
