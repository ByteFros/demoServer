from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.auth.exceptions import (
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UserAlreadyExistsError,
)
from app.auth.models import RefreshToken, User, UserRole
from app.auth.repository import RefreshTokenRepository, UserRepository
from app.auth.schemas import UserRegister, UserUpdate
from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    verify_password,
)


class AuthService:
    """Business logic for authentication and account self-management."""

    def __init__(
        self,
        user_repo: UserRepository,
        refresh_token_repo: RefreshTokenRepository,
    ) -> None:
        self.user_repo = user_repo
        self.refresh_token_repo = refresh_token_repo

    async def register(self, data: UserRegister) -> User:
        """Register a new user account."""
        if await self.user_repo.email_exists(str(data.email)):
            raise UserAlreadyExistsError("A user with this email already exists.")
        if await self.user_repo.username_exists(data.username):
            raise UserAlreadyExistsError("A user with this username already exists.")

        user = User(
            email=str(data.email),
            username=data.username,
            hashed_password=hash_password(data.password),
            first_name=data.first_name,
            last_name=data.last_name,
            role=UserRole.USER,
            is_active=True,
            is_verified=False,
        )
        return await self.user_repo.create(user)

    async def authenticate(
        self,
        email: str,
        password: str,
        user_agent: str | None,
        ip: str | None,
    ) -> tuple[User, str, str]:
        """Authenticate credentials and issue access and refresh tokens."""
        user = await self.user_repo.get_by_email(email)
        if user is None or not verify_password(password, user.hashed_password):
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InactiveUserError()

        access_token = self._create_access_token_for_user(user)
        refresh_token_plain, refresh_token_hash = create_refresh_token(user.id)
        await self.refresh_token_repo.create(
            RefreshToken(
                user_id=user.id,
                token_hash=refresh_token_hash,
                expires_at=self._refresh_token_expires_at(),
                user_agent=user_agent,
                ip_address=ip,
            )
        )
        await self.user_repo.update_last_login(user.id)

        return user, access_token, refresh_token_plain

    async def refresh_access_token(
        self,
        refresh_token_plain: str,
        user_agent: str | None,
        ip: str | None,
    ) -> tuple[str, str]:
        """Rotate a refresh token and issue a new access token."""
        claims = decode_token(refresh_token_plain)
        if claims.get("type") != "refresh":
            raise InvalidTokenError()

        token_hash = hash_token(refresh_token_plain)
        stored_token = await self.refresh_token_repo.get_by_hash(token_hash)
        if stored_token is None:
            raise InvalidTokenError()
        if stored_token.revoked:
            await self.refresh_token_repo.revoke_all_for_user(stored_token.user_id)
            raise TokenRevokedError()
        if self._is_expired(stored_token.expires_at):
            raise TokenExpiredError()

        user = await self.user_repo.get_by_id(self._subject_to_uuid(claims.get("sub")))
        if user is None:
            raise InvalidTokenError()
        if not user.is_active:
            raise InactiveUserError()

        await self.refresh_token_repo.revoke(stored_token.id)
        new_access_token = self._create_access_token_for_user(user)
        new_refresh_token_plain, new_refresh_token_hash = create_refresh_token(user.id)
        await self.refresh_token_repo.create(
            RefreshToken(
                user_id=user.id,
                token_hash=new_refresh_token_hash,
                expires_at=self._refresh_token_expires_at(),
                user_agent=user_agent,
                ip_address=ip,
            )
        )

        return new_access_token, new_refresh_token_plain

    async def logout(self, refresh_token_plain: str) -> None:
        """Revoke a refresh token idempotently."""
        stored_token = await self.refresh_token_repo.get_by_hash(hash_token(refresh_token_plain))
        if stored_token is not None and not stored_token.revoked:
            await self.refresh_token_repo.revoke(stored_token.id)

    async def logout_all(self, user_id: UUID) -> int:
        """Revoke all active refresh tokens for a user."""
        return await self.refresh_token_repo.revoke_all_for_user(user_id)

    async def change_password(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str,
    ) -> None:
        """Change a user's password and revoke all refresh tokens."""
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User not found.")
        if not verify_password(current_password, user.hashed_password):
            raise InvalidCredentialsError()

        user.hashed_password = hash_password(new_password)
        await self.user_repo.update(user)
        await self.refresh_token_repo.revoke_all_for_user(user.id)

    async def update_profile(self, user_id: UUID, data: UserUpdate) -> User:
        """Update mutable profile fields for a user."""
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User not found.")

        changes = data.model_dump(exclude_unset=True, exclude_none=True)
        for field, value in changes.items():
            setattr(user, field, value)

        return await self.user_repo.update(user)

    def _create_access_token_for_user(self, user: User) -> str:
        return create_access_token(user.id, {"role": user.role.value})

    def _refresh_token_expires_at(self) -> datetime:
        return datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    def _is_expired(self, expires_at: datetime) -> bool:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at < datetime.now(UTC)

    def _subject_to_uuid(self, subject: object) -> UUID:
        if not isinstance(subject, str):
            raise InvalidTokenError()
        try:
            return UUID(subject)
        except ValueError as exc:
            raise InvalidTokenError() from exc
