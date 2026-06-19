from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, cast
from uuid import UUID, uuid4

from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from app.auth.exceptions import InvalidTokenError, TokenExpiredError
from app.core.config import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2."""
    return cast(str, pwd_context.hash(password))


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored password hash."""
    return cast(bool, pwd_context.verify(plain, hashed))


def create_access_token(subject: str | UUID, extra_claims: dict[str, Any] | None = None) -> str:
    """Create a signed access JWT for a subject."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": now,
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)

    return cast(str, jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM))


def create_refresh_token(subject: str | UUID) -> tuple[str, str]:
    """Create a signed refresh JWT and its SHA-256 storage hash."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": now,
        "type": "refresh",
        "jti": str(uuid4()),
    }
    token = cast(str, jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM))
    return token, hash_token(token)


def decode_token(token: str) -> dict[str, Any]:
    """Decode a JWT and validate its signature and expiration."""
    try:
        claims = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except JWTError as exc:
        raise InvalidTokenError() from exc

    if not isinstance(claims, dict):
        raise InvalidTokenError()

    return claims


def hash_token(token: str) -> str:
    """Hash a token with SHA-256 for database storage."""
    return sha256(token.encode("utf-8")).hexdigest()
