from __future__ import annotations

import re
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.auth.models import UserRole

USERNAME_PATTERN = r"^[a-zA-Z0-9_]{3,30}$"
SPECIAL_CHARACTER_PATTERN = re.compile(r"[^a-zA-Z0-9]")


class NameValidationMixin:
    """Shared validation for human name fields."""

    @field_validator("first_name", "last_name", mode="before", check_fields=False)
    @classmethod
    def validate_name(cls, value: Any) -> Any:
        """Trim names and reject empty values."""
        if value is None:
            return value
        if not isinstance(value, str):
            return value

        stripped = value.strip()
        if not stripped:
            msg = "Name fields cannot be empty."
            raise ValueError(msg)
        return stripped


class PasswordValidationMixin:
    """Shared validation for password fields."""

    @field_validator("password", "new_password", check_fields=False)
    @classmethod
    def validate_password(cls, value: str) -> str:
        """Enforce the project password policy."""
        if len(value) < 8:
            msg = "Password must contain at least 8 characters."
            raise ValueError(msg)
        if not any(char.isupper() for char in value):
            msg = "Password must contain at least one uppercase letter."
            raise ValueError(msg)
        if not any(char.isdigit() for char in value):
            msg = "Password must contain at least one number."
            raise ValueError(msg)
        if SPECIAL_CHARACTER_PATTERN.search(value) is None:
            msg = "Password must contain at least one special character."
            raise ValueError(msg)
        return value


class UserRegister(NameValidationMixin, PasswordValidationMixin, BaseModel):
    """Payload used to register a user."""

    email: EmailStr
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str
    first_name: str = Field(max_length=50)
    last_name: str = Field(max_length=50)


class UserLogin(BaseModel):
    """Payload used to authenticate a user."""

    email: EmailStr
    password: str


class UserUpdate(NameValidationMixin, BaseModel):
    """Payload used to update user profile fields."""

    first_name: str | None = Field(default=None, max_length=50)
    last_name: str | None = Field(default=None, max_length=50)


class PasswordChange(PasswordValidationMixin, BaseModel):
    """Payload used to change a user's password."""

    current_password: str
    new_password: str


class RefreshTokenRequest(BaseModel):
    """Payload used to request a token refresh."""

    refresh_token: str


class UserRead(BaseModel):
    """Public user representation."""

    id: UUID
    email: EmailStr
    username: str
    first_name: str
    last_name: str
    role: UserRole
    is_active: bool
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """Auth token response payload."""

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
