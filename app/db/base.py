import sys

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""


if "app.auth.models" not in sys.modules:
    from app.auth.models import RefreshToken, User  # noqa: E402,F401
