from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.exceptions import AppException

engine = create_async_engine(settings.DATABASE_URL)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session for request-scoped usage."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except AppException:
            await session.commit()
            raise
        except Exception:
            await session.rollback()
            raise
