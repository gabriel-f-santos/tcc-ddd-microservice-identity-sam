# src/shared/infrastructure/database/connection.py
"""Database connection management."""

from typing import AsyncGenerator

import structlog
from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = structlog.get_logger()

# Global variables
async_engine = None
async_session_factory = None
sync_engine = None
sync_session_factory = None


class Base(DeclarativeBase):
    """Base class for all database models."""
    
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s"
        }
    )


async def init_db(database_url: str) -> None:
    """Initialize database connections."""
    global async_engine, async_session_factory, sync_engine, sync_session_factory
    
    # Convert PostgreSQL URL for async
    async_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
    
    # Async engine for FastAPI
    async_engine = create_async_engine(
        async_url,
        echo=False,
        pool_size=20,
        max_overflow=30,
        pool_timeout=30,
        pool_pre_ping=True
    )
    
    async_session_factory = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    # Sync engine for Alembic migrations
    sync_engine = create_engine(
        database_url,
        echo=False,
        pool_size=20,
        max_overflow=30,
        pool_timeout=30,
        pool_pre_ping=True
    )
    
    sync_session_factory = sessionmaker(
        sync_engine,
        expire_on_commit=False
    )
    
    logger.info("Database connections initialized")


async def close_db() -> None:
    """Close database connections."""
    global async_engine, sync_engine
    
    if async_engine:
        await async_engine.dispose()
        logger.info("Async database connection closed")
    
    if sync_engine:
        sync_engine.dispose()
        logger.info("Sync database connection closed")


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Get async database session."""
    if not async_session_factory:
        raise RuntimeError("Database not initialized")
    
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_sync_session():
    """Get sync database session."""
    if not sync_session_factory:
        raise RuntimeError("Database not initialized")
    
    return sync_session_factory()