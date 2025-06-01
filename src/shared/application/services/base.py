# src/shared/application/services/base.py
"""Base application service."""

from abc import ABC
from typing import Generic, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar('T')


class BaseApplicationService(ABC, Generic[T]):
    """Base application service class."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
