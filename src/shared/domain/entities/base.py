# src/shared/domain/entities/base.py
"""Base entity class for domain entities."""

from abc import ABC
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4


class Entity(ABC):
    """Base class for domain entities."""
    
    def __init__(self, id: UUID | None = None):
        self._id = id or uuid4()
    
    @property
    def id(self) -> UUID:
        """Entity unique identifier."""
        return self._id
    
    def __eq__(self, other: Any) -> bool:
        """Check equality based on ID."""
        if not isinstance(other, Entity):
            return False
        return self._id == other._id
    
    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self._id)
    
    def __repr__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(id={self._id})"


class AggregateRoot(Entity):
    """Base class for aggregate roots."""
    
    def __init__(self, id: UUID | None = None):
        super().__init__(id)
        self._created_at = datetime.utcnow()
        self._updated_at = datetime.utcnow()
    
    @property
    def created_at(self) -> datetime:
        """When the aggregate was created."""
        return self._created_at
    
    @property
    def updated_at(self) -> datetime:
        """When the aggregate was last updated."""
        return self._updated_at
    
    def mark_as_updated(self) -> None:
        """Mark aggregate as updated."""
        self._updated_at = datetime.utcnow()
