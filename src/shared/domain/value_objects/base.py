# src/shared/domain/value_objects/base.py
"""Base value object class."""

from abc import ABC
from typing import Any


class ValueObject(ABC):
    """Base class for value objects."""
    
    def __eq__(self, other: Any) -> bool:
        """Check equality based on all attributes."""
        if not isinstance(other, self.__class__):
            return False
        
        return self.__dict__ == other.__dict__
    
    def __hash__(self) -> int:
        """Hash based on all attributes."""
        return hash(tuple(sorted(self.__dict__.items())))
    
    def __repr__(self) -> str:
        """String representation."""
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"
