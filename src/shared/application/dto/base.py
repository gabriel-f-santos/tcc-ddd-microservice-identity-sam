# src/shared/application/dto/base.py
"""Base DTO classes."""

from abc import ABC
from datetime import datetime
from typing import Any, Dict
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class BaseDTO(BaseModel, ABC):
    """Base class for DTOs."""
    
    model_config = ConfigDict(
        from_attributes=True,
        validate_assignment=True,
        arbitrary_types_allowed=True,
        json_encoders={
            UUID: str,
            datetime: lambda v: v.isoformat(),
        }
    )


class CreateDTO(BaseDTO):
    """Base class for creation DTOs."""
    pass


class UpdateDTO(BaseDTO):
    """Base class for update DTOs."""
    pass


class ResponseDTO(BaseDTO):
    """Base class for response DTOs."""
    id: UUID
    created_at: datetime
    updated_at: datetime
