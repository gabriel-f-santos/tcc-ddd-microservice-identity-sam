# src/identity/domain/value_objects/email.py
"""Email value object."""

import re
from typing import Any

from src.shared.domain.value_objects.base import ValueObject
from src.shared.domain.exceptions.base import ValidationException


class Email(ValueObject):
    """Email address value object."""
    
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    def __init__(self, valor: str):
        if not valor:
            raise ValidationException("Email cannot be empty")
        
        valor = valor.strip().lower()
        if not self.EMAIL_PATTERN.match(valor):
            raise ValidationException(f"Invalid email format: {valor}")
        
        self.valor = valor
    
    def __str__(self) -> str:
        """String representation."""
        return self.valor
