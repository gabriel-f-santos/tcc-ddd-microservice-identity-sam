# src/identity/application/dto/auth_dto.py
"""Authentication DTOs."""

from datetime import datetime
from typing import Optional

from pydantic import EmailStr, Field

from src.shared.application.dto.base import BaseDTO


class LoginDTO(BaseDTO):
    """DTO for user login."""
    email: EmailStr
    senha: str = Field(..., min_length=1)


class TokenResponseDTO(BaseDTO):
    """DTO for token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    user_name: str
    permissions: list[str]


class RefreshTokenDTO(BaseDTO):
    """DTO for token refresh."""
    refresh_token: str


class ChangePasswordDTO(BaseDTO):
    """DTO for password change."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6, max_length=100)