# src/identity/application/dto/usuario_dto.py
"""User DTOs."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import EmailStr, Field

from src.shared.application.dto.base import BaseDTO, CreateDTO, UpdateDTO, ResponseDTO


class UsuarioCreateDTO(CreateDTO):
    """DTO for creating users."""
    email: EmailStr
    nome: str = Field(..., min_length=1, max_length=255)
    senha: str = Field(..., min_length=6, max_length=100)
    permissoes: List[str] = Field(default_factory=list)
    ativo: bool = True


class UsuarioUpdateDTO(UpdateDTO):
    """DTO for updating users."""
    nome: Optional[str] = Field(None, min_length=1, max_length=255)
    email: Optional[EmailStr] = None
    permissoes: Optional[List[str]] = None
    ativo: Optional[bool] = None


class UsuarioResponseDTO(ResponseDTO):
    """DTO for user responses."""
    email: str
    nome: str
    permissoes: List[str]
    ativo: bool


class UsuarioListResponseDTO(BaseDTO):
    """DTO for user list responses."""
    usuarios: List[UsuarioResponseDTO]
    total: int
    page: int
    page_size: int
