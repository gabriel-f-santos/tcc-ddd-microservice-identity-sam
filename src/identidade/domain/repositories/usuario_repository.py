# src/identity/domain/repositories/usuario_repository.py
"""User repository interface."""

from abc import abstractmethod
from typing import Optional, List
from uuid import UUID

from src.shared.infrastructure.repositories.base import BaseRepository
from src.identidade.domain.entities.usuario import Usuario
from src.identidade.domain.value_objects.email import Email


class UsuarioRepository(BaseRepository[Usuario]):
    """User repository interface."""
    
    @abstractmethod
    async def get_by_email(self, email: Email | str) -> Optional[Usuario]:
        """Get user by email."""
        pass
    
    @abstractmethod
    async def get_active_users(self, skip: int = 0, limit: int = 100) -> List[Usuario]:
        """Get active users."""
        pass
    
    @abstractmethod
    async def email_exists(self, email: Email | str) -> bool:
        """Check if email already exists."""
        pass