# src/identity/application/services/usuario_application_service.py
"""User application service."""

from typing import List, Optional
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from src.shared.application.services.base import BaseApplicationService
from src.shared.domain.exceptions.base import ValidationException, BusinessRuleException
from src.identidade.domain.entities.usuario import Usuario
from src.identidade.domain.value_objects.email import Email
from src.identidade.domain.value_objects.permissao import Permissao
from src.identidade.infrastructure.repositories.sqlalchemy_usuario_repository import SqlAlchemyUsuarioRepository
from src.identidade.application.dto.usuario_dto import (
    UsuarioCreateDTO, 
    UsuarioUpdateDTO, 
    UsuarioResponseDTO,
    UsuarioListResponseDTO
)

logger = structlog.get_logger()


class UsuarioApplicationService(BaseApplicationService[Usuario]):
    """User application service."""
    
    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self.usuario_repository = SqlAlchemyUsuarioRepository(db)
    
    async def create_user(self, create_dto: UsuarioCreateDTO) -> UsuarioResponseDTO:
        """Create new user."""
        try:
            # Check if email already exists
            if await self.usuario_repository.email_exists(create_dto.email):
                raise BusinessRuleException(f"Email already exists: {create_dto.email}")
            
            # Convert permissions
            permissoes = [
                Permissao.from_string(p) for p in create_dto.permissoes
            ]
            
            # Create user entity
            user = Usuario(
                email=Email(create_dto.email),
                nome=create_dto.nome,
                permissoes=permissoes,
                ativo=create_dto.ativo
            )
            
            # Set password
            user.set_password(create_dto.senha)
            
            # Save to repository
            user = await self.usuario_repository.create(user)
            await self.db.commit()
            
            logger.info("User created", user_id=str(user.id), email=user.email.valor)
            
            return self._entity_to_response_dto(user)
            
        except Exception as e:
            logger.error("User creation failed", email=create_dto.email, error=str(e))
            await self.db.rollback()
            raise
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[UsuarioResponseDTO]:
        """Get user by ID."""
        try:
            user = await self.usuario_repository.get_by_id(user_id)
            
            if user is None:
                return None
            
            return self._entity_to_response_dto(user)
            
        except Exception as e:
            logger.error("Error getting user", user_id=str(user_id), error=str(e))
            raise
    
    async def get_users(self, skip: int = 0, limit: int = 100) -> UsuarioListResponseDTO:
        """Get users with pagination."""
        try:
            users = await self.usuario_repository.get_all(skip, limit)
            total = await self.usuario_repository.count()
            
            user_dtos = [self._entity_to_response_dto(user) for user in users]
            
            return UsuarioListResponseDTO(
                usuarios=user_dtos,
                total=total,
                page=skip // limit + 1 if limit > 0 else 1,
                page_size=limit
            )
            
        except Exception as e:
            logger.error("Error getting users", skip=skip, limit=limit, error=str(e))
            raise
    
    async def update_user(
        self, 
        user_id: UUID, 
        update_dto: UsuarioUpdateDTO
    ) -> Optional[UsuarioResponseDTO]:
        """Update user."""
        try:
            user = await self.usuario_repository.get_by_id(user_id)
            
            if user is None:
                return None
            
            # Update fields
            if update_dto.nome is not None:
                user.update_name(update_dto.nome)
            
            if update_dto.email is not None:
                # Check if new email already exists
                if await self.usuario_repository.email_exists(update_dto.email):
                    raise BusinessRuleException(f"Email already exists: {update_dto.email}")
                user.update_email(Email(update_dto.email))
            
            if update_dto.permissoes is not None:
                # Clear existing permissions and add new ones
                user._permissoes = [
                    Permissao.from_string(p) for p in update_dto.permissoes
                ]
                user.mark_as_updated()
            
            if update_dto.ativo is not None:
                if update_dto.ativo:
                    user.activate()
                else:
                    user.deactivate()
            
            # Save changes
            user = await self.usuario_repository.update(user)
            await self.db.commit()
            
            logger.info("User updated", user_id=str(user_id))
            
            return self._entity_to_response_dto(user)
            
        except Exception as e:
            logger.error("User update failed", user_id=str(user_id), error=str(e))
            await self.db.rollback()
            raise
    
    async def delete_user(self, user_id: UUID) -> bool:
        """Delete user."""
        try:
            success = await self.usuario_repository.delete(user_id)
            
            if success:
                await self.db.commit()
                logger.info("User deleted", user_id=str(user_id))
            
            return success
            
        except Exception as e:
            logger.error("User deletion failed", user_id=str(user_id), error=str(e))
            await self.db.rollback()
            raise
    
    def _entity_to_response_dto(self, user: Usuario) -> UsuarioResponseDTO:
        """Convert entity to response DTO."""
        return UsuarioResponseDTO(
            id=user.id,
            email=user.email.valor,
            nome=user.nome,
            permissoes=[p.to_string() for p in user.permissoes],
            ativo=user.ativo,
            created_at=user.created_at,
            updated_at=user.updated_at
        )