# src/identity/infrastructure/repositories/sqlalchemy_usuario_repository.py
"""SQLAlchemy implementation of UsuarioRepository."""

from typing import List, Optional
from uuid import UUID

import structlog
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.identidade.domain.entities.usuario import Usuario
from src.identidade.domain.repositories.usuario_repository import UsuarioRepository
from src.identidade.domain.value_objects.email import Email
from src.identidade.domain.value_objects.permissao import Permissao
from src.identidade.infrastructure.models.usuario_model import UsuarioModel

logger = structlog.get_logger()


class SqlAlchemyUsuarioRepository(UsuarioRepository):
    """SQLAlchemy implementation of UsuarioRepository."""
    
    def __init__(self, db: AsyncSession):
        super().__init__(db)
    
    async def get_by_id(self, id: UUID) -> Optional[Usuario]:
        """Get user by ID."""
        try:
            query = select(UsuarioModel).where(UsuarioModel.id == id)
            result = await self.db.execute(query)
            model = result.scalar_one_or_none()
            
            if model is None:
                return None
            
            return self._model_to_entity(model)
            
        except Exception as e:
            logger.error("Error getting user by ID", user_id=str(id), error=str(e))
            raise
    
    async def get_by_email(self, email: Email | str) -> Optional[Usuario]:
        """Get user by email."""
        try:
            email_str = email.valor if isinstance(email, Email) else email
            
            query = select(UsuarioModel).where(UsuarioModel.email == email_str)
            result = await self.db.execute(query)
            model = result.scalar_one_or_none()
            
            if model is None:
                return None
            
            return self._model_to_entity(model)
            
        except Exception as e:
            logger.error("Error getting user by email", email=str(email), error=str(e))
            raise
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Usuario]:
        """Get all users with pagination."""
        try:
            query = (
                select(UsuarioModel)
                .offset(skip)
                .limit(limit)
                .order_by(UsuarioModel.created_at.desc())
            )
            result = await self.db.execute(query)
            models = result.scalars().all()
            
            return [self._model_to_entity(model) for model in models]
            
        except Exception as e:
            logger.error("Error getting all users", skip=skip, limit=limit, error=str(e))
            raise
    
    async def get_active_users(self, skip: int = 0, limit: int = 100) -> List[Usuario]:
        """Get active users."""
        try:
            query = (
                select(UsuarioModel)
                .where(UsuarioModel.ativo == True)
                .offset(skip)
                .limit(limit)
                .order_by(UsuarioModel.created_at.desc())
            )
            result = await self.db.execute(query)
            models = result.scalars().all()
            
            return [self._model_to_entity(model) for model in models]
            
        except Exception as e:
            logger.error("Error getting active users", skip=skip, limit=limit, error=str(e))
            raise
    
    async def create(self, entity: Usuario) -> Usuario:
        """Create new user."""
        try:
            model = self._entity_to_model(entity)
            self.db.add(model)
            await self.db.flush()
            await self.db.refresh(model)
            
            logger.info("User created", user_id=str(model.id), email=model.email)
            return self._model_to_entity(model)
            
        except Exception as e:
            logger.error("Error creating user", email=entity.email.valor, error=str(e))
            await self.db.rollback()
            raise
    
    async def update(self, entity: Usuario) -> Usuario:
        """Update existing user."""
        try:
            query = select(UsuarioModel).where(UsuarioModel.id == entity.id)
            result = await self.db.execute(query)
            model = result.scalar_one_or_none()
            
            if model is None:
                raise ValueError(f"User not found: {entity.id}")
            
            # Update fields
            model.email = entity.email.valor
            model.nome = entity.nome
            model.senha_hash = entity.senha_hash
            model.permissoes = [p.to_string() for p in entity.permissoes]
            model.ativo = entity.ativo
            model.updated_at = entity.updated_at
            
            await self.db.flush()
            await self.db.refresh(model)
            
            logger.info("User updated", user_id=str(model.id), email=model.email)
            return self._model_to_entity(model)
            
        except Exception as e:
            logger.error("Error updating user", user_id=str(entity.id), error=str(e))
            await self.db.rollback()
            raise
    
    async def delete(self, id: UUID) -> bool:
        """Delete user by ID."""
        try:
            query = select(UsuarioModel).where(UsuarioModel.id == id)
            result = await self.db.execute(query)
            model = result.scalar_one_or_none()
            
            if model is None:
                return False
            
            await self.db.delete(model)
            await self.db.flush()
            
            logger.info("User deleted", user_id=str(id))
            return True
            
        except Exception as e:
            logger.error("Error deleting user", user_id=str(id), error=str(e))
            await self.db.rollback()
            raise
    
    async def count(self) -> int:
        """Count total users."""
        try:
            query = select(func.count(UsuarioModel.id))
            result = await self.db.execute(query)
            return result.scalar_one()
            
        except Exception as e:
            logger.error("Error counting users", error=str(e))
            raise
    
    async def email_exists(self, email: Email | str) -> bool:
        """Check if email already exists."""
        try:
            email_str = email.valor if isinstance(email, Email) else email
            
            query = select(func.count(UsuarioModel.id)).where(UsuarioModel.email == email_str)
            result = await self.db.execute(query)
            count = result.scalar_one()
            
            return count > 0
            
        except Exception as e:
            logger.error("Error checking email existence", email=str(email), error=str(e))
            raise
    
    def _entity_to_model(self, entity: Usuario) -> UsuarioModel:
        """Convert entity to SQLAlchemy model."""
        return UsuarioModel(
            id=entity.id,
            email=entity.email.valor,
            nome=entity.nome,
            senha_hash=entity.senha_hash,
            permissoes=[p.to_string() for p in entity.permissoes],
            ativo=entity.ativo,
            created_at=entity.created_at,
            updated_at=entity.updated_at
        )
    
    def _model_to_entity(self, model: UsuarioModel) -> Usuario:
        """Convert SQLAlchemy model to entity."""
        permissoes = [
            Permissao.from_string(p) for p in (model.permissoes or [])
        ]
        
        entity = Usuario(
            id=model.id,
            email=Email(model.email),
            nome=model.nome,
            senha_hash=model.senha_hash,
            permissoes=permissoes,
            ativo=model.ativo
        )
        
        # Set timestamps manually since they're managed by the aggregate
        entity._created_at = model.created_at
        entity._updated_at = model.updated_at
        
        return entity