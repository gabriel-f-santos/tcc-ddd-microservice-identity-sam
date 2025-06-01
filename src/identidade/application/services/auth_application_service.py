# src/identity/application/services/auth_application_service.py
"""Authentication application service."""

from datetime import datetime, timedelta
from typing import Optional

import structlog
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import get_settings
from src.shared.application.services.base import BaseApplicationService
from src.shared.domain.exceptions.base import ValidationException, BusinessRuleException
from src.identidade.domain.entities.usuario import Usuario
from src.identidade.domain.value_objects.email import Email
from src.identidade.infrastructure.repositories.sqlalchemy_usuario_repository import SqlAlchemyUsuarioRepository
from src.identidade.application.dto.auth_dto import LoginDTO, TokenResponseDTO, ChangePasswordDTO

logger = structlog.get_logger()
settings = get_settings()


class AuthApplicationService(BaseApplicationService[Usuario]):
    """Authentication application service."""
    
    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self.usuario_repository = SqlAlchemyUsuarioRepository(db)
    
    async def login(self, login_dto: LoginDTO) -> TokenResponseDTO:
        """Authenticate user and return token."""
        try:
            # Get user by email
            user = await self.usuario_repository.get_by_email(login_dto.email)
            
            if user is None:
                raise ValidationException("Invalid email or password")
            
            # Check if user is active
            if not user.ativo:
                raise BusinessRuleException("User account is deactivated")
            
            # Verify password
            if not user.verify_password(login_dto.senha):
                raise ValidationException("Invalid email or password")
            
            # Generate token
            token_data = {
                "sub": str(user.id),
                "email": user.email.valor,
                "name": user.nome,
                "permissions": [p.to_string() for p in user.permissoes],
                "exp": datetime.utcnow() + timedelta(minutes=settings.jwt_access_token_expire_minutes)
            }
            
            access_token = jwt.encode(
                token_data,
                settings.jwt_secret_key,
                algorithm=settings.jwt_algorithm
            )
            
            logger.info("User logged in", user_id=str(user.id), email=user.email.valor)
            
            return TokenResponseDTO(
                access_token=access_token,
                token_type="bearer",
                expires_in=settings.jwt_access_token_expire_minutes * 60,
                user_id=str(user.id),
                user_name=user.nome,
                permissions=[p.to_string() for p in user.permissoes]
            )
            
        except Exception as e:
            logger.error("Login failed", email=login_dto.email, error=str(e))
            raise
    
    async def change_password(
        self, 
        user_id: str, 
        change_password_dto: ChangePasswordDTO
    ) -> bool:
        """Change user password."""
        try:
            # Get user
            user = await self.usuario_repository.get_by_id(user_id)
            
            if user is None:
                raise ValidationException("User not found")
            
            # Verify current password
            if not user.verify_password(change_password_dto.current_password):
                raise ValidationException("Current password is incorrect")
            
            # Set new password
            user.set_password(change_password_dto.new_password)
            
            # Save changes
            await self.usuario_repository.update(user)
            await self.db.commit()
            
            logger.info("Password changed", user_id=user_id)
            return True
            
        except Exception as e:
            logger.error("Password change failed", user_id=user_id, error=str(e))
            await self.db.rollback()
            raise
    
    async def verify_token(self, token: str) -> Optional[Usuario]:
        """Verify JWT token and return user."""
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm]
            )
            
            user_id = payload.get("sub")
            if user_id is None:
                return None
            
            user = await self.usuario_repository.get_by_id(user_id)
            return user
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.JWTError as e:
            logger.warning("Invalid token", error=str(e))
            return None
        except Exception as e:
            logger.error("Token verification failed", error=str(e))
            return None
