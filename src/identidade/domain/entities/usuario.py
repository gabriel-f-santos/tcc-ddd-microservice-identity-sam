# src/identity/domain/entities/usuario.py
"""User entity."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from passlib.context import CryptContext

from src.shared.domain.entities.base import AggregateRoot
from src.shared.domain.exceptions.base import ValidationException, BusinessRuleException
from src.identidade.domain.value_objects.email import Email
from src.identidade.domain.value_objects.permissao import Permissao

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Usuario(AggregateRoot):
    """User aggregate root."""
    
    def __init__(
        self,
        email: Email | str,
        nome: str,
        senha_hash: str | None = None,
        permissoes: List[Permissao] | None = None,
        ativo: bool = True,
        id: UUID | None = None
    ):
        super().__init__(id)
        
        # Validate and set email
        if isinstance(email, str):
            email = Email(email)
        self._email = email
        
        # Validate and set name
        if not nome or not nome.strip():
            raise ValidationException("Nome cannot be empty")
        self._nome = nome.strip()
        
        # Set password hash
        self._senha_hash = senha_hash
        
        # Set permissions
        self._permissoes = permissoes or []
        
        # Set status
        self._ativo = ativo
    
    @property
    def email(self) -> Email:
        """User email."""
        return self._email
    
    @property
    def nome(self) -> str:
        """User name."""
        return self._nome
    
    @property
    def senha_hash(self) -> str:
        """Password hash."""
        return self._senha_hash
    
    @property
    def permissoes(self) -> List[Permissao]:
        """User permissions."""
        return self._permissoes.copy()
    
    @property
    def ativo(self) -> bool:
        """User active status."""
        return self._ativo
    
    def set_password(self, senha: str) -> None:
        """Set user password."""
        if not senha or len(senha) < 6:
            raise ValidationException("Password must be at least 6 characters")
        
        self._senha_hash = pwd_context.hash(senha)
        self.mark_as_updated()
    
    def verify_password(self, senha: str) -> bool:
        """Verify password."""
        if not self._senha_hash:
            return False
        return pwd_context.verify(senha, self._senha_hash)
    
    def add_permission(self, permissao: Permissao) -> None:
        """Add permission to user."""
        if permissao not in self._permissoes:
            self._permissoes.append(permissao)
            self.mark_as_updated()
    
    def remove_permission(self, permissao: Permissao) -> None:
        """Remove permission from user."""
        if permissao in self._permissoes:
            self._permissoes.remove(permissao)
            self.mark_as_updated()
    
    def has_permission(self, required_permission: Permissao | str) -> bool:
        """Check if user has required permission."""
        if isinstance(required_permission, str):
            required_permission = Permissao.from_string(required_permission)
        
        return any(
            perm.can_access(required_permission) 
            for perm in self._permissoes
        )
    
    def activate(self) -> None:
        """Activate user."""
        self._ativo = True
        self.mark_as_updated()
    
    def deactivate(self) -> None:
        """Deactivate user."""
        self._ativo = False
        self.mark_as_updated()
    
    def update_name(self, nome: str) -> None:
        """Update user name."""
        if not nome or not nome.strip():
            raise ValidationException("Nome cannot be empty")
        
        self._nome = nome.strip()
        self.mark_as_updated()
    
    def update_email(self, email: Email | str) -> None:
        """Update user email."""
        if isinstance(email, str):
            email = Email(email)
        
        self._email = email
        self.mark_as_updated()