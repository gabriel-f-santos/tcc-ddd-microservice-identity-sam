# src/identity/domain/value_objects/permissao.py
"""Permission value object."""

from enum import Enum
from typing import Any

from src.shared.domain.value_objects.base import ValueObject
from src.shared.domain.exceptions.base import ValidationException


class AcaoPermissao(str, Enum):
    """Permission actions."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "*"


class RecursoPermissao(str, Enum):
    """Permission resources."""
    PRODUTOS = "produtos"
    ESTOQUE = "estoque"
    MOVIMENTACOES = "movimentacoes"
    RELATORIOS = "relatorios"
    USUARIOS = "usuarios"
    ADMIN = "admin"


class Permissao(ValueObject):
    """Permission value object."""
    
    def __init__(self, recurso: RecursoPermissao | str, acao: AcaoPermissao | str):
        if isinstance(recurso, str):
            try:
                recurso = RecursoPermissao(recurso)
            except ValueError:
                raise ValidationException(f"Invalid resource: {recurso}")
        
        if isinstance(acao, str):
            try:
                acao = AcaoPermissao(acao)
            except ValueError:
                raise ValidationException(f"Invalid action: {acao}")
        
        self.recurso = recurso
        self.acao = acao
    
    def to_string(self) -> str:
        """Convert to string format."""
        return f"{self.recurso.value}:{self.acao.value}"
    
    @classmethod
    def from_string(cls, permission_str: str) -> "Permissao":
        """Create permission from string."""
        try:
            recurso_str, acao_str = permission_str.split(":", 1)
            return cls(recurso_str, acao_str)
        except ValueError:
            raise ValidationException(f"Invalid permission format: {permission_str}")
    
    def can_access(self, required_permission: "Permissao") -> bool:
        """Check if this permission allows access to required permission."""
        # Admin permissions allow everything
        if self.acao == AcaoPermissao.ADMIN:
            return True
        
        if self.recurso == RecursoPermissao.ADMIN and self.acao == AcaoPermissao.ADMIN:
            return True
        
        # Exact match
        if self.recurso == required_permission.recurso and self.acao == required_permission.acao:
            return True
        
        # Resource admin allows all actions on that resource
        if (self.recurso == required_permission.recurso and 
            self.acao == AcaoPermissao.ADMIN):
            return True
        
        return False
    
    def __str__(self) -> str:
        """String representation."""
        return self.to_string()
