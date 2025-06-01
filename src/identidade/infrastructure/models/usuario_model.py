# src/identity/infrastructure/models/usuario_model.py
"""SQLAlchemy model for Usuario."""

from datetime import datetime
from typing import List
from uuid import UUID

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID, ARRAY
from sqlalchemy.sql import func

from src.shared.infrastructure.database.connection import Base


class UsuarioModel(Base):
    """SQLAlchemy model for Usuario entity."""
    
    __tablename__ = "usuarios"
    __table_args__ = {"schema": "identity"}
    
    id = Column(PGUUID(as_uuid=True), primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    nome = Column(String(255), nullable=False)
    senha_hash = Column(String(255), nullable=False)
    permissoes = Column(ARRAY(String), nullable=False, default=[])
    ativo = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    def __repr__(self) -> str:
        """String representation."""
        return f"<UsuarioModel(id={self.id}, email={self.email}, nome={self.nome})>"
