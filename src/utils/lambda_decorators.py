# src/utils/lambda_decorators.py
"""Decorators para substituir FastAPI Depends em Lambda functions."""

import json
import functools
from typing import Dict, Any, Callable, Optional
from dataclasses import dataclass

import structlog
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import get_settings
from src.shared.infrastructure.database.connection import get_async_session, async_session_factory, init_db
from src.identidade.infrastructure.repositories.sqlalchemy_usuario_repository import (
    SqlAlchemyUsuarioRepository
)
from src.identidade.domain.entities.usuario import Usuario

logger = structlog.get_logger()
settings = get_settings()


@dataclass
class LambdaResponse:
    """Classe para padronizar respostas Lambda."""
    status_code: int
    body: Dict[str, Any]
    headers: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        response = {
            "statusCode": self.status_code,
            "body": json.dumps(self.body, default=str),
            "headers": self.headers or {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type,Authorization"
            }
        }
        return response


class LambdaException(Exception):
    """Exception customizada para Lambda com status code."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def lambda_handler(func: Callable) -> Callable:
    """
    Decorator principal que converte função async em Lambda handler.
    Substitui o padrão FastAPI route.
    """
    @functools.wraps(func)
    def wrapper(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        import asyncio
        
        async def async_wrapper():
            try:
                # Parse do body se existir
                body = {}
                if event.get("body"):
                    body = json.loads(event["body"])
                
                # Parse dos path parameters
                path_params = event.get("pathParameters") or {}
                
                # Parse dos query parameters
                query_params = event.get("queryStringParameters") or {}
                
                # Executar função ASYNC
                result = await func(event, context, body, path_params, query_params)
                
                # Se retornou LambdaResponse, converter
                if isinstance(result, LambdaResponse):
                    return result.to_dict()
                
                # Se retornou dict simples, wrap em LambdaResponse
                return LambdaResponse(200, result).to_dict()
                
            except LambdaException as e:
                return LambdaResponse(
                    status_code=e.status_code,
                    body={"detail": e.detail}
                ).to_dict()
                
            except Exception as e:
                logger.error("Lambda handler error", error=str(e))
                return LambdaResponse(
                    status_code=500,
                    body={"detail": "Internal server error"}
                ).to_dict()
        
        # Executar função async usando asyncio
        return asyncio.run(async_wrapper())
    
    return wrapper


def with_database(func: Callable) -> Callable:
    """
    Decorator que injeta sessão do banco.
    Substitui Depends(get_db).
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        if not async_session_factory:
            await init_db(settings.database_url)
        async for db_session in get_async_session():
            try:
                # Adiciona db_session aos kwargs
                kwargs['db'] = db_session
                result = await func(*args, **kwargs)
                await db_session.commit()
                return result
            except Exception as e:
                await db_session.rollback()
                raise e
            finally:
                await db_session.close()
    
    return wrapper


def with_auth(func: Callable) -> Callable:
    """
    Decorator que valida autenticação.
    Substitui Depends(get_current_user).
    """
    @functools.wraps(func)
    async def wrapper(event: Dict[str, Any], context: Any, *args, **kwargs):
        # Extrair token do header Authorization
        headers = event.get("headers", {})
        auth_header = headers.get("Authorization") or headers.get("authorization")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            raise LambdaException(401, "Authorization header required")
        
        token = auth_header.split(" ")[1]
        
        try:
            # Decode JWT token
            payload = jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm]
            )
            
            user_id = payload.get("sub")
            if not user_id:
                raise LambdaException(401, "Invalid token")
                
        except JWTError as e:
            logger.warning("JWT decode error", error=str(e))
            raise LambdaException(401, "Invalid token")
        
        # Buscar usuário no banco
        # Nota: Precisamos da sessão DB aqui
        async for db_session in get_async_session():
            try:
                user_repo = SqlAlchemyUsuarioRepository(db_session)
                user = await user_repo.get_by_id(user_id)
                
                if not user:
                    raise LambdaException(401, "User not found")
                
                if not user.ativo:
                    raise LambdaException(401, "Inactive user")
                
                # Adiciona usuário aos kwargs
                kwargs['current_user'] = user
                kwargs['db'] = db_session
                
                result = await func(event, context, *args, **kwargs)
                await db_session.commit()
                return result
                
            except LambdaException:
                raise
            except Exception as e:
                await db_session.rollback()
                logger.error("Auth error", error=str(e))
                raise LambdaException(500, "Authentication error")
            finally:
                await db_session.close()
    
    return wrapper


def require_permission(permission: str):
    """
    Decorator factory para verificar permissões.
    Substitui Depends(require_permission("permission")).
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            
            if not current_user:
                raise LambdaException(401, "Authentication required")
            
            # Verificar permissões
            user_permissions = [p.to_string() for p in current_user.permissoes]
            
            if permission not in user_permissions and "admin:*" not in user_permissions:
                raise LambdaException(403, f"Permission required: {permission}")
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def validate_request_body(dto_class):
    """
    Decorator para validar e converter body para DTO.
    Substitui validação automática do FastAPI.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(event, context, body, *args, **kwargs):
            try:
                # Criar instância do DTO a partir do body
                dto_instance = dto_class(**body)
                kwargs['dto'] = dto_instance
                return await func(event, context, body, *args, **kwargs)
            except Exception as e:
                raise LambdaException(400, f"Invalid request body: {str(e)}")
        
        return wrapper
    return decorator


# Utility functions para responses comuns
def success_response(data: Any, status_code: int = 200) -> LambdaResponse:
    """Resposta de sucesso padrão."""
    return LambdaResponse(status_code, data)


def error_response(message: str, status_code: int = 400) -> LambdaResponse:
    """Resposta de erro padrão."""
    return LambdaResponse(status_code, {"detail": message})


def created_response(data: Any) -> LambdaResponse:
    """Resposta para recursos criados."""
    return LambdaResponse(201, data)


def no_content_response() -> LambdaResponse:
    """Resposta sem conteúdo."""
    return LambdaResponse(204, {})