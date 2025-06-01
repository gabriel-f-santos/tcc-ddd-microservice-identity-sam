# src/handlers/user_handler.py
"""User management Lambda handlers."""

from uuid import UUID
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from src.utils.lambda_decorators import (
    lambda_handler, with_auth, require_permission, validate_request_body,
    success_response, created_response, no_content_response, LambdaException
)
from src.identidade.application.services.usuario_application_service import UsuarioApplicationService
from src.identidade.application.dto.usuario_dto import (
    UsuarioCreateDTO, UsuarioUpdateDTO
)
from src.identidade.domain.entities.usuario import Usuario
from src.shared.domain.exceptions.base import ValidationException, BusinessRuleException

logger = structlog.get_logger()


@lambda_handler
@with_auth
@require_permission("usuarios:write")
@validate_request_body(UsuarioCreateDTO)
async def create_user_handler(
    event, context, body, path_params, query_params,
    current_user: Usuario, db: AsyncSession, dto: UsuarioCreateDTO
):
    """Handler for creating new user."""
    try:
        user_service = UsuarioApplicationService(db)
        user_response = await user_service.create_user(dto)
        
        return created_response(user_response.dict())
        
    except ValidationException as e:
        raise LambdaException(400, e.message)
    except BusinessRuleException as e:
        raise LambdaException(409, e.message)


@lambda_handler
@with_auth
@require_permission("usuarios:read")
async def get_users_handler(
    event, context, body, path_params, query_params,
    current_user: Usuario, db: AsyncSession
):
    """Handler for getting users with pagination."""
    try:
        # Parse pagination parameters
        skip = int(query_params.get("skip", 0))
        limit = int(query_params.get("limit", 20))
        
        # Validate pagination
        if skip < 0:
            raise LambdaException(400, "skip must be >= 0")
        if limit < 1 or limit > 100:
            raise LambdaException(400, "limit must be between 1 and 100")
        
        user_service = UsuarioApplicationService(db)
        users_response = await user_service.get_users(skip, limit)
        
        return success_response(users_response.dict())
        
    except LambdaException:
        raise
    except Exception as e:
        logger.error("Get users error", error=str(e))
        raise LambdaException(500, "Internal server error")


@lambda_handler
@with_auth
@require_permission("usuarios:read")
async def get_user_handler(
    event, context, body, path_params, query_params,
    current_user: Usuario, db: AsyncSession
):
    """Handler for getting user by ID."""
    try:
        user_id = path_params.get("user_id")
        if not user_id:
            raise LambdaException(400, "user_id is required")
        
        # Validate UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            raise LambdaException(400, "Invalid user_id format")
        
        user_service = UsuarioApplicationService(db)
        user_response = await user_service.get_user_by_id(user_uuid)
        
        if not user_response:
            raise LambdaException(404, "User not found")
        
        return success_response(user_response.dict())
        
    except LambdaException:
        raise
    except Exception as e:
        logger.error("Get user error", user_id=user_id, error=str(e))
        raise LambdaException(500, "Internal server error")


@lambda_handler
@with_auth
@require_permission("usuarios:write")
@validate_request_body(UsuarioUpdateDTO)
async def update_user_handler(
    event, context, body, path_params, query_params,
    current_user: Usuario, db: AsyncSession, dto: UsuarioUpdateDTO
):
    """Handler for updating user."""
    try:
        user_id = path_params.get("user_id")
        if not user_id:
            raise LambdaException(400, "user_id is required")
        
        # Validate UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            raise LambdaException(400, "Invalid user_id format")
        
        user_service = UsuarioApplicationService(db)
        user_response = await user_service.update_user(user_uuid, dto)
        
        if not user_response:
            raise LambdaException(404, "User not found")
        
        return success_response(user_response.dict())
        
    except LambdaException:
        raise
    except ValidationException as e:
        raise LambdaException(400, e.message)
    except BusinessRuleException as e:
        raise LambdaException(409, e.message)
    except Exception as e:
        logger.error("Update user error", user_id=user_id, error=str(e))
        raise LambdaException(500, "Internal server error")


@lambda_handler
@with_auth
@require_permission("usuarios:delete")
async def delete_user_handler(
    event, context, body, path_params, query_params,
    current_user: Usuario, db: AsyncSession
):
    """Handler for deleting user."""
    try:
        user_id = path_params.get("user_id")
        if not user_id:
            raise LambdaException(400, "user_id is required")
        
        # Validate UUID
        try:
            user_uuid = UUID(user_id)
        except ValueError:
            raise LambdaException(400, "Invalid user_id format")
        
        user_service = UsuarioApplicationService(db)
        success = await user_service.delete_user(user_uuid)
        
        if not success:
            raise LambdaException(404, "User not found")
        
        return no_content_response()
        
    except LambdaException:
        raise
    except Exception as e:
        logger.error("Delete user error", user_id=user_id, error=str(e))
        raise LambdaException(500, "Internal server error")


# src/handlers/health_handler.py
"""Health check Lambda handler."""

from src.utils.lambda_decorators import lambda_handler, success_response


@lambda_handler
async def health_check_handler(event, context, body, path_params, query_params):
    """Health check endpoint."""
    return success_response({
        "status": "healthy",
        "service": "accounts-service",
        "version": "1.0.0"
    })