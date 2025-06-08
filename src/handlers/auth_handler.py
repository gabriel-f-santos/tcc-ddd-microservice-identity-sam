# src/handlers/auth_handler.py
"""Authentication Lambda handlers."""

import asyncio
import json
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from src.utils.lambda_decorators import (
    lambda_handler, with_auth, validate_request_body, 
    success_response, error_response, LambdaException, with_database
)
from src.identidade.application.services.auth_application_service import AuthApplicationService
from src.identidade.application.dto.auth_dto import LoginDTO, ChangePasswordDTO
from src.identidade.domain.entities.usuario import Usuario
from src.shared.domain.exceptions.base import ValidationException, BusinessRuleException
from src.config import get_settings

from jwt import InvalidTokenError

logger = structlog.get_logger()

# Segredo e algoritmo devem ser iguais aos usados no seu AuthApplicationService
JWT_SECRET = get_settings().jwt_secret_key
JWT_ALGO = get_settings().jwt_algorithm



@lambda_handler
@with_database
@validate_request_body(LoginDTO)
async def login_handler(event, context, body, path_params, query_params, db: AsyncSession, dto: LoginDTO):
    """Handler for user login."""
    try:
        auth_service = AuthApplicationService(db)
        token_response = await auth_service.login(dto)
        
        return success_response(token_response.dict())
        
    except ValidationException as e:
        raise LambdaException(401, e.message)
    except BusinessRuleException as e:
        raise LambdaException(403, e.message)


@lambda_handler
@with_auth
@validate_request_body(ChangePasswordDTO)
async def change_password_handler(
    event, context, body, path_params, query_params, 
    current_user: Usuario, db: AsyncSession, dto: ChangePasswordDTO
):
    """Handler for changing user password."""
    try:
        auth_service = AuthApplicationService(db)
        await auth_service.change_password(str(current_user.id), dto)
        
        return success_response({"message": "Password changed successfully"})
        
    except ValidationException as e:
        raise LambdaException(400, e.message)


@lambda_handler
@with_auth
async def get_current_user_handler(
    event, context, body, path_params, query_params,
    current_user: Usuario, db: AsyncSession
):
    """Handler for getting current user info."""
    user_info = {
        "id": str(current_user.id),
        "email": current_user.email.valor,
        "nome": current_user.nome,
        "permissoes": [p.to_string() for p in current_user.permissoes],
        "ativo": current_user.ativo
    }
    
    return success_response(user_info)

# src/handlers/authorizer.py
def generate_policy(principal_id: str, effect: str, resource: str, context: dict):
    """
    Versão mais robusta da policy
    """
    # Extrair o ARN base para criar wildcard
    # arn:aws:execute-api:region:account:api-id/stage/method/resource
    arn_parts = resource.split('/')
    if len(arn_parts) >= 3:
        # Permite acesso a toda a API
        base_arn = '/'.join(arn_parts[:3])  # arn:aws:execute-api:region:account:api-id/stage
        wildcard_resource = f"{base_arn}/*/*"
    else:
        wildcard_resource = resource
    
    auth_response = {
        "principalId": principal_id,
        "context": context,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": wildcard_resource
                }
            ]
        }
    }
    
    return auth_response

@with_database
async def auth_handler_with_db(event, context, db: AsyncSession, token: str = None, method_arn: str = None):
    """
    Lambda Authorizer usando decorator @with_database.
    """
    
    try:
        # ✅ Agora tem acesso ao db via decorator
        auth_service = AuthApplicationService(db)
        
        # Verificar token
        usuario = await auth_service.verify_token(token)
        
        if not usuario or not usuario.ativo:
            raise InvalidTokenError("User not found or inactive")
        
        logger.warning("permissoes: %s", usuario.permissoes)
        
        context_extra = {
            "userId": str(usuario.id),
            "email": usuario.email.valor,
            "permissoes": ",".join([p.to_string() for p in usuario.permissoes]),
        }

        logger.warning("Authorization: %s", context_extra)
        
        policy_response = generate_policy(str(usuario.id), "Allow", method_arn, context_extra)

        logger.warning("Policy response jwt: %s", json.dumps(policy_response, default=str))

        return policy_response
    
    except InvalidTokenError as e:
        logger.error("Token inválido: %s", e)
        return generate_policy("unauthorized", "Deny", method_arn, {})

def auth_handler(event, context):
    """Entry point que converte async para sync."""
    token_str = event.get("authorizationToken", "")
    method_arn = event.get("methodArn")
    
    # 🔍 DEBUG: Log completo do event
    logger.warning("Event completo: %s", json.dumps(event, default=str))
    logger.warning("Method ARN: %s", method_arn)
    
    if not token_str.startswith("Bearer "):
        logger.warning("Authorization header inválido: %s", token_str)
        return generate_policy("unauthorized", "Deny", method_arn, {})
    
    token = token_str.split(" ", 1)[1]
    logger.info("Token recebido: %s", token)
    
    if len(token) == 36 and all(c in "0123456789abcdef-" for c in token.lower()):
        logger.info("Token é um UUID4, possivelmente um internal API key")
    
    if token == get_settings().internal_api_key:
        logger.info("Internal API key detected, allowing access without authentication")
        permissoes = ["admin:*"]
        # 🔧 Policy mais permissiva

        context_extra = {
            "userId": "serviceAuth",
            "email": "service@internal",
            "permissoes": ",".join(permissoes),
        }

        policy_response = generate_policy(
            "internal_api_key", 
            "Allow", 
            method_arn, 
            context_extra
        )
        
        # 🔍 DEBUG: Log da policy response
        logger.warning("Policy response: %s", json.dumps(policy_response, default=str))
        
        return policy_response
    
    logger.info("Token é um JWT, processando autenticação")
    return asyncio.run(auth_handler_with_db(event, context, token=token, method_arn=method_arn))