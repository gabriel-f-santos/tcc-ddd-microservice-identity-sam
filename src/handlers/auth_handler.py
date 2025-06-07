# src/handlers/auth_handler.py
"""Authentication Lambda handlers."""

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

logger = structlog.get_logger()


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

import os
import logging
import jwt
from jwt import InvalidTokenError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Segredo e algoritmo devem ser iguais aos usados no seu AuthApplicationService
JWT_SECRET = os.environ["JWT_SECRET_KEY"]
JWT_ALGO = os.environ.get("JWT_ALGO", "HS256")

def generate_policy(principal_id: str, effect: str, resource: str, context: dict):
    """
    Monta o retorno esperado pelo API Gateway Lambda Authorizer:
    {
      "principalId": "...",
      "policyDocument": { ... },
      "context": { ... }
    }
    """
    auth_response = {
        "principalId": principal_id,
        "context": context
    }
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }
        ]
    }
    auth_response["policyDocument"] = policy_document
    return auth_response

def lambda_handler(event, context):
    """
    Espera receber o event com:
      event['type'] == 'TOKEN'
      event['authorizationToken'] == 'TOKEN <jwt>'
      event['methodArn'] == 'arn:aws:execute-api:...'
    """
    token_str = event.get("authorizationToken", "")
    method_arn = event.get("methodArn")
    
    if not token_str.startswith("TOKEN "):
        logger.warning("Authorization header inválido: %s", token_str)
        return generate_policy("unauthorized", "Deny", method_arn, {})
    
    jwt_token = token_str.split(" ", 1)[1]
    
    try:
        auth_service = AuthApplicationService()  # Inicialize conforme necessário

        # Verifica se o JWT é válido
        usuario: Usuario = auth_service.verify_token(jwt_token)
        # Decodifica o JWT e extrai claims
        
        # Contexto extra que ficará disponível no requestContext.authorizer
        context_extra = {
            "userId": usuario.id,
            "email": usuario.email.valor,
            # Strings são obrigatórias no context; arrays podem virar string JSON
            "permissoes": ",".join(usuario.permissoes),
        }
        
        return generate_policy(usuario.id, "Allow", method_arn, context_extra)
    
    except InvalidTokenError as e:
        logger.error("Token inválido: %s", e)
        return generate_policy("unauthorized", "Deny", method_arn, {})
