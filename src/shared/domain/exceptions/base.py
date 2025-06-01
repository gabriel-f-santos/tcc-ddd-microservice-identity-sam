# src/shared/domain/exceptions/base.py
"""Base domain exceptions."""


class DomainException(Exception):
    """Base exception for domain layer."""
    
    def __init__(self, message: str, error_code: str | None = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__


class ValidationException(DomainException):
    """Exception for domain validation errors."""
    pass


class BusinessRuleException(DomainException):
    """Exception for business rule violations."""
    pass


class NotFoundException(DomainException):
    """Exception for entity not found."""
    pass