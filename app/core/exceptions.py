from typing import ClassVar


class AppException(Exception):
    """Base class for domain exceptions."""

    code: ClassVar[str] = "app_error"
    default_message: ClassVar[str] = "Application error."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


class NotFoundError(AppException):
    """Raised when a requested resource does not exist."""

    code = "not_found"
    default_message = "Resource not found."


class ConflictError(AppException):
    """Raised when a request conflicts with existing state."""

    code = "conflict"
    default_message = "Resource conflict."


class UnauthorizedError(AppException):
    """Raised when authentication is missing or invalid."""

    code = "unauthorized"
    default_message = "Unauthorized."


class ForbiddenError(AppException):
    """Raised when the authenticated principal cannot perform an action."""

    code = "forbidden"
    default_message = "Forbidden."


class ValidationError(AppException):
    """Raised when domain validation fails."""

    code = "validation_error"
    default_message = "Validation error."
