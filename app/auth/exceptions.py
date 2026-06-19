from app.core.exceptions import ConflictError, ForbiddenError, UnauthorizedError


class InvalidCredentialsError(UnauthorizedError):
    """Raised when login credentials are invalid."""

    code = "INVALID_CREDENTIALS"
    default_message = "Invalid credentials."


class UserAlreadyExistsError(ConflictError):
    """Raised when attempting to create an already registered user."""

    code = "USER_ALREADY_EXISTS"
    default_message = "User already exists."


class InactiveUserError(ForbiddenError):
    """Raised when an inactive user attempts to authenticate."""

    code = "INACTIVE_USER"
    default_message = "Inactive user."


class InvalidTokenError(UnauthorizedError):
    """Raised when a token cannot be decoded or validated."""

    code = "INVALID_TOKEN"
    default_message = "Invalid token."


class TokenExpiredError(UnauthorizedError):
    """Raised when a token is expired."""

    code = "TOKEN_EXPIRED"
    default_message = "Token has expired."


class TokenRevokedError(UnauthorizedError):
    """Raised when a refresh token has already been revoked."""

    code = "TOKEN_REVOKED"
    default_message = "Token has been revoked."


class InsufficientPermissionsError(ForbiddenError):
    """Raised when a user does not have the required role or permission."""

    code = "INSUFFICIENT_PERMISSIONS"
    default_message = "Insufficient permissions."
