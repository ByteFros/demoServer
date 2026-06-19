from app.core.exceptions import ConflictError, ForbiddenError, UnauthorizedError


class InvalidCredentialsError(UnauthorizedError):
    """Raised when login credentials are invalid."""

    code = "invalid_credentials"
    default_message = "Invalid credentials."


class UserAlreadyExistsError(ConflictError):
    """Raised when attempting to create an already registered user."""

    code = "user_already_exists"
    default_message = "User already exists."


class InactiveUserError(ForbiddenError):
    """Raised when an inactive user attempts to authenticate."""

    code = "inactive_user"
    default_message = "Inactive user."


class InvalidTokenError(UnauthorizedError):
    """Raised when a token cannot be decoded or validated."""

    code = "invalid_token"
    default_message = "Invalid token."


class TokenExpiredError(UnauthorizedError):
    """Raised when a token is expired."""

    code = "token_expired"
    default_message = "Token has expired."


class TokenRevokedError(UnauthorizedError):
    """Raised when a refresh token has already been revoked."""

    code = "token_revoked"
    default_message = "Token has been revoked."


class InsufficientPermissionsError(ForbiddenError):
    """Raised when a user does not have the required role or permission."""

    code = "insufficient_permissions"
    default_message = "Insufficient permissions."
