class ResolverIdentityError(Exception):
    """Base error for resolver identity prototype."""


class VerificationError(ResolverIdentityError):
    """Raised when a resolver cannot be verified."""


class NotFoundError(ResolverIdentityError):
    """Raised when an indexed object or anchor is missing."""
