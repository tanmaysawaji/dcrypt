class CryptError(Exception):
    """Base class for all cryptography exceptions"""

    pass


class KeyGenerationError(CryptError):
    """Raised when there is an error generating keys."""

    pass


class KeyExchangeError(CryptError):
    """Raised when there is an error during the key exchange process."""

    pass
