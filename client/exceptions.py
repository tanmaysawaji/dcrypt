class ClientError(Exception):
    """Base class for all client-related errors."""

    pass


class KeyGenerationError(ClientError):
    """Raised when there is an error generating keys."""

    pass


class ServerConnectionError(ClientError):
    """Raised when there is an error connecting to the server."""

    pass


class KeyExchangeError(ClientError):
    """Raised when there is an error during the key exchange process."""

    pass
