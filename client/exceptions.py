class ClientError(Exception):
    """Base class for all client-related errors."""

    pass


class ServerConnectionError(ClientError):
    """Raised when there is an error connecting to the server."""

    pass
