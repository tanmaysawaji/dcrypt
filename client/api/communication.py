import requests
from crypt.handshake import generate_keys, derive_shared_key
from client.exceptions import ServerConnectionError
from crypt.exceptions import KeyExchangeError


def initiate_connection(server_url: str) -> bytes:
    """
    Initiate a connection to the server, perform a key exchange, and derive a symmetric key.

    Args:
        server_url (str): The server URL.

    Returns:
        bytes: Shared symmetric key.

    Raises:
        ServerConnectionError: If unable to connect to the server.
        KeyExchangeError: If key exchange or shared key derivation fails.
    """

    private_key, public_key_b64 = generate_keys()

    try:
        # Send client request to connect
        response = requests.post(
            f"{server_url}/connect", json={"public_key": public_key_b64}
        )
        response.raise_for_status()

        # Parse response
        server_public_key: str | None = response.json().get("server_public_key")
        if server_public_key is None:
            raise KeyExchangeError("Server did not provide a public key.")

    except requests.exceptions.RequestException as e:
        raise ServerConnectionError(f"Failed to connect to the server: {e}")

    shared_key = derive_shared_key(private_key, server_public_key)
    return shared_key
