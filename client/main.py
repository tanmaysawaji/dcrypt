from client.api.communication import initiate_connection
from client.exceptions import ClientError

if __name__ == "__main__":
    """
    Entry point for the client application. Connects to the server and establishes encryption.
    """
    server_url = "http://127.0.0.1:8000"
    try:
        symmetric_key = initiate_connection(server_url)
    except Exception as e:
        raise ClientError(f"Error: {e}")
    print(f"Symmetric key: {symmetric_key.hex()}")

# Usage: python -m client.main
