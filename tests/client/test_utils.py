import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from client.utils import generate_keys, derive_shared_key
from client.exceptions import KeyGenerationError, KeyExchangeError


def test_generate_keys():
    # Test that generate_keys returns a private key and a valid base64-encoded public key
    private_key, public_key_b64 = generate_keys()
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    assert isinstance(public_key_b64, str)

    # Ensure the public key is properly base64-encoded
    public_key_bytes = base64.b64decode(public_key_b64)
    assert len(public_key_bytes) > 0


def test_derive_shared_key_success():
    # Generate two key pairs for the client and server
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    server_private_key = ec.generate_private_key(ec.SECP256R1())

    # Get the server's public key and encode it in base64
    server_public_key_bytes = server_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    server_public_key_b64 = base64.b64encode(server_public_key_bytes).decode()

    # Derive the shared key
    shared_key = derive_shared_key(client_private_key, server_public_key_b64)
    assert isinstance(shared_key, bytes)
    assert len(shared_key) == 32  # Derived key length is 32 bytes


def test_derive_shared_key_invalid_key():
    # Test invalid base64 public key
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    invalid_public_key = "invalid_key"

    with pytest.raises(KeyExchangeError):
        derive_shared_key(client_private_key, invalid_public_key)
