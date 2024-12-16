import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from crypt.exceptions import KeyGenerationError, KeyExchangeError


def generate_keys() -> tuple[EllipticCurvePrivateKey, str]:
    """
    Generate an ECDH key pair and return the private key and base64-encoded public key.

    Returns:
        tuple: (private_key, public_key_base64)

    Raises:
        KeyGenerationError: If key generation fails.
    """
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode()
        return private_key, public_key_b64
    except Exception as e:
        raise KeyGenerationError(f"Failed to generate keys: {e}")


def derive_shared_key(
    private_key: EllipticCurvePrivateKey, remote_public_key_b64: str
) -> bytes:
    """
    Derive a shared symmetric key using ECDH with the server's public key.

    Args:
        private_key (EllipticCurvePrivateKey): Private key.
        server_public_key_b64 (str): Server's base64-encoded public key.

    Returns:
        bytes: Derived shared symmetric key.

    Raises:
        KeyExchangeError: If the shared key derivation fails.
    """
    try:
        remote_public_key_bytes = base64.b64decode(remote_public_key_b64)
        remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), remote_public_key_bytes
        )
        shared_secret = private_key.exchange(ec.ECDH(), remote_public_key)
        shared_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data"
        ).derive(shared_secret)
        return shared_key
    except Exception as e:
        raise KeyExchangeError(f"Failed to derive shared key: {e}")
