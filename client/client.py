import requests
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# Generate client's key pair
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Serialize client's public key to raw point bytes
client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.X962,  # Corrected import
    format=serialization.PublicFormat.UncompressedPoint,  # Corrected import
)

# Base64-encode the public key to send in JSON
client_public_key_b64 = base64.b64encode(client_public_key_bytes).decode()

# Send public key to server
response = requests.post(
    "http://127.0.0.1:8000/connect", json={"public_key": client_public_key_b64}
)

# Parse server's response
if response.status_code == 200:
    server_public_key_b64 = response.json()["server_public_key"]
    server_public_key_bytes = base64.b64decode(server_public_key_b64)

    # Load server's public key
    server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), server_public_key_bytes
    )

    # Derive shared secret
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

    # Derive a symmetric key using HKDF
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

    print(f"Shared symmetric key: {symmetric_key.hex()}")

else:
    print(f"Error: {response.json()}")
