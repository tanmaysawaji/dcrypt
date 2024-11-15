from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import base64

app = FastAPI()


class ClientPublicKey(BaseModel):
    public_key: str  # Base64-encoded raw public key bytes


# Generate server key pair
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# Store shared keys for each client
client_shared_keys = {}


@app.post("/connect")
async def connect(client_key: ClientPublicKey):
    try:
        # Decode client's public key from Base64
        client_public_key_bytes = base64.b64decode(client_key.public_key)

        # Load the client's public key from raw bytes
        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), client_public_key_bytes
        )

        # Derive the shared secret
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

        # Derive a symmetric key using HKDF
        symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_secret)
        print(f"Shared symmetric key: {symmetric_key.hex()}")

        # Store the key for the client
        client_identifier = client_key.public_key  # Use public key as an identifier
        client_shared_keys[client_identifier] = symmetric_key

        # Respond with the server's public key in raw bytes (Base64-encoded)
        server_public_key_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.X962,  # Corrected import
            format=serialization.PublicFormat.UncompressedPoint,  # Corrected import
        )
        return {"server_public_key": base64.b64encode(server_public_key_bytes).decode()}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")
