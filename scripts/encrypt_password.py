#!/usr/bin/env python3
"""
Helper script to encrypt password using RSA-OAEP for oxmon login.
Usage: python3 encrypt_password.py <public_key_pem> <password>
"""

import sys
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def encrypt_password(public_key_pem: str, password: str) -> str:
    """Encrypt password using RSA-OAEP with the provided public key."""
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )

    # Encrypt the password
    encrypted = public_key.encrypt(
        password.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return base64 encoded result
    return base64.b64encode(encrypted).decode('utf-8')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 encrypt_password.py <public_key_pem> <password>", file=sys.stderr)
        sys.exit(1)

    public_key_pem = sys.argv[1]
    password = sys.argv[2]

    try:
        encrypted = encrypt_password(public_key_pem, password)
        print(encrypted)
    except Exception as e:
        print(f"Error encrypting password: {e}", file=sys.stderr)
        sys.exit(1)
