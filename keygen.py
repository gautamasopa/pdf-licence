"""
keygen.py — Run this ONCE locally to generate your Ed25519 keypair.

Usage:
    python keygen.py

Output:
  PRIVATE_KEY_B64  → set as Railway environment variable PRIVATE_KEY_B64
                     never put this in source control
  PUBLIC_KEY_B64   → paste into client's licence.py as PUBLIC_KEY_B64

The private key never leaves your server.
The public key ships with the desktop app and is used to verify tokens.
"""

import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

priv = Ed25519PrivateKey.generate()
pub  = priv.public_key()

priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
pub_b64  = base64.b64encode(pub.public_bytes_raw()).decode()

print("=" * 60)
print("PRIVATE_KEY_B64 (→ Railway env var, NEVER commit this):")
print(priv_b64)
print()
print("PUBLIC_KEY_B64  (→ paste into client's licence.py):")
print(pub_b64)
print("=" * 60)
print()
print("Store the PRIVATE key somewhere safe (password manager, etc.)")
print("You will need it if you ever need to recreate the server from scratch.")