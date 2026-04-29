from dotenv import load_dotenv
import os

load_dotenv()

# --- Integridad ---
SECRET_KEY: str = os.getenv("INTEGRITY_SECRET", "dev-secret-change-in-production")
SIGNATURE_HEADER: str = "X-Signature-SHA256"
SIGNATURE_PREFIX: str = "sha256="

# --- Cifrado AES-256-GCM ---
# 64 caracteres hex = 32 bytes = 256 bits
_ENCRYPTION_KEY_HEX: str = os.getenv(
    "ENCRYPTION_KEY",
    "de10de10de10de10de10de10de10de10de10de10de10de10de10de10de10de10",  # dev only
)
try:
    ENCRYPTION_KEY: bytes = bytes.fromhex(_ENCRYPTION_KEY_HEX)
    if len(ENCRYPTION_KEY) != 32:
        raise ValueError
except ValueError:
    raise RuntimeError("ENCRYPTION_KEY debe ser una cadena hex de 64 caracteres (256 bits)")

ENCRYPTION_HEADER: str = "X-Encrypted"
