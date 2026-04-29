import hashlib
import hmac
from app.config import SIGNATURE_PREFIX


def compute_signature(body: bytes, secret: str) -> str:
    """Returns 'sha256=<hex>' for the given body and secret."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def verify_signature(body: bytes, secret: str, received_signature: str) -> bool:
    """
    Timing-safe comparison between the computed and received signatures.
    Raises ValueError if the received signature format is invalid.
    """
    if not received_signature.startswith(SIGNATURE_PREFIX):
        raise ValueError(
            f"Signature must start with '{SIGNATURE_PREFIX}', got: '{received_signature[:20]}'"
        )

    expected = compute_signature(body, secret)
    return hmac.compare_digest(expected, received_signature)
