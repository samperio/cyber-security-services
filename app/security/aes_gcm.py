import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits — valor recomendado para AES-GCM (evita colisiones con nonce aleatorio)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra con AES-256-GCM.
    Retorna base64(nonce[12] || ciphertext || tag[16]).
    El nonce se genera aleatoriamente por llamada (nunca reutilizar).
    """
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext_with_tag)


def decrypt(encrypted_b64: bytes, key: bytes) -> bytes:
    """
    Descifra base64(nonce[12] || ciphertext || tag[16]).
    Lanza InvalidTag si el ciphertext fue manipulado (AES-GCM autentica implícitamente).
    Lanza ValueError si el formato base64 o el tamaño mínimo no es válido.
    """
    try:
        raw = base64.b64decode(encrypted_b64)
    except Exception:
        raise ValueError("El body cifrado no es base64 válido")

    # nonce(12) + tag(16) = 28 bytes mínimo; sin payload el tag solo sería 16
    if len(raw) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext demasiado corto — posible manipulación")

    nonce, ciphertext_with_tag = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    # AESGCM.decrypt lanza cryptography.exceptions.InvalidTag si el tag no coincide
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, None)
