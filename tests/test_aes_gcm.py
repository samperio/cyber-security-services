import json
import pytest
from cryptography.exceptions import InvalidTag
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.config import SECRET_KEY, ENCRYPTION_KEY, SIGNATURE_HEADER, ENCRYPTION_HEADER
from app.security.aes_gcm import encrypt, decrypt
from app.security.hmac_validator import compute_signature


# --- Unit tests: aes_gcm ---

def test_encrypt_decrypt_roundtrip():
    plaintext = b'{"order_id":"1","amount":10.0}'
    ciphertext = encrypt(plaintext, ENCRYPTION_KEY)
    assert decrypt(ciphertext, ENCRYPTION_KEY) == plaintext


def test_encrypt_produces_different_ciphertext_each_call():
    plaintext = b"mismo mensaje"
    c1 = encrypt(plaintext, ENCRYPTION_KEY)
    c2 = encrypt(plaintext, ENCRYPTION_KEY)
    assert c1 != c2  # nonces distintos → ciphertexts distintos


def test_decrypt_raises_on_tampered_ciphertext():
    import base64
    raw_b64 = encrypt(b"secreto", ENCRYPTION_KEY)
    raw_bytes = bytearray(base64.b64decode(raw_b64))
    raw_bytes[20] ^= 0xFF  # corrompe un byte en los datos crudos, luego re-encodea
    with pytest.raises(InvalidTag):
        decrypt(base64.b64encode(bytes(raw_bytes)), ENCRYPTION_KEY)


def test_decrypt_raises_on_wrong_key():
    ciphertext = encrypt(b"secreto", ENCRYPTION_KEY)
    wrong_key = bytes(32)  # 32 ceros
    with pytest.raises(InvalidTag):
        decrypt(ciphertext, wrong_key)


def test_decrypt_raises_on_invalid_base64():
    with pytest.raises(ValueError, match="base64"):
        decrypt(b"!!!no-es-base64!!!", ENCRYPTION_KEY)


def test_decrypt_raises_on_short_ciphertext():
    import base64
    with pytest.raises(ValueError, match="corto"):
        decrypt(base64.b64encode(b"short"), ENCRYPTION_KEY)


# --- Integration tests: encrypted + signed requests ---

def _encrypted_signed_headers(payload: dict) -> tuple[bytes, dict]:
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ciphertext = encrypt(plaintext, ENCRYPTION_KEY)
    headers = {
        "Content-Type": "application/octet-stream",
        ENCRYPTION_HEADER: "aes-gcm",
        SIGNATURE_HEADER: compute_signature(ciphertext, SECRET_KEY),
    }
    return ciphertext, headers


@pytest.mark.asyncio
async def test_encrypted_signed_request_succeeds():
    order = {"order_id": "ORD-100", "amount": 99.9, "currency": "USD"}
    ciphertext, headers = _encrypted_signed_headers(order)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", content=ciphertext, headers=headers)
    assert r.status_code == 200
    assert r.json()["data"]["amount"] == 99.9


@pytest.mark.asyncio
async def test_tampered_ciphertext_after_signing_returns_403():
    order = {"order_id": "ORD-101", "amount": 500.0, "currency": "USD"}
    ciphertext, headers = _encrypted_signed_headers(order)
    tampered = ciphertext[:-4] + b"XXXX"  # modifica los últimos bytes (tag)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", content=tampered, headers=headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_valid_signature_but_corrupt_ciphertext_returns_400():
    corrupt = b"ZXN0b2VzYmFzdXJh"
    headers = {
        "Content-Type": "application/octet-stream",
        ENCRYPTION_HEADER: "aes-gcm",
        SIGNATURE_HEADER: compute_signature(corrupt, SECRET_KEY),
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", content=corrupt, headers=headers)
    assert r.status_code == 400
    assert "Descifrado fallido" in r.json()["detail"]


@pytest.mark.asyncio
async def test_plain_signed_request_still_works():
    order = {"order_id": "ORD-102", "amount": 10.0, "currency": "MXN"}
    body = json.dumps(order, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: compute_signature(body, SECRET_KEY),
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", content=body, headers=headers)
    assert r.status_code == 200
