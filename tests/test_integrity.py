import json
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.security.hmac_validator import compute_signature, verify_signature
from app.config import SECRET_KEY, SIGNATURE_HEADER


# --- Unit tests: hmac_validator ---

def test_compute_signature_returns_sha256_prefix():
    sig = compute_signature(b"hello", "secret")
    assert sig.startswith("sha256=")


def test_verify_signature_valid():
    body = b'{"order_id":"1","amount":10.0}'
    sig = compute_signature(body, SECRET_KEY)
    assert verify_signature(body, SECRET_KEY, sig) is True


def test_verify_signature_wrong_secret():
    body = b'{"order_id":"1","amount":10.0}'
    sig = compute_signature(body, "wrong-secret")
    assert verify_signature(body, SECRET_KEY, sig) is False


def test_verify_signature_tampered_body():
    original = b'{"amount":100.0}'
    sig = compute_signature(original, SECRET_KEY)
    tampered = b'{"amount":0.01}'
    assert verify_signature(tampered, SECRET_KEY, sig) is False


def test_verify_signature_invalid_format():
    with pytest.raises(ValueError, match="must start with"):
        verify_signature(b"body", SECRET_KEY, "invalid-signature")


# --- Integration tests: middleware via HTTP ---

def _signed_headers(body: bytes) -> dict:
    return {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: compute_signature(body, SECRET_KEY),
    }


@pytest.mark.asyncio
async def test_post_with_valid_signature():
    payload = {"order_id": "ORD-001", "amount": 50.0, "currency": "USD"}
    body = json.dumps(payload, separators=(",", ":")).encode()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", content=body, headers=_signed_headers(body))
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_post_without_signature_returns_401():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", json={"order_id": "x", "amount": 1.0, "currency": "USD"})
    assert r.status_code == 401
    assert "ausente" in r.json()["detail"]


@pytest.mark.asyncio
async def test_post_tampered_body_returns_403():
    original = {"order_id": "ORD-002", "amount": 200.0, "currency": "USD"}
    original_body = json.dumps(original, separators=(",", ":")).encode()
    sig = compute_signature(original_body, SECRET_KEY)

    tampered = {"order_id": "ORD-002", "amount": 0.01, "currency": "USD"}
    tampered_body = json.dumps(tampered, separators=(",", ":")).encode()

    headers = {"Content-Type": "application/json", SIGNATURE_HEADER: sig}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/orders", content=tampered_body, headers=headers)
    assert r.status_code == 403
    assert "Integridad comprometida" in r.json()["detail"]


@pytest.mark.asyncio
async def test_get_health_skips_validation():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/health")
    assert r.status_code == 200
