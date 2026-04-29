"""
Cliente de ejemplo — demuestra los tres modos de uso:
  1. Solo integridad (HMAC): body en claro + firma
  2. Integridad + confidencialidad (HMAC + AES-GCM): body cifrado + firma del ciphertext
  3. Ataques simulados: body manipulado, sin firma, ciphertext corrupto

Ejecutar servidor primero:  uvicorn app.main:app --reload
Luego este script:          python client_example.py
"""

import json
import httpx

from app.config import SECRET_KEY, SIGNATURE_HEADER, ENCRYPTION_KEY, ENCRYPTION_HEADER
from app.security.hmac_validator import compute_signature
from app.security.aes_gcm import encrypt

BASE_URL = "http://127.0.0.1:8000"


# --- Helpers ---

def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode()


def signed_request(method: str, url: str, payload: dict) -> httpx.Response:
    """Body en claro + HMAC. Sin cifrado."""
    body = _json_bytes(payload)
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: compute_signature(body, SECRET_KEY),
    }
    return httpx.request(method, url, content=body, headers=headers)


def encrypted_signed_request(method: str, url: str, payload: dict) -> httpx.Response:
    """Encrypt-then-Sign: cifra el body y firma el ciphertext."""
    plaintext = _json_bytes(payload)
    ciphertext = encrypt(plaintext, ENCRYPTION_KEY)          # base64(nonce+ciphertext+tag)
    headers = {
        "Content-Type": "application/octet-stream",
        ENCRYPTION_HEADER: "aes-gcm",
        SIGNATURE_HEADER: compute_signature(ciphertext, SECRET_KEY),
    }
    return httpx.request(method, url, content=ciphertext, headers=headers)


# --- Escenarios ---

def run():
    order = {"order_id": "ORD-001", "amount": 250.00, "currency": "USD"}

    print("=" * 60)
    print("MODO 1 — Solo integridad (body en claro + HMAC)")
    print("=" * 60)
    r = signed_request("POST", f"{BASE_URL}/orders", order)
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}\n")

    print("=" * 60)
    print("MODO 2 — Integridad + Confidencialidad (AES-GCM + HMAC)")
    print("=" * 60)
    r = encrypted_signed_request("POST", f"{BASE_URL}/orders", order)
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}\n")

    print("=" * 60)
    print("ATAQUE — Body manipulado después de firmar → 403")
    print("=" * 60)
    original_body = _json_bytes(order)
    sig = compute_signature(original_body, SECRET_KEY)
    tampered = _json_bytes({**order, "amount": 0.01})
    r = httpx.post(
        f"{BASE_URL}/orders",
        content=tampered,
        headers={"Content-Type": "application/json", SIGNATURE_HEADER: sig},
    )
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}\n")

    print("=" * 60)
    print("ATAQUE — Sin header de firma → 401")
    print("=" * 60)
    r = httpx.post(f"{BASE_URL}/orders", json=order)
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}\n")

    print("=" * 60)
    print("ATAQUE — Ciphertext corrupto + firma válida del ciphertext corrupto → 400")
    print("=" * 60)
    corrupt = b"ZXN0b2VzYmFzdXJh"   # base64 de basura, no descifrable
    r = httpx.post(
        f"{BASE_URL}/orders",
        content=corrupt,
        headers={
            "Content-Type": "application/octet-stream",
            ENCRYPTION_HEADER: "aes-gcm",
            SIGNATURE_HEADER: compute_signature(corrupt, SECRET_KEY),
        },
    )
    print(f"Status: {r.status_code}")
    print(f"Body:   {r.json()}")


if __name__ == "__main__":
    run()
