from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import SECRET_KEY, SIGNATURE_HEADER, ENCRYPTION_KEY, ENCRYPTION_HEADER
from app.security.hmac_validator import verify_signature
from app.security.aes_gcm import decrypt

EXCLUDED_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}
MUTATING_METHODS = {"POST", "PUT", "PATCH"}


async def _read_body(receive: Receive) -> bytes:
    """Lee todos los chunks del body desde el receive callable."""
    chunks = []
    more = True
    while more:
        message = await receive()
        chunks.append(message.get("body", b""))
        more = message.get("more_body", False)
    return b"".join(chunks)


def _make_receive(body: bytes) -> Receive:
    """Devuelve un receive callable que reproduce un body ya leído."""
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


class IntegrityMiddleware:
    """
    Valida HMAC-SHA256 del body para métodos mutantes.
    Siempre valida sobre el body RAW recibido — si viene cifrado, valida el ciphertext.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")

        if method not in MUTATING_METHODS or path in EXCLUDED_PATHS:
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive)

        headers = dict(scope.get("headers", []))
        received_sig = headers.get(SIGNATURE_HEADER.lower().encode(), b"").decode()

        if not received_sig:
            response = JSONResponse(
                status_code=401,
                content={
                    "detail": f"Header de integridad '{SIGNATURE_HEADER}' ausente.",
                    "hint": "Firma el body con HMAC-SHA256 y envíalo como 'sha256=<hex>'.",
                },
            )
            await response(scope, receive, send)
            return

        try:
            valid = verify_signature(body, SECRET_KEY, received_sig)
        except ValueError as exc:
            response = JSONResponse(status_code=400, content={"detail": str(exc)})
            await response(scope, receive, send)
            return

        if not valid:
            response = JSONResponse(
                status_code=403,
                content={"detail": "Integridad comprometida: la firma del body no coincide."},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, _make_receive(body), send)


class DecryptionMiddleware:
    """
    Descifra el body con AES-256-GCM cuando el header X-Encrypted: aes-gcm está presente.
    Debe ejecutarse DESPUÉS de IntegrityMiddleware (más interno en la cadena),
    para que la integridad se valide sobre el ciphertext y el descifrado ocurra después.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")

        if method not in MUTATING_METHODS or path in EXCLUDED_PATHS:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        enc_header = headers.get(ENCRYPTION_HEADER.lower().encode(), b"").decode().lower()

        if enc_header != "aes-gcm":
            await self.app(scope, receive, send)
            return

        ciphertext = await _read_body(receive)

        try:
            plaintext = decrypt(ciphertext, ENCRYPTION_KEY)
        except Exception as exc:
            response = JSONResponse(
                status_code=400,
                content={"detail": f"Descifrado fallido: {exc}"},
            )
            await response(scope, receive, send)
            return

        # Reemplaza Content-Type → application/json para que FastAPI parsee el plaintext correctamente
        new_headers = [
            (k, v) for k, v in scope.get("headers", [])
            if k.lower() not in (b"content-type", b"content-length", b"x-encrypted")
        ]
        new_headers.append((b"content-type", b"application/json"))
        new_headers.append((b"content-length", str(len(plaintext)).encode()))

        new_scope = {**scope, "headers": new_headers}
        await self.app(new_scope, _make_receive(plaintext), send)
