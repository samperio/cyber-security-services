# Memoria Técnica — cyber-security-services

## Objetivo del proyecto

Aseguramiento (hardening) de servicios web y APIs REST usando tres pilares de seguridad:

| Pilar | Técnica | Estado |
|---|---|---|
| Integridad | HMAC-SHA256 | Implementado |
| Confidencialidad | AES-256-GCM | Implementado |
| Autenticidad | JWT RS256 | Pendiente |

---

## Estructura del proyecto

```
cyber-security-services/
├── app/
│   ├── config.py                  # Variables de entorno: SECRET_KEY, ENCRYPTION_KEY
│   ├── main.py                    # FastAPI app + registro de middlewares
│   └── security/
│       ├── hmac_validator.py      # compute_signature / verify_signature
│       ├── aes_gcm.py             # encrypt / decrypt AES-256-GCM
│       └── middleware.py          # IntegrityMiddleware + DecryptionMiddleware
├── tests/
│   ├── test_integrity.py          # 9 tests HMAC (unit + integración)
│   └── test_aes_gcm.py            # 10 tests AES-GCM (unit + integración)
├── client_example.py              # Cliente que firma y cifra requests
├── COMMANDS.md                    # Referencia de comandos del proyecto
├── TECHNICAL_MEMORY.md            # Este archivo
├── requirements.txt
├── pytest.ini
└── .env.example
```

---

## Componente 1 — Validación de integridad HMAC-SHA256

### Archivos
- `app/security/hmac_validator.py`
- `app/security/middleware.py` → clase `IntegrityMiddleware`
- `tests/test_integrity.py`

### Flujo
```
Cliente:
  body (JSON compacto) → HMAC-SHA256(body, secret) → header X-Signature-SHA256: sha256=<hex>

Servidor (IntegrityMiddleware):
  lee body raw → recalcula HMAC → hmac.compare_digest() → mismatch: 403 | ausente: 401
```

### Decisiones de diseño
- **Algoritmo:** HMAC-SHA256, misma convención que GitHub Webhooks.
- **Header:** `X-Signature-SHA256: sha256=<hex>` — el prefijo `sha256=` obliga a declarar el algoritmo, facilita migración futura.
- **Comparación timing-safe:** `hmac.compare_digest` previene timing attacks.
- **Serialización del body:** JSON compacto (`separators=(",", ":")`) — un espacio extra produce firma diferente.
- **Paths excluidos:** `/health`, `/docs`, `/openapi.json`, `/redoc`.
- **Secreto:** env var `INTEGRITY_SECRET`, nunca hardcodeado.

### Códigos de respuesta
| Situación | HTTP |
|---|---|
| Firma válida | 200 |
| Header ausente | 401 |
| Formato inválido (sin prefijo sha256=) | 400 |
| Firma no coincide | 403 |

---

## Componente 2 — Cifrado AES-256-GCM

### Archivos
- `app/security/aes_gcm.py`
- `app/security/middleware.py` → clase `DecryptionMiddleware`
- `tests/test_aes_gcm.py`

### Patrón: Encrypt-then-Sign
```
Cliente:
  plaintext → AES-GCM encrypt → ciphertext → HMAC(ciphertext) → envía ambos

Servidor:
  HMAC(ciphertext) válido? → AES-GCM decrypt → plaintext → route handler
```

**Por qué Encrypt-then-Sign:** el servidor valida integridad (operación barata) antes de descifrar (operación costosa). Protege contra DoS. Es el patrón de IPsec y TLS.

### Formato wire
```
base64( nonce[12 bytes] || ciphertext || tag[16 bytes] )
```
- Nonce: 12 bytes aleatorios por cada llamada (96 bits, recomendado para AES-GCM).
- El tag AES-GCM autentica implícitamente — si el ciphertext es manipulado, `decrypt` lanza `InvalidTag`.
- Todo en un solo campo base64: autocontenido, sin estado en el servidor.

### Headers del request cifrado
| Header | Valor |
|---|---|
| `X-Encrypted` | `aes-gcm` |
| `X-Signature-SHA256` | `sha256=<hmac-del-ciphertext>` |
| `Content-Type` | `application/octet-stream` |

### Clave de cifrado
- 256 bits (32 bytes), configurada como cadena hex de 64 caracteres en env var `ENCRYPTION_KEY`.
- Generar con: `python -c "import secrets; print(secrets.token_hex(32))"`

### Orden de middlewares en main.py
```python
app.add_middleware(DecryptionMiddleware)  # inner — se registra primero
app.add_middleware(IntegrityMiddleware)   # outer — se registra segundo, ejecuta primero
```
Flujo de un request: `IntegrityMiddleware → DecryptionMiddleware → Route`

### Detalle de implementación crítico
`DecryptionMiddleware` es **pure ASGI** (no `BaseHTTPMiddleware`) para poder reemplazar el `receive` callable y entregar el plaintext al route handler. Tras descifrar también reemplaza `Content-Type` a `application/json` en el scope para que FastAPI parsee el body correctamente.

### Modo mixto
Los dos modos coexisten. Si el header `X-Encrypted` está ausente, `DecryptionMiddleware` pasa el request sin modificarlo; `IntegrityMiddleware` valida el HMAC del body en claro.

### Lección aprendida en tests
Corromper bytes directamente en la representación base64 puede invalidar el encoding antes de alcanzar el tag AES-GCM. Los tests deben decodificar → corromper bytes crudos → re-encodear.

---

## Variables de entorno

| Variable | Descripción | Default (dev) |
|---|---|---|
| `INTEGRITY_SECRET` | Secreto compartido para HMAC | `dev-secret-change-in-production` |
| `ENCRYPTION_KEY` | Clave AES-256 en hex (64 chars) | `de10de10...` (dev only) |

---

## Cobertura de tests

| Archivo | Tests | Estado |
|---|---|---|
| `test_integrity.py` | 9 (5 unit + 4 integración) | Passing |
| `test_aes_gcm.py` | 10 (6 unit + 4 integración) | Passing |
| **Total** | **19** | **19/19** |

---

## Pendiente

- **Pilar 3:** Autenticidad con JWT RS256/ES256 — verifica que el emisor es quien dice ser.
- **Postman Collection:** Scripts pre-request para los dos modos (HMAC solo + AES-GCM + HMAC).
