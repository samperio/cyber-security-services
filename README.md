# cyber-security-services

```
                       ~ cyber-security-services ~

     CLIENTE                                          SERVIDOR
  ┌──────────┐                                      ┌──────────┐
  │  (•_•)   │  1) "Aquí va mi pedido..."           │  (•‿•)   │
  │  / >📦   │ ─────────────────────────────────►  │          │
  └──────────┘                                      └────┬─────┘
                                                         │
  ┌──────────┐                                      ┌────▼─────┐
  │  (•_•)   │  2) Firma con llave secreta 🔑       │ 🛡️ HMAC  │ ← ¿La firma
  │  / >✍️   │ ─── sha256=abc123... ────────────►  │  GUARD   │   coincide?
  └──────────┘                                      └────┬─────┘
                                                    ✅ SÍ │  ❌ NO → 403 🚫
  ┌──────────┐                                      ┌────▼─────┐
  │  (•_•)   │  3) Mete el pedido en caja fuerte    │ 🔐 AES   │ ← ¿Se puede
  │  / >🔐   │ ─── [#@!%&*xK9mQ...] ───────────►  │  GUARD   │   abrir?
  └──────────┘                                      └────┬─────┘
                                                    ✅ SÍ │  ❌ NO → 400 🚫
                                                    ┌────▼─────────────────┐
                                                    │   HANDLER 🎉         │
                                                    │  {"order_id":"ORD-1",│
                                                    │   "amount": 250.0 }  │
                                                    └──────────────────────┘

  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

     😈 ATACANTE                ¿Qué pasa si intenta colarse?

      (>ᴗ•) "modifico          sha256=abc123  ← firma del original
      el monto a $0.01"        amount: 0.01   ← body manipulado

                                    🛡️ HMAC GUARD: "Eso no cuadra..."
                                                              403 🚫 BOOM

      (>ᴗ•) "intercepto        [#@!%&*xK9mQ...]  ← no sé la llave
      el mensaje cifrado"
                                    🔐 AES GUARD: "Ni lo intentes."
                                                              400 🚫 BOOM
```

API REST con validación de integridad y cifrado de payload, construida con FastAPI.

## Qué hace

Cada request `POST / PUT / PATCH` pasa por dos capas de seguridad antes de llegar al handler:

```
Request
  └─► IntegrityMiddleware   — valida HMAC-SHA256 del body
        └─► DecryptionMiddleware — descifra AES-256-GCM (si viene cifrado)
              └─► Route handler — recibe el JSON en claro
```

Dos modos de uso coexisten:

| Modo | Headers requeridos |
|---|---|
| Solo integridad | `X-Signature-SHA256: sha256=<hex>` |
| Integridad + confidencialidad | `X-Signature-SHA256` + `X-Encrypted: aes-gcm` |

## Requisitos

- Python 3.11 o superior

## Instalación

```bash
# 1. Clonar el repositorio
git clone <url-del-repo>
cd cyber-security-services

# 2. Crear y activar entorno virtual
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
cp .env.example .env
```

Edita el `.env` con tus propios secretos:

```
INTEGRITY_SECRET=<mínimo 32 caracteres aleatorios>
ENCRYPTION_KEY=<64 caracteres hex — 256 bits>
```

Para generar valores seguros:

```bash
# INTEGRITY_SECRET
python -c "import secrets; print(secrets.token_urlsafe(32))"

# ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_hex(32))"
```

## Ejecutar

```bash
# Servidor (hot-reload)
uvicorn app.main:app --reload
```

La API queda disponible en `http://127.0.0.1:8000`.
Documentación interactiva: `http://127.0.0.1:8000/docs`

## Probar

```bash
# Cliente de ejemplo (servidor debe estar corriendo)
python client_example.py
```

Deberías ver cinco escenarios: dos requests válidos (plano y cifrado) y tres ataques rechazados.

## Tests

```bash
# Suite completa
python -m pytest tests/ -v

# Por módulo
python -m pytest tests/test_integrity.py -v
python -m pytest tests/test_aes_gcm.py -v
```

Cobertura actual: **19/19 tests passing**.

## Estructura

```
app/
├── config.py               # Carga de variables de entorno
├── main.py                 # FastAPI app y registro de middlewares
└── security/
    ├── hmac_validator.py   # HMAC-SHA256: compute_signature / verify_signature
    ├── aes_gcm.py          # AES-256-GCM: encrypt / decrypt
    └── middleware.py       # IntegrityMiddleware + DecryptionMiddleware
tests/
├── test_integrity.py       # Tests HMAC (unit + integración)
└── test_aes_gcm.py         # Tests AES-GCM (unit + integración)
client_example.py           # Cliente de demostración
COMMANDS.md                 # Referencia rápida de comandos
TECHNICAL_MEMORY.md         # Decisiones de diseño y arquitectura
```

## Endpoints disponibles

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/health` | Health check (sin validación) |
| `POST` | `/orders` | Crear orden |
| `PUT` | `/users/{id}` | Actualizar usuario |
| `POST` | `/webhook` | Recibir webhook |
