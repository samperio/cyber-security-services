# Comandos del proyecto — cyber-security-services

## Instalación

```bash
# Instalar todas las dependencias
pip install -r requirements.txt

# Instalar solo la librería de cifrado (si se agrega al proyecto ya iniciado)
pip install cryptography==44.0.2
```

## Servidor

```bash
# Levantar el servidor con hot-reload (desarrollo)
uvicorn app.main:app --reload

# Levantar en un puerto específico
uvicorn app.main:app --reload --port 8080
```

## Cliente de prueba

```bash
# Correr el cliente de ejemplo (servidor debe estar corriendo)
python client_example.py
```

## Tests

```bash
# Correr todos los tests con detalle
python -m pytest tests/ -v

# Correr solo los tests de integridad HMAC
python -m pytest tests/test_integrity.py -v

# Correr solo los tests de cifrado AES-GCM
python -m pytest tests/test_aes_gcm.py -v

# Correr un test específico por nombre
python -m pytest tests/ -v -k "test_encrypt_decrypt_roundtrip"
```

## Generación de secretos seguros

```bash
# Generar INTEGRITY_SECRET (mínimo 32 caracteres)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Generar ENCRYPTION_KEY (64 chars hex = 256 bits para AES-256-GCM)
python -c "import secrets; print(secrets.token_hex(32))"
```

## Variables de entorno

```bash
# Copiar el archivo de ejemplo y editarlo
cp .env.example .env
```

Contenido del `.env`:
```
INTEGRITY_SECRET=<resultado de token_urlsafe(32)>
ENCRYPTION_KEY=<resultado de token_hex(32)>
```
