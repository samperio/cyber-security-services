from fastapi import FastAPI, Request
from pydantic import BaseModel

from app.security.middleware import DecryptionMiddleware, IntegrityMiddleware

app = FastAPI(title="Integrity-Protected API", version="0.2.0")

# Orden importa: el último en add_middleware es el más externo (primero en ejecutarse).
# Flujo de request: IntegrityMiddleware → DecryptionMiddleware → Route
app.add_middleware(DecryptionMiddleware)
app.add_middleware(IntegrityMiddleware)


# --- Models ---

class OrderPayload(BaseModel):
    order_id: str
    amount: float
    currency: str


class UserPayload(BaseModel):
    username: str
    email: str


# --- Routes ---

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/orders")
async def create_order(payload: OrderPayload):
    return {"message": "Orden recibida — integridad y confidencialidad verificadas", "data": payload.model_dump()}


@app.put("/users/{user_id}")
async def update_user(user_id: int, payload: UserPayload):
    return {"message": "Usuario actualizado", "user_id": user_id, "data": payload.model_dump()}


@app.post("/webhook")
async def receive_webhook(request: Request):
    body = await request.body()
    return {"message": "Webhook aceptado", "bytes_received": len(body)}
