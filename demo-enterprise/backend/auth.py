"""Synthetic demo code only. It intentionally contains legacy crypto patterns."""

from fastapi import FastAPI
from cryptography.hazmat.primitives.asymmetric import rsa


app = FastAPI()


def create_session_key() -> object:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@app.post("/sessions")
def login() -> dict[str, str]:
    create_session_key()
    return {"status": "synthetic-demo"}
