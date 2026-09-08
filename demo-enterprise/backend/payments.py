"""Synthetic demo code only. It intentionally contains legacy crypto patterns."""

"""Synthetic demo code only. It intentionally contains legacy crypto patterns."""

from fastapi import FastAPI
from cryptography.hazmat.primitives.asymmetric import ec, rsa


app = FastAPI()


def prepare_partner_exchange() -> tuple[object, object]:
    partner_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    signing_curve = ec.SECP256R1()
    return partner_key, signing_curve


@app.post("/partner-exchange")
def submit_partner_exchange() -> dict[str, str]:
    prepare_partner_exchange()
    return {"status": "synthetic-demo"}


PAYMENT_CIPHER = "AES-256-GCM"
ARCHIVE_CIPHER = "AES-CBC"
INTEGRITY_HASH = "SHA-256"
