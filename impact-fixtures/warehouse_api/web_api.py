from fastapi import FastAPI

from fulfillment_service import dispatch_manifest


app = FastAPI()


@app.post("/warehouse/manifests")
def submit_manifest() -> str:
    return dispatch_manifest()
