import base64
import json
import os

from fastapi import FastAPI, Header, Request
from typings import RequestDetails

app = FastAPI()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def handle(
    request: Request, path: str = "", x_jwt_payload: str = Header()
) -> RequestDetails | None:
    details: RequestDetails = {
        "path": f"/{path}",
        "method": request.method,
        "headers": dict(request.headers),
    }

    if x_jwt_payload:
        try:
            padded = x_jwt_payload + "=" * (-len(x_jwt_payload) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            details["payload"] = json.loads(decoded)
        except Exception:
            ...

    return details


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
