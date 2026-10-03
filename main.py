import uvicorn
from fastapi import Depends, FastAPI, Request

from app.guard import build_verifier, require_integrity

app = FastAPI()
app.state.verifier = build_verifier()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/api/echo", dependencies=[Depends(require_integrity)])
async def echo(request: Request):
    """Protected endpoint: only verified, in-scope, non-replayed requests."""
    body = await request.body()
    return {"echo": body.decode("utf-8", errors="replace")}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
