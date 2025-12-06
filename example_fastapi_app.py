# example_fastapi_app.py
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os
import logging
import builtins

from fastapi_redaction.redaction import Redaction

# Example: set environment secret
os.environ["PASSWORD"] = "my_db_pass_1234"

# Create FastAPI app
app = FastAPI(title="Redaction Example")

# Initialize Redaction middleware
redaction = Redaction()
redaction.init_app(app)  # attaches middleware and logging filter

original_print = builtins.print

def redacted_print(*args, **kwargs):
    redacted_args = [redaction.redact_text(str(a)) for a in args]
    original_print(*redacted_args, **kwargs)

builtins.print = redacted_print

# Set up a logger (optional, root logger already filtered by Redaction)
logger = logging.getLogger("example")
logger.setLevel(logging.INFO)

@app.get("/login")
async def login():
    # Example of logging a secret

    print(f"Logging in with password: {os.environ['PASSWORD']}")
    print(f"Logging in with password: {redaction.redact_text(os.environ['PASSWORD'])}")

    # Example of returning a secret in JSON
    return {"username": "alice", "password": os.environ["PASSWORD"]}

@app.post("/update")
async def update(request: Request):
    # Access redacted headers
    redacted_headers = request.state.redacted_headers
    logger.info(f"Received headers: {redacted_headers}")
    data = await request.json()
    return JSONResponse(content=data)

# To run: uvicorn example_fastapi_app:app --reload
