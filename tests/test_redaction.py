# test_app.py
import os
import pytest
from fastapi.testclient import TestClient
from example_app import app

client = TestClient(app)

def test_show_redaction():
    response = client.get("/show")
    data = response.json()
    assert data["ok"] is True
    # token should be redacted
    assert data["token"] == "***REDACTED***"

def test_echo_redaction():
    response = client.get("/echo")
    data = response.json()
    assert data["username"] == "alice"
    assert data["password"] == "***REDACTED***"
    # DB password in note should also be redacted
    assert "***REDACTED***" in data["note"]
