import os
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest
from src.app import create_app


@pytest.fixture
def setup(tmp_path):
    secret = os.urandom(32).hex()
    path = str(tmp_path / "test.sqlite")
    app = create_app({"TESTING": True, "DATABASE": path, "JWT_SECRET": secret})
    with sqlite3.connect(path) as conn:
        for username in ["alice", "bob"]:
            conn.execute("INSERT INTO users(username,password_hash) VALUES(?,?)", (username, bcrypt.hashpw(b"Education!2026", bcrypt.gensalt(rounds=4))))
    return app.test_client(), secret, path


def auth(client, username="alice"):
    result = client.post("/auth/login", json={"username": username, "password": "Education!2026"})
    assert result.status_code == 200
    return {"Authorization": "Bearer " + result.json["access_token"]}


def test_workflow_and_isolation(setup):
    client, _, path = setup
    headers = auth(client)
    assert client.post("/api/notes", headers=headers, json={"text": "My note"}).status_code == 201
    assert client.get("/api/data", headers=headers).json["notes"][0]["text"] == "My note"
    assert client.get("/api/data", headers=auth(client, "bob")).json["notes"] == []
    with sqlite3.connect(path) as connection:
        stored = connection.execute("SELECT password_hash FROM users LIMIT 1").fetchone()[0]
        assert stored != b"Education!2026"
        assert bcrypt.checkpw(b"Education!2026", stored)


@pytest.mark.parametrize("endpoint,method", [("/api/data", "get"), ("/api/notes", "post")])
def test_missing_token(setup, endpoint, method):
    assert getattr(setup[0], method)(endpoint).status_code == 401


def test_sqli_and_xss(setup):
    client, _, _ = setup
    assert client.post("/auth/login", json={"username": "' OR 1=1 --", "password": "wrong"}).status_code == 401
    headers = auth(client)
    payload = "<script>alert(1)</script>'); DROP TABLE users;--"
    response = client.post("/api/notes", headers=headers, json={"text": payload})
    assert response.status_code == 201
    assert "<script>" not in response.json["text"]
    assert "&lt;script&gt;" in response.json["text"]
    assert response.content_type == "application/json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get("/api/data", headers=auth(client)).status_code == 200


@pytest.mark.parametrize("mode", ["expired", "wrong_key", "wrong_audience", "missing_exp", "none", "bad_subject"])
def test_invalid_tokens(setup, mode):
    client, secret, _ = setup
    now = datetime.now(timezone.utc)
    claims = {"sub": "1", "exp": now+timedelta(minutes=1), "iat": now, "iss": "lab1-api", "aud": "lab1-client"}
    key = secret
    alg = "HS256"
    if mode == "expired": claims["exp"] = now-timedelta(seconds=1)
    if mode == "wrong_key": key = os.urandom(32).hex()
    if mode == "wrong_audience": claims["aud"] = "another-client"
    if mode == "missing_exp": claims.pop("exp")
    if mode == "none": alg, key = "none", ""
    if mode == "bad_subject": claims["sub"] = "9999"
    token = jwt.encode(claims, key, algorithm=alg)
    assert client.get("/api/data", headers={"Authorization":"Bearer " + token}).status_code == 401


def test_invalid_input(setup):
    client, _, _ = setup
    headers = auth(client)
    for body in [{}, [], {"text": ""}, {"text": 123}, {"text": "x"*1001}]:
        assert client.post("/api/notes", headers=headers, json=body).status_code == 400
    assert client.post("/api/notes", headers=headers, json={"text":"x"*20000}).status_code == 413
    assert client.post("/auth/login", json=[]).status_code == 400


def test_login_rate_limit(setup):
    client, _, _ = setup
    for _ in range(10):
        assert client.post("/auth/login", json={"username":"alice", "password":"wrong"}).status_code == 401
    assert client.post("/auth/login", json={"username":"alice", "password":"wrong"}).status_code == 429


def test_secret_required(tmp_path):
    with pytest.raises(ValueError):
        create_app({"JWT_SECRET":"short", "DATABASE":str(tmp_path / "unused.sqlite")})
