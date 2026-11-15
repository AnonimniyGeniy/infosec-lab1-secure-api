"""Учебный REST API. Секреты и данные задаются только вне репозитория."""
import functools
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(JWT_SECRET=os.environ.get("JWT_SECRET"), DATABASE=os.environ.get("DATABASE", "lab.sqlite"), MAX_CONTENT_LENGTH=16 * 1024)
    if config:
        app.config.update(config)
    secret = app.config["JWT_SECRET"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise ValueError("JWT_SECRET must contain at least 32 bytes")
    attempts = {}
    dummy_hash = bcrypt.hashpw(os.urandom(32), bcrypt.gensalt())

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().executescript("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), text TEXT NOT NULL);""")
        db().commit()

    @app.cli.command("create-user")
    def create_user():
        import click
        username = click.prompt("Username")
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        if not 12 <= len(password.encode()) <= 72:
            raise click.ClickException("Password must contain 12 to 72 UTF-8 bytes")
        db().execute("INSERT INTO users(username, password_hash) VALUES (?, ?)",
                     (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))))
        db().commit()
        click.echo("User created")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    def protected(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="Authentication required"), 401
            try:
                payload = jwt.decode(header[7:], app.config["JWT_SECRET"], algorithms=["HS256"],
                                     issuer="lab1-api", audience="lab1-client",
                                     options={"require": ["sub", "exp", "iat", "iss", "aud"]})
                user = db().execute("SELECT id FROM users WHERE id = ?", (payload["sub"],)).fetchone()
                if user is None:
                    return jsonify(error="Invalid token"), 401
                g.user_id = user["id"]
            except jwt.InvalidTokenError:
                return jsonify(error="Invalid token"), 401
            return view(*args, **kwargs)
        return wrapper

    @app.post("/auth/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("username"), str) or not isinstance(data.get("password"), str):
            return jsonify(error="Expected username and password"), 400
        if len(data["username"]) > 128 or len(data["password"].encode()) > 72:
            return jsonify(error="Invalid credentials"), 401
        now = time.monotonic()
        # Ограничение попыток подходит для одного учебного процесса; в кластере нужен общий storage.
        key = request.remote_addr
        recent = [stamp for stamp in attempts.get(key, []) if now - stamp < 60]
        attempts[key] = recent
        if len(recent) >= 10:
            return jsonify(error="Too many attempts"), 429
        recent.append(now)
        user = db().execute("SELECT id, password_hash FROM users WHERE username = ?", (data["username"],)).fetchone()
        valid = bcrypt.checkpw(data["password"].encode(), user["password_hash"] if user else dummy_hash)
        if not user or not valid:
            return jsonify(error="Invalid credentials"), 401
        current = datetime.now(timezone.utc)
        token = jwt.encode({"sub": str(user["id"]), "iat": current, "exp": current + timedelta(minutes=15),
                            "iss": "lab1-api", "aud": "lab1-client"}, app.config["JWT_SECRET"], algorithm="HS256")
        return jsonify({"access_token": token, "expires_in": 900})

    @app.get("/api/data")
    @protected
    def get_notes():
        rows = db().execute("SELECT id, text FROM notes WHERE owner_id = ? ORDER BY id", (g.user_id,)).fetchall()
        return jsonify(notes=[{"id": row["id"], "text": str(escape(row["text"]))} for row in rows])

    @app.post("/api/notes")
    @protected
    def add_note():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("text"), str) or not 1 <= len(data["text"]) <= 1000:
            return jsonify(error="text must contain 1 to 1000 characters"), 400
        cursor = db().execute("INSERT INTO notes(owner_id, text) VALUES (?, ?)", (g.user_id, data["text"]))
        db().commit()
        return jsonify(id=cursor.lastrowid, text=str(escape(data["text"]))), 201

    return app
