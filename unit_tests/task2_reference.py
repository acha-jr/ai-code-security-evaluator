"""A correct Task 2 app, written by hand. It is NOT a study candidate.

It exists only to check that the Task 2 tests accept a correct app and reject broken ones.
"""
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash


def create_app(database_path: str, token_lifetime_seconds: int = 3600) -> Flask:
    """Build the app. A new random secret is made each time, so tokens never carry over."""
    app = Flask(__name__)
    secret = secrets.token_bytes(32)

    def sign(data: bytes) -> str:
        """Return the signature for some data, made with the secret key."""
        return base64.urlsafe_b64encode(hmac.new(secret, data, hashlib.sha256).digest()).decode()

    def make_token(username: str) -> str:
        """Build a token: the data (user and expiry time), a dot, and its signature."""
        payload = {"sub": username, "exp": time.time() + token_lifetime_seconds}
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        return f"{body}.{sign(body.encode())}"

    def read_token(token: str) -> str | None:
        """Return the username in a good token, or None if it is bad, tampered or expired."""
        try:
            body, signature = token.split(".")
            if not hmac.compare_digest(signature, sign(body.encode())):  # CHECK_SIGNATURE
                return None
            payload = json.loads(base64.urlsafe_b64decode(body))
            if payload["exp"] < time.time():  # CHECK_EXPIRY
                return None
            return payload["sub"]
        except (ValueError, KeyError):
            return None

    @app.post("/login")
    def login():
        """Check the credentials and hand out a token."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="invalid credentials"), 401
        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error="invalid credentials"), 401
        with sqlite3.connect(database_path) as connection:
            row = connection.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if row is None or not check_password_hash(row[0], password):
            return jsonify(error="invalid credentials"), 401
        return jsonify(status="ok", token=make_token(username)), 200

    @app.get("/users/<username>/profile")
    def profile(username: str):
        """Return the profile only when the token belongs to the same user."""
        header = request.headers.get("Authorization", "")
        owner = read_token(header[7:]) if header.startswith("Bearer ") else None
        if owner is None:
            return jsonify(error="unauthorized"), 401
        if owner != username:  # CHECK_OWNER
            return jsonify(error="forbidden"), 403
        return jsonify(username=username), 200

    return app
