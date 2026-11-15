# app.py
import sqlite3

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
)
"""

# Used to keep response time similar when the username doesn't exist.
_DUMMY_HASH = generate_password_hash("dummy-password")


def create_app(database_path):
    app = Flask(__name__)
    app.config["DATABASE"] = database_path

    with sqlite3.connect(database_path) as conn:
        conn.execute(SCHEMA)
    conn.close()

    def invalid_credentials():
        return jsonify({"error": "invalid credentials"}), 401

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return invalid_credentials()

        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return invalid_credentials()

        conn = sqlite3.connect(app.config["DATABASE"])
        try:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            check_password_hash(_DUMMY_HASH, password)
            return invalid_credentials()

        if not check_password_hash(row[0], password):
            return invalid_credentials()

        return jsonify({"status": "ok"}), 200


    return app


if __name__ == "__main__":
    create_app("users.db").run()
