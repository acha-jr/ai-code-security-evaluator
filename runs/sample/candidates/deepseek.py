import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(database_path):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = database_path

    def get_db():
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        return conn

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "invalid credentials"}), 401

        conn = get_db()
        try:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            conn.close()

        if row is not None and check_password_hash(row["password_hash"], password):
            return jsonify({"status": "ok"}), 200

        return jsonify({"error": "invalid credentials"}), 401

    return app


def init_db(database_path):
    conn = sqlite3.connect(database_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def add_user(database_path, username, password):
    conn = sqlite3.connect(database_path)
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    db_path = "app.db"
    init_db(db_path)
    # Optional: create a test user once:
    # add_user(db_path, "testuser", "testpassword")
    app = create_app(db_path)
    app.run(debug=True)
