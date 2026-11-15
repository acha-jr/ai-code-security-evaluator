import sqlite3

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash


def create_app(database_path):
    app = Flask(__name__)

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify(error="invalid credentials"), 401

        username = data.get("username")
        password = data.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error="invalid credentials"), 401

        with sqlite3.connect(database_path) as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if row is not None and check_password_hash(row[0], password):
            return jsonify(status="ok"), 200

        return jsonify(error="invalid credentials"), 401

    return app
