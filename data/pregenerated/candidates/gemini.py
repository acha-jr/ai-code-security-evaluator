import sqlite3
import os
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

def create_app(database_path):
    app = Flask(__name__)

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "invalid credentials"}), 401

        username = data['username']
        password = data['password']

        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()

            if row is not None and check_password_hash(row[0], password):
                return jsonify({"status": "ok"}), 200
            else:
                return jsonify({"error": "invalid credentials"}), 401
        finally:
            conn.close()

    return app

if __name__ == '__main__':
    DB_PATH = 'test_app.db'

    # Setup code to ensure the app can run and be tested immediately
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        # Seed a test user (username: admin, password: password123)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ('admin', generate_password_hash('password123'))
        )
        conn.commit()
        conn.close()

    app = create_app(DB_PATH)
    app.run(port=5000, debug=True)
