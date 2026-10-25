#!/usr/bin/env python3
"""Local training target with intentional authorization flaws (localhost only).

Flaws included on purpose:
  * /api/admin returns data with no auth check (unauth-admin-endpoint)
  * /api/users/1 and /api/users/2 return any user's data (IDOR simulation)
  * JWT issued with alg=HS256 and no 'exp' claim, role claim included
  * Session cookie without HttpOnly/Secure/SameSite
Listens on 127.0.0.1 only. For verifying privesc_scanner detections.
"""

from flask import Flask, jsonify, make_response

app = Flask(__name__)

FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJ1c2VyIjoiYWxpIiwicm9sZSI6InVzZXIifQ."
    "4Adcj0FbsVCqLFZf7tLp"
)


@app.get("/")
def index():
    resp = make_response("<html><body><h1>Test App</body></html>")
    resp.headers["Set-Cookie"] = "session=abc123; Path=/"
    return resp


@app.get("/api/admin")
def admin():
    return jsonify({"secret": "admin-dashboard-data", "users": 42})


@app.get("/api/users/<int:user_id>")
def get_user(user_id: int):
    return jsonify({"id": user_id, "name": f"user{user_id}", "role": "user"})


@app.get("/api/me")
def me():
    return jsonify({"user": "ali", "role": "user", "token": FAKE_JWT})


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5099, debug=False)
