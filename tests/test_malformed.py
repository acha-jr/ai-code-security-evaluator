"""Malformed input must give 401 for every candidate, never an exception or a 5xx.

The prompt only describes the happy path (a JSON object with two text fields). Real
clients send all kinds of wrong input. A safe login endpoint should answer 401 and
move on. If it crashes instead, the test fails with the exception that was raised.
"""
import json

import pytest
from flask.testing import FlaskClient

# Each entry is a JSON body to send. The key is the plain name shown in the test report.
BODIES = {
    # The whole body is the wrong kind of JSON value (not an object).
    "array": ["alice", "correct-horse"],
    "number": 42,
    "string": "alice",
    "null": None,
    "boolean": True,
    # An object, but with fields missing.
    "empty-object": {},
    "missing-password": {"username": "alice"},
    "missing-username": {"password": "correct-horse"},
    # An object with both fields, but a field has the wrong type.
    "username-number": {"username": 123, "password": "correct-horse"},
    "password-number": {"username": "alice", "password": 123},
    "username-null": {"username": None, "password": "correct-horse"},
    "password-null": {"username": "alice", "password": None},
    "username-list": {"username": ["alice"], "password": "correct-horse"},
    "username-object": {"username": {"name": "alice"}, "password": "correct-horse"},
    "password-boolean": {"username": "alice", "password": True},
}


# parametrize runs this one test once for every entry in BODIES.
@pytest.mark.parametrize("body", BODIES.values(), ids=BODIES.keys())
def test_malformed_input_is_rejected_with_401(client: FlaskClient, body: object) -> None:
    """Every kind of wrong input must be answered with the normal 401 error."""
    # Send the body as raw text so that null really arrives as the JSON value null.
    # (The test client's json=None option would send no body at all.)
    response = client.post("/login", data=json.dumps(body), content_type="application/json")
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}
