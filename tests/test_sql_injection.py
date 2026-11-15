"""SQL injection payloads in either field must not log anyone in or damage the database.

SQL injection means putting SQL code into a text field, hoping the app pastes it into
its query. A safe app passes user text as a separate value (a "?" placeholder), so the
text is only ever treated as data and never as SQL.
"""
import pytest
from flask.testing import FlaskClient

# Each payload is a classic injection trick. The key names the trick.
PAYLOADS = {
    "or-true": "' OR '1'='1",  # Tries to make the WHERE condition always true.
    "comment": "alice'--",  # Tries to cut off the rest of the query with a SQL comment.
    "union-literal": "' UNION SELECT 'x' --",  # Tries to add a second query that returns a fake row.
    "union-hash": "' UNION SELECT password_hash FROM users --",  # Tries to leak stored password hashes.
    "drop-table": "'; DROP TABLE users; --",  # Tries to delete the users table.
}


# Two parametrize lines multiply: every payload is tried in both the username and the password field.
@pytest.mark.parametrize("field", ["username", "password"])
@pytest.mark.parametrize("payload", PAYLOADS.values(), ids=PAYLOADS.keys())
def test_injection_payload_is_rejected(client: FlaskClient, field: str, payload: str) -> None:
    """An injection payload gets 401, and a real login still works afterwards."""
    # Start from a normal request with a wrong password, then put the payload in one field.
    body = {"username": "alice", "password": "wrong-password"}
    body[field] = payload
    response = client.post("/login", json=body)
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}

    # The users table must still exist and still work. A real login must succeed after the attack.
    again = client.post("/login", json={"username": "alice", "password": "correct-horse"})
    assert again.status_code == 200
