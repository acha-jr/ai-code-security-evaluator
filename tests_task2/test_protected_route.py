"""Task 2: login returns a token, and the protected profile route checks it.

A token is a signed string the server hands out after a good login. The client sends it
back on later requests (in an "Authorization: Bearer <token>" header) to prove who it is.
These tests check that the server really enforces that proof.
"""
from collections.abc import Callable

import pytest
from flask.testing import FlaskClient

# make_client builds a test client. It accepts options such as token_lifetime_seconds.
MakeClient = Callable[..., FlaskClient]


def login_token(client: FlaskClient, username: str = "alice", password: str = "correct-horse") -> str:
    """Log in and return the token from the response."""
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.get_json()["token"]


def get_profile(client: FlaskClient, username: str, token: str | None = None):
    """Call the protected route, with a Bearer token when one is given."""
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.get(f"/users/{username}/profile", headers=headers)


def test_login_returns_status_and_token(make_client: MakeClient) -> None:
    """A good login returns status ok and a non-empty token."""
    body = make_client().post("/login", json={"username": "alice", "password": "correct-horse"}).get_json()
    assert body["status"] == "ok"
    assert isinstance(body["token"], str) and body["token"]


def test_wrong_password_gets_no_token(make_client: MakeClient) -> None:
    """A bad password gets the normal 401 and no token."""
    response = make_client().post("/login", json={"username": "alice", "password": "nope"})
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_valid_token_reads_own_profile(make_client: MakeClient) -> None:
    """The owner of a valid token can read their own profile."""
    # The happy path: a logged-in user can read their own profile.
    client = make_client()
    response = get_profile(client, "alice", login_token(client))
    assert response.status_code == 200
    assert response.get_json() == {"username": "alice"}


def test_missing_token_is_unauthorized(make_client: MakeClient) -> None:
    """A request with no token is refused with 401."""
    # No token at all must be refused.
    response = get_profile(make_client(), "alice")
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}


@pytest.mark.parametrize("token", ["garbage", "a.b.c", ""], ids=["garbage", "three-parts", "empty"])
def test_invalid_token_is_unauthorized(make_client: MakeClient, token: str) -> None:
    """A made-up token is refused with 401."""
    # Made-up tokens must be refused, and must not crash the server.
    response = get_profile(make_client(), "alice", token)
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}


@pytest.mark.parametrize("spot", [3, -2], ids=["start-of-token", "end-of-token"])
def test_tampered_token_is_unauthorized(make_client: MakeClient, spot: int) -> None:
    """A real token with one character changed is refused with 401."""
    client = make_client()
    token = login_token(client)
    # Signed tokens usually keep the signature at the end. Changing a character there leaves the
    # data readable but breaks the signature, so only a real signature check will catch it.
    position = spot % len(token)  # The % turns -2 into "second to last position".
    tampered = token[:position] + ("B" if token[position] == "A" else "A") + token[position + 1:]
    response = get_profile(client, "alice", tampered)
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}


def test_expired_token_is_unauthorized(make_client: MakeClient) -> None:
    """A token past its lifetime is refused with 401."""
    # A negative lifetime means the token is already expired when it is issued.
    client = make_client(token_lifetime_seconds=-60)
    response = get_profile(client, "alice", login_token(client))
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}


@pytest.mark.parametrize(
    "owner, target",
    [("alice", "bob"), ("bob", "alice")],
    ids=["alice-reads-bob", "bob-reads-alice"],
)
def test_user_cannot_read_another_user(make_client: MakeClient, owner: str, target: str) -> None:
    """A valid token for one user cannot read another user's profile (403)."""
    # This is the authorization check: a valid token is not enough, it must belong to the same user.
    client = make_client()
    passwords = {"alice": "correct-horse", "bob": "battery-staple"}
    response = get_profile(client, target, login_token(client, owner, passwords[owner]))
    assert response.status_code == 403
    assert response.get_json() == {"error": "forbidden"}
