def test_valid_credentials(client):
    response = client.post(
        "/login",
        json={"username": "alice", "password": "correct-horse"},
    )
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_wrong_password_rejected(client):
    response = client.post(
        "/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_unknown_user_rejected(client):
    response = client.post(
        "/login",
        json={"username": "unknown", "password": "correct-horse"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_sql_injection_does_not_bypass_login(client):
    response = client.post(
        "/login",
        json={"username": "' OR 1=1 --", "password": "anything"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}
