def test_non_object_json_payload_is_rejected(client):
    response = client.post(
        "/login",
        json=["alice", "correct-horse"],
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}
