from http import HTTPStatus


def test_smoke(client):
    resp = client.get("/api/v1/smoke")
    assert resp.status_code == HTTPStatus.OK
