from http import HTTPStatus

from src.database.db import session_scope
from src.database.models import Role, User

USERS_ENDPOINT = "/api/v1/users"


def test_update_user_info_without_jwt(client):
    resp = client.put(USERS_ENDPOINT)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_assign_role(client, registered_user, access_token_admin):
    user_login, password = registered_user

    with session_scope() as session:
        user = session.query(User).filter_by(login=user_login).first()
        assert user.role.name == "User"
        admin_role_id = (
            session.query(Role)
            .filter_by(permissions=0xFF)
            .with_entities(Role.id)
            .scalar()
        )

    resp = client.put(
        f"{USERS_ENDPOINT}/{user.id}/role/{admin_role_id}", headers=access_token_admin
    )
    assert resp.status_code == HTTPStatus.OK

    with session_scope() as session:
        user = session.query(User).filter_by(login=user_login).first()
        assert user.role.name == "Admin"


def test_reset_role(client, registered_user, access_token_admin):
    user_login, password = registered_user

    with session_scope() as session:
        user = session.query(User).filter_by(login=user_login).first()
        assert user.role.name == "User"

    resp = client.delete(
        f"{USERS_ENDPOINT}/{user.id}/role/", headers=access_token_admin
    )
    assert resp.status_code == HTTPStatus.NO_CONTENT

    with session_scope() as session:
        user = session.query(User).filter_by(login=user_login).first()
        assert not user.role
