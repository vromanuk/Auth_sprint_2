from http import HTTPStatus
from uuid import UUID

from flask import request
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restful import Resource
from marshmallow import ValidationError

from src.database.db import session_scope
from src.schemas.users import UserSchema
from src.services.auth_service import admin_required
from src.services.users_service import UserService


class Users(Resource):
    @jwt_required()
    def put(self):
        """
        users related view, e.g. change-password, change-login
        ---
        tags:
          - users
        parameters:
          - name: body
            in: body
            required: true
            schema:
              id: User
              properties:
                login:
                  type: string
                  description: The user's name.
                  default: "Spike"
                password:
                  type: string
                  description: The user's new password.
                  default: "Spiegel123"
        security:
            - bearerAuth: []
        responses:
          200:
            description: User data has been updated.
          400:
            description: Invalid data.
          404:
            description: User has not been found.
        """
        current_user_id = get_jwt_identity()
        try:
            data = {
                "login": request.json.get("login", None),
                "password": request.json.get("password", None),
            }
            with session_scope() as session:
                updated_user = UserSchema().load(data, session=session)
        except ValidationError as e:
            return {"message": str(e)}, HTTPStatus.BAD_REQUEST

        is_updated = UserService.update(current_user_id, updated_user)
        if is_updated:
            if data["password"]:
                UserService.reset_active_tokens(current_user_id)
            return {"message": "updated"}, HTTPStatus.OK
        return {"message": "user has not been found"}, HTTPStatus.NOT_FOUND


class UserRole(Resource):
    @admin_required
    def put(self, user_id: UUID, role_id: int):
        """
        Manage user role view
        ---
        tags:
          - users-roles
        parameters:
         - in: path
           name: user_id
           type: uuid
           required: true
           name: role_id
           type: integer
           required: true
        security:
            - bearerAuth: []
        responses:
          200:
            description: User role has been updated.
          404:
            description: Role has not been found.
        """
        is_role_set = UserService.update_role(user_id, role_id)

        if is_role_set:
            return {"message": "role has been set"}, HTTPStatus.OK
        return {"message": "user or role has not been found"}, HTTPStatus.NOT_FOUND

    @admin_required
    def delete(self, user_id: UUID):
        """
        Remove user role view
        ---
        tags:
          - users-roles
        parameters:
         - in: path
           name: user_id
           type: uuid
           required: true
        security:
            - bearerAuth: []
        responses:
          204:
            description: User role has been reset.
          404:
            description: Role has not been found.
        """
        is_role_reset = UserService.reset_role(user_id)

        if is_role_reset:
            return {"message": "role has been reset"}, HTTPStatus.NO_CONTENT
        return {"message": "not found"}, HTTPStatus.NOT_FOUND
