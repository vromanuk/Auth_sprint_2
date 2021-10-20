import uuid
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    or_,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import backref, relationship
from werkzeug.security import generate_password_hash

from src.database.db import Base, session_scope
from src.permissions import Permission


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True)
    default = Column(Boolean, default=False)
    permissions = Column(Integer)
    users = relationship("User", back_populates="role", lazy="selectin")

    @classmethod
    def insert_roles(cls):
        roles = {
            "User": (Permission.READ_MOVIES | Permission.UPDATE_PERSONAL_INFO, True),
            "Admin": (0xFF, False),
        }

        with session_scope() as session:
            for r in roles:
                role = session.query(cls).filter_by(name=r).first()
                if role is None:
                    role = Role(name=r)
                role.permissions = roles[r][0]
                role.default = roles[r][1]
                session.add(role)
            session.commit()

    @classmethod
    def fetch(cls, role_id: int):
        with session_scope() as session:
            return session.query(cls).filter_by(id=role_id).first()

    @classmethod
    def fetch_all(cls):
        with session_scope() as session:
            return session.query(cls).all()

    @classmethod
    def create(cls, role) -> bool:
        with session_scope() as session:
            session.add(role)
            session.commit()
            return True

    @classmethod
    def update(cls, role_id, update_role) -> bool:
        with session_scope() as session:
            role = cls.fetch(role_id)
            if not role:
                return False
            role.name = update_role.name
            role.permissions = update_role.permissions
            role.default = update_role.default

            session.add(role)
            session.commit()

            return True

    @classmethod
    def delete(cls, role_id: int) -> bool:
        with session_scope() as session:
            role = cls.fetch(role_id)
            if not role:
                return False

            session.delete(role)
            session.commit()

            return True

    @classmethod
    def fetch_default_role(cls):
        with session_scope() as session:
            return (
                session.query(Role)
                .filter_by(default=True)
                .with_entities(Role.id)
                .scalar()
            )


class User(Base):
    __tablename__ = "users"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    # id = Column(Integer, primary_key=True)
    login = Column(String, unique=True, nullable=True)
    password = Column(String, nullable=False)
    log_history = relationship("LogHistory", backref="user", lazy="dynamic")
    role_id = Column(Integer, ForeignKey("roles.id"))
    role = relationship("Role", back_populates="users", lazy="selectin")
    email = Column(String(64), nullable=True)

    def __init__(
        self, login: str, password: str, email: Optional[str] = None, is_admin=False
    ):
        self.login = login
        self.email = email
        self.password = generate_password_hash(password)
        self.is_admin = is_admin

    def __repr__(self):
        return f"<User {self.login}>"

    @classmethod
    def find_by_login(cls, login: str):
        with session_scope() as session:
            return session.query(cls).filter_by(login=login).first()

    @classmethod
    def find_by_uuid(cls, user_id: UUID):
        with session_scope() as session:
            return session.query(cls).filter_by(id=user_id).first()

    @classmethod
    def get_user_by_universal_login(
        cls, login: Optional[str] = None, email: Optional[str] = None
    ):
        with session_scope() as session:
            return (
                session.query(cls)
                .filter(or_(cls.login == login, cls.email == email))
                .first()
            )


class LogHistory(Base):
    __tablename__ = "log_history"
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    # id = Column(Integer, primary_key=True)
    logged_at = Column(DateTime, nullable=False, index=True)
    user_agent = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    refresh_token = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    # user_id = Column(Integer, ForeignKey("users.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))


class SocialAccount(Base):
    __tablename__ = "social_account"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    # id = Column(Integer, primary_key=True)
    # user_id = Column(Integer, ForeignKey("users.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    user = relationship(User, backref=backref("social_accounts", lazy=True))

    social_id = Column(String(64), nullable=False)
    social_name = Column(String(64), nullable=False)

    __table_args__ = (UniqueConstraint("social_id", "social_name", name="social_pk"),)

    def __repr__(self):
        return f"<SocialAccount {self.social_name}:{self.user_id}>"
