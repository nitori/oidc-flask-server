from datetime import datetime
import secrets
from uuid import UUID, uuid4

from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import ForeignKey, String, JSON
from flask_login import UserMixin

from openid_server import db
from openid_server.types import KeyAlgorithm
from openid_server.utils import now, until
from openid_server.security import (
    pw_context,
    generate_client_id,
    generate_client_secret,
)


class User(db.Model, UserMixin):
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    is_active: Mapped[bool] = mapped_column(default=True)
    is_admin: Mapped[bool] = mapped_column(default=False)
    email: Mapped[str] = mapped_column(unique=True)
    email_verified: Mapped[bool] = mapped_column(default=False)
    email_update_key: Mapped[str | None] = mapped_column()
    name: Mapped[str] = mapped_column()
    family_name: Mapped[str] = mapped_column(nullable=True)
    given_name: Mapped[str] = mapped_column(nullable=True)
    picture: Mapped[str] = mapped_column(nullable=True)

    hashed_password: Mapped[str] = mapped_column(String(255))
    clients: Mapped[list[Client]] = relationship(back_populates="user")

    @property
    def password(self):
        raise AttributeError("Can't get clear text password")

    @password.setter
    def password(self, value: str):
        self.hashed_password = pw_context.hash(value)

    def verify_password(self, value: str) -> bool:
        return pw_context.verify(value, self.hashed_password)


class AuthorizationCode(db.Model):
    """short-lived autorization code created right after user permitted access through the /auth endpoint"""

    code: Mapped[str] = mapped_column(
        String(50), primary_key=True, default=lambda: secrets.token_urlsafe(32)
    )
    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    user: Mapped[User] = relationship()
    client_id: Mapped[str] = mapped_column(ForeignKey("client.client_id"))
    client: Mapped[Client] = relationship()
    scope: Mapped[str] = mapped_column()
    response_mode: Mapped[str] = mapped_column()
    code_challenge: Mapped[str | None] = mapped_column()
    code_challenge_method: Mapped[str | None] = mapped_column()
    redirect_uri: Mapped[str] = mapped_column()
    created: Mapped[datetime] = mapped_column(default=now)
    expires: Mapped[datetime] = mapped_column(default=lambda: until(minutes=5))
    auth_time: Mapped[datetime] = mapped_column(default=now)
    nonce: Mapped[str | None] = mapped_column()


class Client(db.Model):
    """API Client"""

    client_id: Mapped[str] = mapped_column(
        primary_key=True,
        default=generate_client_id,
    )
    client_secret: Mapped[str] = mapped_column(default=generate_client_secret)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list)

    name: Mapped[str] = mapped_column()
    is_public: Mapped[bool] = mapped_column(default=True)
    preferred_algorithm: Mapped[KeyAlgorithm] = mapped_column()

    # owner
    user_id: Mapped[UUID] = mapped_column(ForeignKey("user.id"))
    user: Mapped[User] = relationship(back_populates="clients")


class KeyStore(db.Model):
    id: Mapped[str] = mapped_column(primary_key=True)
    # sqlite does not have timezones, so retrievals will always return "naive" datetime objects.
    # that's why I convert them to UTC, and ensure they're naive at any point (so comparisons don't fail)
    created: Mapped[datetime] = mapped_column(default=now)
    alg: Mapped[KeyAlgorithm] = mapped_column()
    public_key: Mapped[bytes] = mapped_column()
    secret_key: Mapped[bytes] = mapped_column()
