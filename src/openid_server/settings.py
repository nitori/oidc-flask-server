import os
import re
from dataclasses import dataclass
from enum import StrEnum

from dotenv import load_dotenv

from .paths import path

load_dotenv(".env.local")
load_dotenv(".env")


class MailSSLType(StrEnum):
    NONE = "NONE"
    NATIVE = "NATIVE"
    STARTTLS = "STARTTLS"


@dataclass
class Settings:
    issuer: str
    database_uri: str
    database_echo: bool
    token_lifetime_seconds: int
    authorization_code_lifetime_seconds: int

    mail_username: str
    mail_password: str
    mail_server: str
    mail_port: int
    mail_ssl_type: MailSSLType
    mail_sender: str

    wk_security_contact: str
    wk_security_languages: list[str]

    recaptcha_site: str
    recaptcha_secret: str


def substitute_vars(text: str) -> str:
    def _replacer(m):
        return str(path(m[1]))

    return re.sub(r"\{path:([^}]+)}", _replacer, text)


def to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.isdigit():
            return bool(int(value))
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
        raise ValueError(f"Invalid value for to_bool: {value!r}")
    if value is None:
        return False
    raise TypeError(f"Invalid type for to_bool: {type(value)}")


def _build_settings() -> Settings:
    # we use native ssl by default (not starttls). explicitly set NONE if no encrypting should be used.
    ssl_type = MailSSLType(os.environ.get("MAIL_SSL_TYPE", "NATIVE"))
    default_mail_port = 25
    if ssl_type == MailSSLType.NATIVE:
        default_mail_port = 465
    if ssl_type == MailSSLType.STARTTLS:
        default_mail_port = 587

    return Settings(
        issuer=os.environ["OIDC_ISSUER"],
        database_uri=substitute_vars(os.environ["SQLALCHEMY_DATABASE_URI"]),
        database_echo=to_bool(os.environ.get("SQLALCHEMY_ECHO", False)),
        token_lifetime_seconds=int(os.environ["OIDC_TOKEN_LIFETIME_SECONDS"]),
        authorization_code_lifetime_seconds=int(
            os.environ["OIDC_AUTHORIZATION_CODE_LIFETIME_SECONDS"]
        ),
        mail_username=os.environ["MAIL_USERNAME"],
        mail_password=os.environ["MAIL_PASSWORD"],
        mail_server=os.environ["MAIL_SERVER"],
        mail_port=int(os.environ.get("MAIL_PORT", default_mail_port)),
        mail_ssl_type=ssl_type,
        mail_sender=os.environ["MAIL_SENDER"],
        wk_security_contact=os.environ["WK_SECURITY_CONTACT"],
        wk_security_languages=[
            lang.strip()
            for lang in os.environ["WK_SECURITY_LANGUAGES"].split(",")
            if lang.strip()
        ],
        recaptcha_site=os.environ.get("RECAPTCHA_SITE"),
        recaptcha_secret=os.environ.get("RECAPTCHA_SECRET"),
    )


settings = _build_settings()
