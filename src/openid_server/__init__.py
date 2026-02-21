import os
import re
import sys
from typing import TYPE_CHECKING
from datetime import timedelta
from uuid import UUID

from flask import Flask, render_template, session, request
from werkzeug.exceptions import HTTPException
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from jinja2 import pass_eval_context
from markupsafe import Markup, escape
from loguru import logger

from .security import KeyPair
from .settings import settings
from .utils import anonymize_ip

if TYPE_CHECKING:
    from .models import User, KeyStore

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "user.login"

fmt = "[{time}] - {name} - {level} - {message}"
logger.remove()
logger.add(sys.stderr, level="WARNING", format=fmt)
logger.add("var/logs/oidc-server.log", level="INFO", rotation="1 week", format=fmt)


@login_manager.user_loader
def load_user(user_id) -> User | None:
    from .models import User

    try:
        user_id = UUID(user_id)
    except ValueError:
        return None

    return User.query.filter_by(id=user_id).first()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
    app.config["SERVER_NAME"] = os.environ["FLASK_SERVER_NAME"]
    app.config["TRUSTED_HOSTS"] = os.environ["FLASK_TRUSTED_HOSTS"].split()
    app.config["PREFERRED_URL_SCHEME"] = os.environ["FLASK_PREFERRED_URL_SCHEME"]
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True

    app.config["RECAPTCHA_PUBLIC_KEY"] = settings.recaptcha_site
    app.config["RECAPTCHA_PRIVATE_KEY"] = settings.recaptcha_secret
    app.config["RECAPTCHA_PARAMETERS"] = {"hl": "en"}

    setup_jinja(app)
    setup_blueprints(app)
    app.register_error_handler(400, error_handler)
    app.register_error_handler(401, error_handler)
    app.register_error_handler(403, error_handler)
    app.register_error_handler(404, error_handler)
    app.register_error_handler(405, error_handler)
    app.register_error_handler(500, error_handler)

    # setup extensions
    configure_database(app)
    setup_login_manager(app)
    setup_cors(app)

    @app.after_request
    def log_request(response):
        query_str = (
            "?" + request.query_string.decode("utf-8") if request.query_string else ""
        )
        request_line = f"{request.method} {request.path}{query_str} {request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')}"

        referer = request.referrer or "-"
        user_agent = request.user_agent.string or "-"
        host = request.host
        status = response.status_code
        size = response.content_length if response.content_length is not None else "-"

        logger.info(
            f'{anonymize_ip(request.remote_addr, 2)} - "{request_line}" {status} {size} "{referer}" "{user_agent}" {host}'
        )

        return response

    return app


def setup_jinja(app: Flask) -> None:
    def hide_email(email: str) -> str:
        email = email.strip()
        return re.sub(r"^(..).+@.+$", r"\1***@******", email)

    def jwks(ks: KeyStore) -> dict:
        kp = KeyPair.from_keystore(ks)
        return kp.generate_jwks_entry()

    @pass_eval_context
    def nl2br(eval_ctx, value):
        br = "<br>\n"

        if eval_ctx.autoescape:
            value = escape(value)
            br = Markup(br)

        result = br.join(value.splitlines())
        return Markup(result) if eval_ctx.autoescape else result

    app.jinja_env.filters["hide_email"] = hide_email
    app.jinja_env.filters["jwks"] = jwks
    app.jinja_env.filters["nl2br"] = nl2br
    app.jinja_env.globals["settings"] = settings


def setup_blueprints(app: Flask) -> None:
    from . import views

    app.register_blueprint(views.frontend_app)
    app.register_blueprint(views.api_app, url_prefix="/api")
    app.register_blueprint(views.user_app, url_prefix="/user")
    app.register_blueprint(views.client_app, url_prefix="/app")
    app.register_blueprint(views.admin_app, url_prefix="/admin")


def setup_login_manager(app: Flask):
    @app.before_request
    def make_session_permanent():
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=30)

    login_manager.init_app(app)


def setup_cors(app: Flask):
    """AI generated"""

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Vary"] = "Origin"
        else:
            response.headers["Access-Control-Allow-Origin"] = "*"

        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Expose-Headers"] = "Authorization"
        return response


def error_handler(exc: HTTPException):
    return render_template("error.html", exc=exc), exc.code


def configure_database(app: Flask):
    app.config["SQLALCHEMY_DATABASE_URI"] = settings.database_uri
    app.config["SQLALCHEMY_ECHO"] = settings.database_echo
    db.init_app(app)
