import re
from typing import Any
from urllib.parse import unquote_plus
from uuid import UUID

import jwt
from flask import Blueprint, Response, jsonify, request, url_for

from openid_server import db
from openid_server.types import KeyPair
from openid_server.models import AuthorizationCode, User
from openid_server.utils import now, auto_commit
from openid_server.settings import settings
from openid_server.security import (
    get_latest_keystore,
    get_client_from_db,
    generate_jwt,
    decode_jwt,
    compute_at_hash,
    verify_pkce_code_challenge,
)

app = Blueprint("api", __name__)


class OAuthError(Exception):
    """
    Error response as defined in RFC 6749 section 5.2 (and RFC 6750 section 3)
    """

    def __init__(
        self,
        error: str,
        description: str | None = None,
        *,
        status: int = 400,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(error, description)
        self.error = error
        self.description = description
        self.status = status
        self.headers = headers or {}


def no_store(response: Response) -> Response:
    # RFC 6749 section 5.1: token responses contain credentials
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@app.errorhandler(OAuthError)
def oauth_error_handler(exc: OAuthError):
    body = {"error": exc.error}
    if exc.description:
        body["error_description"] = exc.description
    response = no_store(jsonify(body))
    response.status_code = exc.status
    response.headers.update(exc.headers)
    return response


# map remaining (e.g. abort()) errors to the OAuth error format as well,
# as clients detect failures by the "error" member.
HTTP_STATUS_ERRORS = {
    400: "invalid_request",
    401: "invalid_client",
    403: "access_denied",
    404: "not_found",
    500: "server_error",
}


@app.errorhandler(500)
@app.errorhandler(404)
@app.errorhandler(403)
@app.errorhandler(401)
@app.errorhandler(400)
def api_error_handler(exc):
    return oauth_error_handler(
        OAuthError(HTTP_STATUS_ERRORS[exc.code], exc.description, status=exc.code)
    )


def invalid_client(description: str) -> OAuthError:
    return OAuthError(
        "invalid_client",
        description,
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="token"'},
    )


def bearer_error(error: str, description: str, *, status: int) -> OAuthError:
    # RFC 6750 section 3: error_description must only use these characters
    description = re.sub(r"[^\x20-\x21\x23-\x5b\x5d-\x7e]", "", description)
    return OAuthError(
        error,
        description,
        status=status,
        headers={
            "WWW-Authenticate": f'Bearer error="{error}", error_description="{description}"'
        },
    )


def get_client_credentials() -> tuple[str | None, str | None]:
    """
    Returns client_id and client_secret, from either the Authorization header
    (client_secret_basic) or the form body (client_secret_post / none).
    """
    form_client_id = request.form.get("client_id") or None
    auth = request.authorization
    if auth is not None and auth.type == "basic":
        # RFC 6749 section 2.3.1: values are form-urlencoded before base64 encoding
        client_id = unquote_plus(auth.username or "")
        client_secret = unquote_plus(auth.password or "")
        if form_client_id is not None and form_client_id != client_id:
            raise OAuthError("invalid_request", "client_id mismatch")
        return client_id or None, client_secret or None

    return form_client_id, request.form.get("client_secret") or None


# scopes that result in user claims in the id_token / userinfo response
USER_CLAIM_SCOPES = frozenset({"email", "profile", "ssh_publickeys"})


def build_user_claims(user: User, scopes: list[str]) -> dict[str, Any]:
    """
    Builds the user claims for both the id_token and the userinfo endpoint,
    depending on the granted scopes.
    """
    claims: dict[str, Any] = {}
    if "email" in scopes:
        claims["email"] = user.email
        claims["email_verified"] = user.email_verified
    if "profile" in scopes:
        claims["name"] = user.name
        if user.family_name:
            claims["family_name"] = user.family_name
        if user.given_name:
            claims["given_name"] = user.given_name
        if user.picture:
            claims["picture"] = url_for("uploads", filename=user.picture, _external=True)
    if "ssh_publickeys" in scopes:
        # always a list (possibly empty) of authorized_keys formatted lines,
        # same as Kanidm does and what e.g. Gitea expects.
        claims["ssh_publickeys"] = user.ssh_publickeys_claim
    return claims


@app.route("/")
def index():
    return jsonify(foo="bar")


@app.route("/token", methods=["POST"])
@auto_commit(rollback=False)
def token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    code_verifier = request.form.get("code_verifier") or None

    if not grant_type:
        raise OAuthError("invalid_request", "Missing grant_type")
    if grant_type != "authorization_code":
        raise OAuthError("unsupported_grant_type")

    client_id, client_secret = get_client_credentials()
    if client_id is None:
        raise invalid_client("Missing client credentials")

    client = get_client_from_db(client_id)
    if client is None:
        raise invalid_client("Invalid client credentials")

    if not client.is_public:
        if client_secret is None or not client.verify_secret(client_secret):
            raise invalid_client("Invalid client credentials")

    if not code:
        raise OAuthError("invalid_request", "Missing code")
    if not redirect_uri:
        raise OAuthError("invalid_request", "Missing redirect_uri")

    auth_code: AuthorizationCode = AuthorizationCode.query.filter(
        AuthorizationCode.code == code
    ).first()
    if auth_code is None:
        raise OAuthError("invalid_grant", "Unknown, expired or already used code")

    if auth_code.client_id != client.client_id:
        raise OAuthError("invalid_grant", "Code was issued to another client")

    if auth_code.redirect_uri != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri mismatch")

    if auth_code.expires < now():
        # expired, can be safely deleted.
        db.session.delete(auth_code)
        raise OAuthError("invalid_grant", "Unknown, expired or already used code")

    if auth_code.user is None or not auth_code.user.is_active:
        # user has been deleted or deactivated/blocked.
        db.session.delete(auth_code)
        raise OAuthError("invalid_grant", "No related user or user is inactive")

    if auth_code.code_challenge:
        if not code_verifier or not verify_pkce_code_challenge(
            code_verifier, auth_code.code_challenge
        ):
            raise OAuthError("invalid_grant", "PKCE verification failed")
    elif code_verifier or client.is_public:
        # public clients always need PKCE, which the auth endpoint enforces.
        raise OAuthError("invalid_grant", "PKCE verification failed")

    # generate access_token and optionally id_token
    ks = get_latest_keystore(auth_code.client.preferred_algorithm)
    kp = KeyPair.from_keystore(ks)

    access_token = generate_jwt(
        kp,
        subject=str(auth_code.user.id),
        scope=str(auth_code.scope),
        audience=str(auth_code.client_id),
        expires_in=settings.token_lifetime_seconds,
        nonce=auth_code.nonce,  # noqa
    )

    scopes = auth_code.scope.split()

    if "openid" not in scopes:
        db.session.delete(auth_code)
        # no id_token requested.
        # @TODO: add refresh_token and the necessary endpoints for that.
        return no_store(
            jsonify(
                access_token=access_token,
                token_type="Bearer",
                expires_in=settings.token_lifetime_seconds,
            )
        )

    claims = build_user_claims(auth_code.user, scopes)

    id_token = generate_jwt(
        kp,
        subject=str(auth_code.user.id),
        scope=str(auth_code.scope),
        audience=str(auth_code.client_id),
        expires_in=settings.token_lifetime_seconds,
        auth_time=int(auth_code.auth_time.timestamp()),
        at_hash=compute_at_hash(access_token, kp.alg),
        nonce=auth_code.nonce,  # noqa
        **claims,
    )

    db.session.delete(auth_code)
    return no_store(
        jsonify(
            id_token=id_token,
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.token_lifetime_seconds,
        )
    )


@app.route("/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization", None)
    if auth_header is None:
        # RFC 6750 section 3.1: no error code if no authentication was attempted
        raise OAuthError(
            "invalid_request",
            "Missing Authorization header",
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        token_type, token_string = auth_header.split()
    except ValueError:
        raise bearer_error(
            "invalid_request", "Malformed Authorization header", status=400
        )

    if token_type.lower() != "bearer":
        raise bearer_error(
            "invalid_request", "Only Bearer tokens are supported", status=400
        )

    try:
        payload = decode_jwt(token_string)
    except jwt.exceptions.InvalidTokenError as e:
        raise bearer_error("invalid_token", f"Invalid token: {e}", status=401)

    scopes = payload.get("scope", "").split()

    if "openid" not in scopes and not set(scopes) & USER_CLAIM_SCOPES:
        raise bearer_error(
            "insufficient_scope", "Token has no openid or user claim scope", status=403
        )

    try:
        user_id = UUID(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise bearer_error("invalid_token", "Missing or invalid sub claim", status=401)

    user: User | None = User.query.filter_by(id=user_id).first()
    if user is None or not user.is_active:
        raise bearer_error(
            "invalid_token", "No related user or user is inactive", status=401
        )

    user_info: dict[str, Any] = {"sub": str(user_id)}
    user_info.update(build_user_claims(user, scopes))

    return jsonify(user_info)
