from typing import Any
from uuid import UUID

import jwt
from flask import Blueprint, jsonify, request, abort, url_for

from openid_server import db
from openid_server.models import AuthorizationCode, User
from openid_server.utils import now, auto_commit
from openid_server.settings import settings
from openid_server.security import (
    get_latest_keystore,
    KeyPair,
    generate_jwt,
    decode_jwt,
    compute_at_hash,
    verify_pkce_code_challenge,
)

app = Blueprint("api", __name__)


@app.errorhandler(404)
@app.errorhandler(403)
@app.errorhandler(401)
@app.errorhandler(400)
def api_error_handler(exc):
    return jsonify(
        error_code=exc.code,
        message=exc.description,
    ), exc.code


@app.route("/")
def index():
    return jsonify(foo="bar")


@app.route("/token", methods=["GET", "POST"])
@auto_commit(rollback=False)
def token():
    client_id = request.form["client_id"]
    client_secret = request.form.get("client_secret", None)
    code = request.form["code"]
    grant_type = request.form["grant_type"]
    redirect_uri = request.form["redirect_uri"]
    code_verifier = request.form.get("code_verifier", None)

    if grant_type != "authorization_code":
        abort(400)

    auth_code: AuthorizationCode = AuthorizationCode.query.filter(
        AuthorizationCode.code == code
    ).first()
    if auth_code is None:
        abort(404, "no such code")

    if auth_code.client is None:
        # invalid, client probably deleted.
        db.session.delete(auth_code)
        abort(404, "no associated client")

    if auth_code.client.client_id != client_id:
        abort(404, "invalid client credentials")

    if auth_code.client.is_public:
        pass
    else:
        if auth_code.client.client_secret != client_secret:
            abort(404, "invalid client credentials")

    if auth_code.redirect_uri != redirect_uri:
        abort(404, "wrong redirect_uri")

    if auth_code.expires < now():
        # expired, can be safely deleted.
        db.session.delete(auth_code)
        abort(404, "expired")

    if auth_code.user is None or not auth_code.user.is_active:
        # user has been deleted or deactivated/blocked.
        db.session.delete(auth_code)
        abort(404, "no related user or user is inactive")

    require_pkce = auth_code.client.is_public

    if require_pkce:
        if not auth_code.code_challenge:
            abort(400, "Missing code_challenge in auth_code. This should not happen.")
        if not code_verifier:
            abort(400, "Missing code_verifier")
        if not verify_pkce_code_challenge(code_verifier, auth_code.code_challenge):  # noqa
            abort(401, "PKCE code challenge failed")
    else:
        if code_verifier:
            if not verify_pkce_code_challenge(code_verifier, auth_code.code_challenge):  # noqa
                abort(401, "PKCE code challenge failed")

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
        return jsonify(
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.token_lifetime_seconds,
        )

    claims = {}
    if "email" in scopes:
        claims["email"] = auth_code.user.email
        claims["email_verified"] = auth_code.user.email_verified
    if "profile" in scopes:
        claims["name"] = auth_code.user.name
        if auth_code.user.family_name:
            claims["family_name"] = auth_code.user.family_name
        if auth_code.user.given_name:
            claims["given_name"] = auth_code.user.given_name
        if auth_code.user.picture:
            claims["picture"] = url_for(
                "static", filename=auth_code.user.picture, _external=True
            )

    id_token = generate_jwt(
        kp,
        subject=str(auth_code.user.id),
        scope=str(auth_code.scope),
        audience=str(auth_code.client_id),
        expires_in=settings.token_lifetime_seconds,
        auth_time=int(auth_code.auth_time.timestamp()),
        at_hash=compute_at_hash(access_token),
        nonce=auth_code.nonce,  # noqa
        **claims,
    )

    db.session.delete(auth_code)
    return jsonify(
        id_token=id_token,
        access_token=access_token,
        token_type="Bearer",
        expires_in=settings.token_lifetime_seconds,
    )


@app.route("/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization", None)
    if auth_header is None:
        abort(401, "Missing Authorization header")

    try:
        token_type, token_string = auth_header.split()
    except ValueError:
        abort(400, "Malformed Authorization header")

    if token_type.lower() != "bearer":
        abort(400, "Only Bearer tokens are supported")

    try:
        payload, client = decode_jwt(token_string)
    except jwt.exceptions.InvalidTokenError as e:
        abort(401, f"Invalid token: {e}")

    scopes = payload.get("scope", "").split()

    if "email" not in scopes and "profile" not in scopes:
        abort(401)

    try:
        user_id = UUID(payload["sub"])
    except (KeyError, TypeError, ValueError):
        abort(400, "Missing or invalid sub claim")

    user: User | None = User.query.filter_by(id=user_id).first()
    if user is None:
        abort(404, "No such user")

    user_info: dict[str, Any] = {"sub": str(user_id)}

    if "email" in scopes:
        user_info["email"] = user.email
        user_info["email_verified"] = user.email_verified

    if "profile" in scopes:
        user_info["name"] = user.name
        if user.family_name:
            user_info["family_name"] = user.family_name
        if user.given_name:
            user_info["given_name"] = user.given_name
        if user.picture:
            user_info["picture"] = url_for(
                "static", filename=user.picture, _external=True
            )

    return jsonify(user_info)
