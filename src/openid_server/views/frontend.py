from textwrap import dedent
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from flask import (
    Blueprint,
    render_template,
    request,
    abort,
    jsonify,
    redirect,
    url_for,
    current_app,
    session,
)
from flask_login import current_user, logout_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from markupsafe import escape

from openid_server import db
from openid_server.types import (
    KeyPair,
    CodeChallengeMethod,
    ResponseType,
    ResponseMode,
    AuthParameters,
)
from openid_server.models import KeyStore, AuthorizationCode, Client
from openid_server.utils import until
from openid_server.settings import settings

app = Blueprint("frontend", __name__)


@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("user.login"))
    return redirect(url_for("user.index"))


@app.route("/docs")
def docs():
    return render_template("docs.html")


def user_has_consented(client_id: str, requested_scopes: list[str]) -> bool:
    # session["consented_scopes"] = { "client-123": ["openid", "email", "profile"], ... }
    consented = session.get("consented_scopes", {}).get(client_id, [])
    return set(requested_scopes).issubset(set(consented))


def save_consent(client_id: str, approved_scopes: list[str]):
    if "consented_scopes" not in session:
        session["consented_scopes"] = {}

    session["consented_scopes"][client_id] = approved_scopes
    session.modified = True


def issue_code_and_redirect(params: AuthParameters):
    # generate "code" and redirect to redirect_uri
    auth_code = AuthorizationCode(
        user=current_user,
        redirect_uri=params.redirect_uri,
        client_id=params.client_id,
        expires=until(seconds=settings.authorization_code_lifetime_seconds),
        scope=params.scope,
        response_mode=params.response_mode.value,
        code_challenge=params.code_challenge,
        code_challenge_method=params.code_challenge_method.value,
        nonce=params.nonce,
    )
    db.session.add(auth_code)
    db.session.commit()

    if params.response_mode == ResponseMode.form_post:
        return generate_form_post(
            params.redirect_uri,
            code=str(auth_code.code),
            state=params.state,
        )
    query = {
        "code": [str(auth_code.code)],
        "state": [params.state],
    }
    return redirect(make_redirect_uri(params, query))


def error_and_redirect(params: AuthParameters, error: str, error_description: str):
    if params.response_mode == ResponseMode.form_post:
        return generate_form_post(
            params.redirect_uri,
            error=error,
            state=params.state,
            error_description=error_description,
        )
    redirect_uri = make_redirect_uri(
        params,
        {
            "error": [error],
            "state": [params.state],
            "error_description": [error_description],
        },
    )
    return redirect(redirect_uri, 303)


def generate_form_post(redirect_uri: str, **parameters: str) -> str:
    hidden_fields = []
    parameters["iss"] = settings.issuer
    for key, value in parameters.items():
        hidden_fields.append(
            f'<input type="hidden" name="{escape(key)}" value="{escape(value)}">'
        )
    hidden_fields_html = "\n".join(hidden_fields)

    return dedent(f'''\
        <html>
        <body onload="document.forms[0].submit()">
            <form method="POST" action="{escape(redirect_uri)}">
                {hidden_fields_html}
                <noscript>
                    <p>Your browser does not support JavaScript.</p>
                    <button type="submit">Continue</button>
                </noscript>
            </form>
        </body>
        </html>
    ''')


def make_redirect_uri(params: AuthParameters, query: dict[str, list[str]]) -> str:
    parts = urlparse(params.redirect_uri)
    base_query = parse_qs(parts.query)
    base_query.update(query)
    base_query["iss"] = settings.issuer

    if params.response_mode == ResponseMode.fragment:
        parts = parts._replace(fragment=urlencode(base_query, doseq=True))
    else:
        parts = parts._replace(query=urlencode(base_query, doseq=True))

    # noinspection PyTypeChecker
    return urlunparse(parts)


@app.route("/auth")
def auth():
    params = AuthParameters(
        client_id=request.args["client_id"],
        response_type=ResponseType(request.args["response_type"]),
        response_mode=ResponseMode(request.args.get("response_mode", "query")),
        code_challenge=request.args.get("code_challenge", None) or None,
        code_challenge_method=CodeChallengeMethod(
            request.args.get("code_challenge_method", "S256")
        ),
        redirect_uri=request.args["redirect_uri"],
        scope=request.args["scope"],
        state=request.args["state"],
        nonce=request.args.get("nonce"),
    )
    try:
        params.basic_validate()
    except ValueError as exc:
        abort(400, exc.args[0])

    client: Client = Client.query.filter_by(client_id=params.client_id).first()
    if client is None:
        abort(404, "No such client")

    if params.redirect_uri not in client.redirect_uris:
        abort(404, "Invalid redirect_uri")

    if client.is_public:
        if not params.code_challenge:
            abort(400, "Public clients MUST use PKCE. code_challenge is missing.")

    prompt = request.args.get("prompt", "").strip().lower()
    prompts = set(prompt.split())

    if "none" in prompts:
        if not current_user.is_authenticated:
            return error_and_redirect(
                params, "login_required", "User is required to login"
            )
        # noinspection PyTypeChecker
        if not user_has_consented(client.client_id, params.scope.split()):
            return error_and_redirect(
                params, "consent_required", "User needs to consent to extended scope"
            )
        return issue_code_and_redirect(params)

    if "login" in prompts:
        logout_user()

    # noinspection PyTypeChecker
    if (
        current_user.is_authenticated
        and user_has_consented(
            client.client_id,
            params.scope.split(),
        )
        and "consent" not in prompts
    ):
        return issue_code_and_redirect(params)

    if not current_user.is_authenticated:
        return redirect(url_for("user.login", next=request.url))

    serializer = URLSafeTimedSerializer(current_app.secret_key)
    signed_params = serializer.dumps(params)

    # consent
    return render_template(
        "auth.html",
        client=client,
        signed_params=signed_params,
        params=params,
        scopes=params.scope.split(),
    )


@app.route("/auth/post", methods=["POST"])
def auth_post():
    if not current_user.is_authenticated:
        # straigth up error. no chance for login
        abort(401)

    action = request.form["action"]
    signed_params = request.form["params"]

    serializer = URLSafeTimedSerializer(current_app.secret_key)
    try:
        params = serializer.loads(signed_params, max_age=300)  # 5-min max age
    except (SignatureExpired, BadSignature):
        abort(400, "Invalid or expired parameters")

    params = AuthParameters.from_str_params(*params)
    try:
        params.basic_validate()
    except ValueError as exc:
        abort(400, exc.args[0])

    if action == "authorize":
        save_consent(params.client_id, params.scope.split())
        return issue_code_and_redirect(params)
    elif action == "deny":
        return error_and_redirect(
            params, "access_denied", "The user declined the access."
        )

    abort(400, "Invalid authorization step")


@app.route("/.well-known/jwks.json")
def well_known_jwks():
    keys = []
    for key in KeyStore.query.all():
        kp = KeyPair.from_keystore(key)
        keys.append(kp.generate_jwks_entry())

    return jsonify(keys=keys)


@app.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify(
        # settings.issuer is origin of a domain.
        # maybe separate each field later or something, but this should do for now.
        issuer=settings.issuer,
        authorization_endpoint=url_for("frontend.auth", _external=True),
        token_endpoint=url_for("api.token", _external=True),
        userinfo_endpoint=url_for("api.userinfo", _external=True),
        jwks_uri=url_for("frontend.well_known_jwks", _external=True),
        response_modes_supported=[
            "query",
            "fragment",
            "form_post",
        ],
        scopes_supported=[
            "openid",
            "email",
            "profile",
        ],
        claims_supported=[
            # openid
            "aud",
            "exp",
            "iat",
            "iss",
            "sub"
            # email
            "email",
            "email_verified",
            # profile
            "name",
            "family_name",
            "given_name",
            "picture",
        ],
        prompt_values_supported=[
            "none",
            "login",
            "consent",
            # "select_account"
        ],
        code_challenge_methods_supported=["S256"],
    )


@app.route("/.well-known/security.txt")
def security_txt():
    now = datetime.now(tz=timezone.utc)
    expires = (now + timedelta(days=365)).replace(microsecond=0)
    expires_str = expires.isoformat(timespec="seconds").replace("+00:00", "Z")

    return (
        dedent(f"""\
    Canonical: {settings.issuer}/.well-known/security.txt
    Contact: mailto:{settings.wk_security_contact}
    Expires: {expires_str}
    Preferred-Languages: {", ".join(settings.wk_security_languages)}
    """).rstrip(),
        200,
        {"Content-Type": "text/plain"},
    )


@app.route("/.well-known/change-password")
def change_password():
    return redirect(url_for("user.change_password"), code=302)
