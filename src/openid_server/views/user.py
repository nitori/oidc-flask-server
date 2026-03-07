import secrets
from uuid import UUID

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
)
from flask_login import login_required, login_user, current_user, logout_user
from jwt import InvalidTokenError
from werkzeug.datastructures import FileStorage

from openid_server import db
from openid_server.types import KeyAlgorithm, UploadLocation, KeyPair
from openid_server.security import (
    is_safe_url,
    move_uploaded_file,
    delete_uploaded_file,
    decode_jwt,
    generate_jwt,
    get_latest_keystore,
)
from openid_server.models import User
from openid_server.email import send_email
from openid_server.settings import settings
from openid_server.views.forms import UserForm, SignUpForm, LoginForm

app = Blueprint("user", __name__)


def create_email_verification_key(sub: UUID, email: str, euk: str):
    ks = get_latest_keystore(KeyAlgorithm.EdDSA)
    return generate_jwt(
        KeyPair.from_keystore(ks),
        subject=str(sub),
        scope="",
        audience=settings.issuer,
        expires_in=86400,
        nonce=euk,
        email=email,
    )


@app.route("/")
@login_required
def index():
    return render_template("user/index.html")


@app.route("/edit-user", methods=["GET", "POST"])
@login_required
def edit_user():
    user: User = current_user

    form = UserForm(obj=user)
    if form.validate_on_submit():
        old_email: str = user.email  # noqa
        new_email: str = form.data["email"]

        user.name = form.data["name"]
        user.family_name = form.data["family_name"]
        user.given_name = form.data["given_name"]

        picture: FileStorage = form.data["picture"]
        if picture:
            if user.picture:
                delete_uploaded_file(user.picture)  # noqa
            user.picture = move_uploaded_file(picture, UploadLocation.images)

        if old_email.casefold() != new_email.casefold():
            user.email_update_key = secrets.token_urlsafe(12)
            send_email(
                str(new_email),
                "Welcome to OIDC Server. Please verify your e-mail address.",
                "emails/verify_email.html",
                jwt_key=create_email_verification_key(
                    user.id, new_email, user.email_update_key
                ),
            )
            flash(
                "Please check your inbox to verify your new email address.",
                category="warning",
            )

        db.session.add(user)
        db.session.commit()
        flash("User was updated")
        return redirect(url_for("user.index", _anchor="overview-tab-pane"))

    return render_template("user/edit_user.html", form=form)


@app.route("/change-password")
@login_required
def change_password():
    return render_template("user/change_password.html")


@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.data["email"]).first()
        if user is None:
            new_user = User()
            form.populate_obj(new_user)
            new_user.email_update_key = secrets.token_urlsafe(12)

            db.session.add(new_user)
            db.session.commit()

            send_email(
                str(new_user.email),
                "Welcome to OIDC Server. Please verify your e-mail address.",
                "emails/verify_email.html",
                jwt_key=create_email_verification_key(
                    new_user.id, new_user.email, new_user.email_update_key
                ),
            )
            flash(
                "Please check your inbox to verify your new email address.",
                category="warning",
            )
            return redirect(url_for("user.login"))
        flash("Cannot use this e-mail address", category="danger")

    return render_template("user/sign_up.html", form=form)


@app.route("/verify-email/<jwt_key>")
def verify_email(jwt_key: str):
    try:
        payload, _ = decode_jwt(jwt_key, aud=settings.issuer)
    except InvalidTokenError:
        abort(404, "Invalid/unknown key")

    user: User = User.query.filter(
        User.id == UUID(payload["sub"]), User.email_update_key == payload["nonce"]
    ).first()
    if user is None:
        abort(404, "Invalid/unknown key")

    # only now is the email updated.
    user.email = payload["email"]
    user.email_verified = True
    user.email_update_key = None

    db.session.add(user)
    db.session.commit()

    if current_user.is_authenticated:
        flash("User email verified. Welcome onboard!", category="success")
        return redirect(url_for("user.index"))

    flash("User email verified. You can now login!", category="success")
    return redirect(url_for("user.login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if next_url := request.args.get("next"):
        if not is_safe_url(next_url):
            return redirect(url_for("user.login"))

    form = LoginForm(data={"next": next_url})

    if form.validate_on_submit():
        email = form.data["email"]
        password = form.data["password"]

        user: User | None = User.query.filter_by(email=email).first()
        if user and user.verify_password(password):
            login_user(user, remember=True)
            if next_url := form.data.get("next"):
                if is_safe_url(next_url):
                    return redirect(next_url)
            return redirect(url_for("user.index"))
        flash("Invalid credentials", category="danger")

    return render_template("user/login.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("user.login"))
