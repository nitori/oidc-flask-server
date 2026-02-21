from uuid import UUID

from flask import Blueprint, render_template, abort, redirect, url_for, flash
from flask_login import current_user

from openid_server import db
from openid_server.models import User, KeyStore
from openid_server.security import delete_uploaded_file, KeyAlgorithm, generate_key_pair
from openid_server.views.forms.admin import AdminEditUserForm, AdminCreateKey

app = Blueprint("admin", __name__)


@app.before_request
def limit_access():
    if current_user.is_authenticated and current_user.is_admin:
        return

    abort(404)


@app.route("/")
def index():
    return render_template("admin/index.html")


@app.route("/user-management", endpoint="users")
def user_management():
    users = User.query.order_by(User.name.asc()).all()
    return render_template("admin/users.html", users=users)


@app.route("/edit-user/<uuid:user_id>", methods=["GET", "POST"])
def user_edit(user_id: UUID):
    user: User = User.query.get_or_404(user_id)
    form = AdminEditUserForm(obj=user)
    if form.validate_on_submit():
        user.name = form.data["name"]
        user.email = form.data["email"]
        user.family_name = form.data["family_name"]
        user.given_name = form.data["given_name"]
        if form.data["delete_picture"]:
            delete_uploaded_file(str(user.picture))
            user.picture = ""

        db.session.add(user)
        db.session.commit()
        flash(f"User {user.name!r} ({user.id}) was updated.", category="success")

    form._fields["delete_picture"].data = False
    return render_template("admin/user_edit.html", user=user, form=form)


@app.route("/delete-user/<uuid:user_id>", methods=["POST"])
def user_delete(user_id: UUID):
    if current_user.id == user_id:
        abort(403, "Can't delete yourself.")

    user: User = User.query.get_or_404(user_id)
    if user.picture:
        delete_uploaded_file(str(user.picture))
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.name!r} ({user.id}) succesfully deleted!")
    return redirect(url_for("admin.users"))


@app.route("/key-management", endpoint="keys")
def key_management():
    keys = KeyStore.query.order_by(KeyStore.created.asc()).all()
    form = AdminCreateKey()
    return render_template("admin/keys.html", keys=keys, form=form)


@app.route("/create-key", methods=["POST"])
def key_create():
    form = AdminCreateKey()
    if form.validate_on_submit():
        algorithm = KeyAlgorithm(form.data["algorithm"])
        kp = generate_key_pair(algorithm)
        ks = kp.to_keystore()
        db.session.add(ks)
        db.session.commit()
        flash(f"Key created! ({ks.id})", category="success")
        return redirect(url_for("admin.keys"))
    flash("Form validation error", category="danger")
    return redirect(url_for("admin.keys"))


@app.route("/delete-key/<key_id>", methods=["POST"])
def key_delete(key_id: str):
    ks: KeyStore = KeyStore.query.get_or_404(key_id)
    db.session.delete(ks)
    db.session.commit()
    flash(f"Key {ks.id!r} succesfully deleted!")
    return redirect(url_for("admin.keys"))
