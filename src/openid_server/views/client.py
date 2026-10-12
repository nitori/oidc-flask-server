from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    abort,
    session,
)
from flask_login import login_required, current_user

from openid_server import db
from openid_server.models import Client
from openid_server.views.forms import ClientForm

app = Blueprint("client", __name__)


def show_secret_once(client: Client, secret: str):
    """
    Only the hash of the secret is stored, so pass the clear text secret
    to the next rendering of the app list, which will show it once.
    """
    session["new_client_secret"] = {"client_id": client.client_id, "secret": secret}


@app.route("/")
@login_required
def index():
    new_secret = session.pop("new_client_secret", None)
    return render_template("app/index.html", new_secret=new_secret)


@app.route("/new-app", methods=["GET", "POST"])
@login_required
def new_app():
    form = ClientForm()
    if form.validate_on_submit():
        client = Client()
        form.populate_obj(client)
        client.user = current_user
        assert isinstance(client.redirect_uris, list), (
            "Redirect URIs was not converted to a list"
        )
        assert isinstance(client.post_logout_redirect_uris, list), (
            "Redirect URIs was not converted to a list"
        )
        secret = client.generate_secret()

        db.session.add(client)
        db.session.commit()

        if not client.is_public:
            show_secret_once(client, secret)

        return redirect(url_for("client.index", _anchor=f"client-{client.client_id}"))

    return render_template("app/new_app.html", form=form)


@app.route("/edit-app/<client_id>", methods=["GET", "POST"])
@login_required
def edit_app(client_id: str):
    client: Client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        abort(404, "No such client")

    if client.user != current_user:
        abort(403)

    form = ClientForm(obj=client)
    # we don't use recaptcha for editing, only creationg (above)
    del form.recaptcha

    if form.validate_on_submit():
        form.populate_obj(client)
        assert isinstance(client.redirect_uris, list), (
            "Redirect URIs was not converted to a list"
        )
        assert isinstance(client.post_logout_redirect_uris, list), (
            "Redirect URIs was not converted to a list"
        )

        secret = None
        if form.data["generate_new_secret_key"]:
            secret = client.generate_secret()
            flash("New client secret generated!", category="warning")

        db.session.add(client)
        db.session.commit()

        if secret is not None:
            show_secret_once(client, secret)
        flash(
            f"Client {client.name!r} ({client.client_id}) updated!", category="success"
        )

        return redirect(url_for("client.index", _anchor=f"client-{client.client_id}"))

    form._fields["generate_new_secret_key"].data = False
    return render_template("app/edit_app.html", client=client, form=form)


@app.route("/delete-app/<client_id>", methods=["POST"])
@login_required
def delete_app(client_id: str):
    client: Client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        abort(404, "No such client")

    if client.user != current_user:
        abort(403)

    db.session.delete(client)
    db.session.commit()

    flash(f"App {client.name} successfully deleted!")
    return redirect(url_for("client.index", _anchor="apps-tab-pane"))
