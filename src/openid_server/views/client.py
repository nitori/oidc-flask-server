from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    abort,
)
from flask_login import login_required, current_user

from openid_server import db
from openid_server.security import (
    generate_client_secret,
)
from openid_server.models import Client
from openid_server.views.forms import ClientForm

app = Blueprint("client", __name__)


@app.route("/")
@login_required
def index():
    return render_template("app/index.html")


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

        db.session.add(client)
        db.session.commit()

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

        if form.data["generate_new_secret_key"]:
            client.client_secret = generate_client_secret()
            flash("New client secret generated!", category="warning")

        db.session.add(client)
        db.session.commit()
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
