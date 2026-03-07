from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    BooleanField,
    EmailField,
    SelectField,
)
from wtforms.validators import DataRequired, Email

from openid_server.types import KeyAlgorithm
from .utils import strip_filter


class AdminEditUserForm(FlaskForm):
    name = StringField(
        "Your display name",
        validators=[DataRequired()],
        render_kw={"autocomplete": "off"},
        filters=[strip_filter],
    )
    email = EmailField(
        "Your e-mail address",
        validators=[DataRequired(), Email()],
        render_kw={"autocomplete": "off"},
        filters=[strip_filter],
    )
    family_name = StringField(
        "Family name", render_kw={"autocomplete": "off"}, filters=[strip_filter]
    )
    given_name = StringField(
        "Given name", render_kw={"autocomplete": "off"}, filters=[strip_filter]
    )
    delete_picture = BooleanField("Delete picture")


class AdminCreateKey(FlaskForm):
    algorithm = SelectField(
        "Algorithm",
        choices=KeyAlgorithm.choices(recommended=KeyAlgorithm.RS256),
        validators=[DataRequired()],
    )
