from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileAllowed, FileSize
from wtforms import (
    StringField,
    BooleanField,
    EmailField,
    PasswordField,
)
from wtforms.fields.choices import SelectField
from wtforms.fields.simple import HiddenField
from wtforms.validators import DataRequired, Email

from .utils import strip_filter, TextAreaListField, WrappedFileField
from openid_server.security import KeyAlgorithm
from openid_server.settings import settings


class SignUpForm(FlaskForm):
    name = StringField(
        "Your name",
        validators=[DataRequired()],
        render_kw={"autocomplete": "nickname"},
        filters=[strip_filter],
    )
    email = EmailField(
        "Your e-mail address",
        validators=[DataRequired(), Email()],
        render_kw={"autocomplete": "email"},
        filters=[strip_filter],
    )
    password = PasswordField(
        "Your password",
        validators=[DataRequired()],
        render_kw={"autocomplete": "new-password"},
        filters=[strip_filter],
    )


class LoginForm(FlaskForm):
    next = HiddenField()
    email = EmailField(
        "Your e-mail address",
        validators=[DataRequired(), Email()],
        render_kw={"autocomplete": "email"},
        filters=[strip_filter],
    )
    password = PasswordField(
        "Your password",
        validators=[DataRequired()],
        render_kw={"autocomplete": "new-password"},
        filters=[strip_filter],
    )


class ClientForm(FlaskForm):
    name = StringField(
        "App Name",
        validators=[DataRequired()],
        render_kw={"autocomplete": "off"},
        filters=[strip_filter],
    )
    is_public = BooleanField(
        "Is Public",
        default=True,
        description=(
            "Public clients cannot maintain the confidentiality of their client credentials (i.e. "
            "desktop/mobile applications that do not use a server to make requests)"
        ),
    )
    generate_new_secret_key = BooleanField(
        "Generate new client secret",
        description=(
            "when checked, submitting the form will generate a new secret key for this client. "
            "This CANNOT be undone.\n"
            "Only meaningful for non-public clients."
        ),
    )
    preferred_algorithm = SelectField(
        "Preferred Algorithm",
        choices=KeyAlgorithm.choices(
            include_empty=False, recommended=KeyAlgorithm.RS256
        ),
    )
    redirect_uris = TextAreaListField(
        "Redirect URIs",
        render_kw={"autocomplete": "off"},
        description="One URI per line",
    )


class UserForm(FlaskForm):
    name = StringField(
        "Your display name",
        validators=[DataRequired()],
        render_kw={"autocomplete": "nickname"},
        filters=[strip_filter],
    )
    email = EmailField(
        "Your e-mail address",
        validators=[DataRequired(), Email()],
        render_kw={"autocomplete": "email"},
        filters=[strip_filter],
    )

    family_name = StringField(
        "Family name", render_kw={"autocomplete": "family-name"}, filters=[strip_filter]
    )
    given_name = StringField(
        "Given name", render_kw={"autocomplete": "given-name"}, filters=[strip_filter]
    )
    picture = WrappedFileField(
        "Picture",
        validators=[
            FileAllowed(["jpg", "png", "webp"], "Images only"),
            FileSize(1 << 19),  # 512 KiB
        ],
    )


if settings.recaptcha_site:
    SignUpForm.recaptcha = RecaptchaField()
    ClientForm.recaptcha = RecaptchaField()
