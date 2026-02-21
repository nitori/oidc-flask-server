from functools import partial
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import render_template

from openid_server.settings import settings, MailSSLType


def send_email(to: str, subject: str, template: str, **context):
    if settings.mail_ssl_type == MailSSLType.NATIVE:
        smtp_obj = partial(smtplib.SMTP_SSL, context=ssl.create_default_context())
    else:  # MailSSLType.NONE | MailSSLType.STARTTLS
        smtp_obj = smtplib.SMTP

    with smtp_obj(settings.mail_server, settings.mail_port) as server:
        if settings.mail_ssl_type == MailSSLType.STARTTLS:
            server.starttls(context=ssl.create_default_context())
        server.login(settings.mail_username, settings.mail_password)

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = settings.mail_sender
        message["To"] = to

        html_body = render_template(template, **context)
        html_part = MIMEText(html_body, "html")
        message.attach(html_part)

        server.sendmail(settings.mail_sender, to, message.as_string())
