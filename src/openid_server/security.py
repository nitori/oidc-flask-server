from pathlib import Path
from typing import overload
import base64
import time
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urljoin
import hashlib

from flask import request, current_app, abort
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from openid_server.settings import settings
from openid_server.types import (
    KeyAlgorithm,
    KeyPair,
    CodeChallengeMethod,
    UploadLocation,
)

if TYPE_CHECKING:
    from openid_server.models import KeyStore, Client

pw_context = CryptContext(
    schemes=["argon2"],
    argon2__type="ID",
    argon2__time_cost=4,
    argon2__memory_cost=256 * 1024,
    argon2__parallelism=4,
    argon2__salt_size=16,
    argon2__digest_size=32,
)


def get_latest_keystore(preferred_algorithm: KeyAlgorithm | None = None) -> KeyStore:
    from openid_server.models import KeyStore

    ks = None

    # try to find the latest key matching the preference
    if preferred_algorithm is not None:
        ks = (
            KeyStore.query.order_by(KeyStore.created.desc())
            .filter(KeyStore.alg == preferred_algorithm)
            .first()
        )

    if ks is None:
        # if not found, use whatever the latest key is
        ks = KeyStore.query.order_by(KeyStore.created.desc()).first()

    if ks is None:
        abort(500, "No key available at the moment")

    return ks


def get_keypair_from_db(kid: str) -> KeyPair | None:
    from openid_server.models import KeyStore

    ks: KeyStore = KeyStore.query.filter_by(id=kid).first()
    if not ks:
        return None
    return KeyPair.from_keystore(ks)


def generate_client_id():
    return secrets.token_hex(16)


def generate_client_secret():
    return secrets.token_urlsafe(32)


def get_client_from_db(client_id: str) -> Client | None:
    from .models import Client

    return Client.query.filter_by(client_id=client_id).first()


def generate_key_pair(alg: KeyAlgorithm = KeyAlgorithm.EdDSA) -> KeyPair:
    if alg == KeyAlgorithm.EdDSA:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        kid = f"ed25519-{secrets.token_urlsafe(12)}"
    elif alg == KeyAlgorithm.RS256:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # 2048 is the most widely accepted size
        )
        public_key = private_key.public_key()
        kid = f"rsa-{secrets.token_urlsafe(12)}"
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")
    return KeyPair(alg=alg, kid=kid, pub=public_key, sec=private_key)


def generate_jwt(
    kp: KeyPair,
    /,
    subject: str | int,
    scope: str,
    audience: str,
    expires_in: int,
    nonce: str | None = None,
    **extra_claims,
):
    if nonce is not None:
        extra_claims["nonce"] = nonce

    payload = {
        "iss": settings.issuer,
        "sub": subject,
        "aud": audience,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
        "jti": secrets.token_urlsafe(16),
        "scope": " ".join(scope.split()),
        **extra_claims,
    }
    return jwt.encode(payload, kp.sec, algorithm=kp.alg, headers={"kid": kp.kid})


@overload
def decode_jwt(jwt_string: str) -> tuple[dict, Client]: ...


@overload
def decode_jwt(jwt_string: str, *, aud: None) -> tuple[dict, Client]: ...


@overload
def decode_jwt(jwt_string: str, *, aud: str) -> tuple[dict, None]: ...


def decode_jwt(jwt_string, *, aud=None):
    try:
        header = jwt.get_unverified_header(jwt_string)
        kid = header["kid"]
    except (KeyError, TypeError):
        raise InvalidTokenError("Missing or invalid kid in JWT header")

    keypair = get_keypair_from_db(kid)
    if not keypair:
        raise InvalidTokenError("Unknown Key ID")

    client = None
    if aud is None:
        # just extract the payload to quickly get the audience (client_id).
        unverified_payload = jwt.decode(
            jwt_string,
            keypair.pub,
            options={"verify_signature": False},
        )

        aud = unverified_payload.get("aud")
        if not isinstance(aud, str):
            raise InvalidTokenError("Invalid or missing audience claim")

        client = get_client_from_db(aud)
        if client is None:
            raise InvalidTokenError("Invalid audience claim. No such client.")

    payload = jwt.decode(
        jwt_string,
        keypair.pub,
        options={"strict_aud": True},  # only str allowed for audience, not list[str]
        issuer=settings.issuer,
        audience=aud,
        algorithms=[keypair.alg],
    )

    return payload, client


def compute_at_hash(access_token: str) -> str:
    hash_obj = hashlib.sha512(access_token.encode("ascii"))
    digest = hash_obj.digest()
    half_digest = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(half_digest).decode("ascii").rstrip("=")


def is_safe_url(target):
    """
    Validate if the target URL is safe (same origin as current request).
    Handles both relative and absolute URLs.
    """
    ref_url = urlparse(request.host_url)  # Current request's base URL (scheme + netloc)
    test_url = urlparse(
        urljoin(request.host_url, target)
    )  # Resolve target against base
    return (
        test_url.scheme in ("http", "https")  # Valid schemes
        and test_url.netloc == ref_url.netloc  # Same host + port
    )


def create_pkce_pair(method: CodeChallengeMethod = CodeChallengeMethod.S256):
    if method != CodeChallengeMethod.S256:
        raise ValueError(f"Invalid code_challenge_method: {method}")
    code_verifier = secrets.token_urlsafe(43)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def verify_pkce_code_challenge(code_verifier: str, code_challenge: str) -> bool:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


def move_uploaded_file(upload: FileStorage, location: UploadLocation):
    """
    returns the path relative to: app.root_path / 'static'
    """
    filename = secure_filename(upload.filename)
    relative_upload_path = Path(location.value, filename)
    relative_upload_path = relative_upload_path.with_stem(
        f"{relative_upload_path.stem}_{secrets.token_hex(8)}"
    )

    upload_folder = Path(current_app.root_path) / current_app.config["UPLOAD_FOLDER"]
    full_path = upload_folder / relative_upload_path
    full_path.parent.mkdir(parents=True, exist_ok=True)

    upload.save(full_path)
    return str(relative_upload_path).replace("\\", "/")


def delete_uploaded_file(relative_upload_path: str):
    upload_folder = Path(current_app.root_path) / current_app.config["UPLOAD_FOLDER"]
    full_path = upload_folder / relative_upload_path
    full_path.unlink(missing_ok=True)
