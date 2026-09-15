from typing import Self
import base64
import hashlib
from typing import NamedTuple, TYPE_CHECKING
from enum import StrEnum

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

if TYPE_CHECKING:
    from openid_server.models import KeyStore


SUPPORTED_SCOPES = ("openid", "email", "profile", "ssh_publickeys")


class MailSSLType(StrEnum):
    NONE = "NONE"
    NATIVE = "NATIVE"
    STARTTLS = "STARTTLS"


class KeyAlgorithm(StrEnum):
    RS256 = "RS256"
    EdDSA = "EdDSA"

    @classmethod
    def choices(cls, *, include_empty=True, recommended: Self | None = None):
        items = []
        if include_empty:
            items.append(("", "Please select"))
        for k, v in cls._member_map_.items():
            items.append((k, f"{v} (recommended)" if v == recommended else f"{v}"))
        return items


class UploadLocation(StrEnum):
    images = "images"


class CodeChallengeMethod(StrEnum):
    S256 = "S256"


type PublicKey = ed25519.Ed25519PublicKey | rsa.RSAPublicKey
type PrivateKey = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey


class KeyPair(NamedTuple):
    alg: KeyAlgorithm
    kid: str
    pub: PublicKey
    sec: PrivateKey

    @property
    def public_bytes(self) -> bytes:
        if self.alg == KeyAlgorithm.EdDSA:
            return self.pub.public_bytes_raw()
        else:
            return self.pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    @property
    def secret_bytes(self) -> bytes:
        if self.alg == KeyAlgorithm.EdDSA:
            return self.sec.private_bytes_raw()
        else:
            return self.sec.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def generate_jwks_entry(self):
        x_encoded = (
            base64.urlsafe_b64encode(self.public_bytes).decode("ascii").rstrip("=")
        )
        if self.alg == KeyAlgorithm.EdDSA:
            return {
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "x": x_encoded,
                "alg": "EdDSA",
                "kid": self.kid,
            }
        else:
            # RSA keys expose .public_numbers()
            pub_numbers = self.pub.public_numbers()

            # Convert big integers to bytes (big-endian)
            n_bytes = pub_numbers.n.to_bytes(
                (pub_numbers.n.bit_length() + 7) // 8, byteorder="big"
            )
            e_bytes = pub_numbers.e.to_bytes(
                (pub_numbers.e.bit_length() + 7) // 8, byteorder="big"
            )

            n_encoded = base64.urlsafe_b64encode(n_bytes).decode("ascii").rstrip("=")
            e_encoded = base64.urlsafe_b64encode(e_bytes).decode("ascii").rstrip("=")

            return {
                "kty": "RSA",
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "RS256",
                "kid": self.kid,
                "n": n_encoded,
                "e": e_encoded,
            }

    @classmethod
    def from_keystore(cls, ks: KeyStore):
        if ks.alg == KeyAlgorithm.EdDSA:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(ks.public_key)  # noqa
            sec = ed25519.Ed25519PrivateKey.from_private_bytes(ks.secret_key)  # noqa
        elif ks.alg == KeyAlgorithm.RS256:
            pub = serialization.load_der_public_key(ks.public_key)  # noqa
            sec = serialization.load_der_private_key(
                ks.secret_key,  # noqa
                password=None,
            )
        else:
            raise ValueError(f"Unknown algorithm in keystore: {ks.alg}")
        return cls(alg=ks.alg, kid=str(ks.id), pub=pub, sec=sec)

    def to_keystore(self) -> KeyStore:
        from openid_server.models import KeyStore

        key = KeyStore()
        key.alg = self.alg
        key.id = self.kid
        key.public_key = self.public_bytes
        key.secret_key = self.secret_bytes
        return key


class ResponseType(StrEnum):
    code = "code"


class ResponseMode(StrEnum):
    query = "query"
    fragment = "fragment"
    form_post = "form_post"


class AuthParameters(NamedTuple):
    client_id: str
    response_type: ResponseType
    response_mode: ResponseMode
    code_challenge: str | None
    code_challenge_method: CodeChallengeMethod
    redirect_uri: str
    scope: str
    state: str
    nonce: str | None

    @classmethod
    def from_str_params(cls, *params: str):
        """
        *params is a tuple of strings, no enums. So they need to be converted here
        """
        obj = cls(*params)
        obj = obj._replace(
            response_type=ResponseType(obj.response_type),
            response_mode=ResponseMode(obj.response_mode),
            code_challenge_method=CodeChallengeMethod(obj.code_challenge_method),
        )
        return obj

    def basic_validate(self):
        if not self.client_id:
            raise ValueError("Empty client_id")
        if not self.redirect_uri:
            raise ValueError("Empty redirect_uri")
        if not self.scope:
            raise ValueError("Empty scope")
        if not self.state:
            raise ValueError("Empty state")
        if self.response_mode == ResponseMode.fragment and not self.code_challenge:
            raise ValueError(
                "response_mode=fragment is requested but PKCE code_challenge is empty"
            )
        if (
            self.code_challenge
            and self.code_challenge_method.value != CodeChallengeMethod.S256
        ):
            raise ValueError("Invalid code_challenge_method. Only S256 is supported.")

        rest_scopes = set(self.scope.split()) - set(SUPPORTED_SCOPES)
        if rest_scopes:
            raise ValueError(
                f"Invalid scopes: {rest_scopes}. Allowed: {' '.join(SUPPORTED_SCOPES)}"
            )


class ParsedSshPublicKey(NamedTuple):
    """
    A parsed and validated OpenSSH public key (authorized_keys format).
    """

    key_type: str
    key_b64: str
    comment: str

    @property
    def fingerprint(self) -> str:
        """SHA256 fingerprint, formatted like ssh-keygen -l does"""
        digest = hashlib.sha256(base64.b64decode(self.key_b64)).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    @property
    def key_line(self) -> str:
        """The key in authorized_keys format, without a comment"""
        return f"{self.key_type} {self.key_b64}"

    @classmethod
    def parse(cls, text: str) -> Self:
        """
        Parse and validate an OpenSSH public key line.
        Raises ValueError when the text is not a valid public key.
        """
        parts = text.strip().split(None, 2)
        if len(parts) < 2:
            raise ValueError("Expected format: <key-type> <base64-key> [comment]")

        key_type, key_b64 = parts[0], parts[1]
        comment = parts[2].strip() if len(parts) == 3 else ""

        try:
            # this fails for corrupt base64 and when the key type
            # inside the blob does not match key_type
            serialization.load_ssh_public_key(f"{key_type} {key_b64}".encode("ascii"))
        except UnsupportedAlgorithm:
            raise ValueError(f"Unsupported key type: {key_type!r}")
        except (ValueError, UnicodeEncodeError) as e:
            raise ValueError(f"Invalid public key: {e}")

        return cls(key_type=key_type, key_b64=key_b64, comment=comment)
