from typing import Self
import base64
from typing import NamedTuple, TYPE_CHECKING
from enum import StrEnum

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

if TYPE_CHECKING:
    from openid_server.models import KeyStore


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
