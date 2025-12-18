import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken


def _derive_key(secret: str) -> bytes:
    # 使用 SHA256 对秘密进行派生，再转为 urlsafe key
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class CredentialCipher:
    def __init__(self, secret: str):
        if not secret:
            raise ValueError("缺少用于加密凭据的 SECRET_KEY")
        self._fernet = Fernet(_derive_key(secret))

    def encrypt(self, data: str) -> str:
        return self._fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("凭据解密失败") from exc
