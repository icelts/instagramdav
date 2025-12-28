import os
from pathlib import Path
import base64
import hashlib
import hmac
import struct
import time

from instagrapi import Client


def load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return

    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        os.environ.setdefault(key, value)


def generate_totp(secret: str, interval: int = 30, digits: int = 6) -> str:
    clean = secret.strip().replace(" ", "").upper()
    if len(clean) % 8:
        clean += "=" * (8 - len(clean) % 8)
    key = base64.b32decode(clean, casefold=True)
    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{code % (10 ** digits):0{digits}d}"


def main() -> None:
    load_dotenv(Path(__file__).with_name(".env"))

    username = os.environ["IG_USERNAME"]
    password = os.environ["IG_PASSWORD"]
    code = os.getenv("IG_2FA_CODE")
    secret = os.getenv("IG_2FA_SECRET")
    proxy = os.getenv("IG_PROXY")
    session_path = Path(os.getenv("IG_SESSION_PATH", "session.json"))

    cl = Client()
    if proxy:
        cl.set_proxy(proxy)

    if session_path.exists():
        cl.load_settings(session_path)

    if code and not code.isdigit() and not secret:
        secret = code
        code = None

    if not code and secret:
        code = generate_totp(secret)

    cl.login(username, password, verification_code=code)
    cl.dump_settings(session_path)
    print(f"Login OK (session saved to {session_path})")


if __name__ == "__main__":
    main()
