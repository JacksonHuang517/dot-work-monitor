#!/usr/bin/env python3
"""Local interactive configuration. Secrets are never printed or placed in .env."""

import argparse, base64, getpass, json, os, re, secrets, stat
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
SECRET_NAMES = (
    "feishu-app-secret",
    "internal-key",
    "state-key",
    "jwks.json",
    "cookie-keys.json",
    "auth-db-key",
    "mail-password",
)


def validate_origin(value):
    p = urlsplit(value)
    if (
        p.scheme != "https"
        or not p.hostname
        or p.username
        or p.password
        or p.path not in ("", "/")
        or p.query
        or p.fragment
    ):
        raise ValueError(
            "PUBLIC_ORIGIN must be an HTTPS origin, e.g. https://monitor.example.com"
        )
    return value.rstrip("/")


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)


def b64int(n):
    return (
        base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
        .decode()
        .rstrip("=")
    )


def generate(directory, app_secret, mail_password=""):
    if directory.is_symlink():
        raise ValueError("Secret directory must not be a symlink")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    for name in SECRET_NAMES:
        p = directory / name
        if p.exists() and (
            p.is_symlink() or not p.is_file() or stat.S_IMODE(p.stat().st_mode) != 0o600
        ):
            raise ValueError("Unsafe existing secret file")
    values = {
        "feishu-app-secret": app_secret,
        "mail-password": mail_password,
        "internal-key": secrets.token_urlsafe(48),
        "state-key": Fernet.generate_key().decode(),
        "auth-db-key": base64.b64encode(secrets.token_bytes(32)).decode(),
        "cookie-keys.json": json.dumps([secrets.token_urlsafe(48)]),
    }
    if not (directory / "jwks.json").exists():
        n = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        ).private_numbers()
        jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": secrets.token_hex(16),
            "n": b64int(n.public_numbers.n),
            "e": b64int(n.public_numbers.e),
            "d": b64int(n.d),
            "p": b64int(n.p),
            "q": b64int(n.q),
            "dp": b64int(n.dmp1),
            "dq": b64int(n.dmq1),
            "qi": b64int(n.iqmp),
        }
        values["jwks.json"] = json.dumps({"keys": [jwk]})
    for name, value in values.items():
        path = directory / name
        if path.exists():
            if (
                path.is_symlink()
                or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) != 0o600
            ):
                raise ValueError("Existing secret file must be a regular 0600 file")
            if name in ("feishu-app-secret", "mail-password") and value:
                # Explicit interactive reruns update credentials, never encryption keys.
                tmp = path.with_suffix(".tmp")
                write_private(tmp, value)
                os.replace(tmp, path)
            continue
        write_private(path, value)


def prompt(label, default="", required=True):
    value = (
        input(label + (f" [{default}]" if default else "") + ": ").strip() or default
    )
    if required and not value:
        raise ValueError(label + " is required")
    if any(c in value for c in '\n\r\0$#"'):
        raise ValueError("Unsupported configuration characters")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--open-registration-hours", type=int)
    args = parser.parse_args()
    os.umask(0o077)
    directory = ROOT / ".secrets"
    env = ROOT / ".env"
    if args.open_registration_hours is not None:
        if (
            not 0 <= args.open_registration_hours <= 168
            or not env.is_file()
            or env.is_symlink()
        ):
            raise ValueError("Existing safe config and 0-168 hours required")
        until = (
            (datetime.now(timezone.utc) + timedelta(hours=args.open_registration_hours))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        lines = [
            line
            for line in env.read_text().splitlines()
            if not line.startswith("DCR_REGISTRATION_UNTIL=")
        ]
        tmp = ROOT / ".env.tmp"
        write_private(
            tmp, "\n".join(lines + [f"DCR_REGISTRATION_UNTIL={until}"]) + "\n"
        )
        os.replace(tmp, env)
        print(
            "Updated new-client registration window; restart monitor to apply. Existing clients are unchanged."
        )
        return
    if args.check:
        if not env.is_file():
            raise ValueError(".env missing; run setup first")
        for name in SECRET_NAMES:
            p = directory / name
            if (
                not p.is_file()
                or p.is_symlink()
                or stat.S_IMODE(p.stat().st_mode) != 0o600
            ):
                raise ValueError("Secret store is incomplete or has unsafe permissions")
        print("Local secret files exist with private permissions. No values displayed.")
        return
    if env.exists():
        if input("Update this existing local configuration? [y/N]: ").lower() != "y":
            return
    origin = validate_origin(prompt("Public HTTPS origin"))
    app = prompt("Feishu App ID")
    tenant = prompt("Feishu tenant key")
    owner = prompt("Owner Open ID")
    if not re.fullmatch(r"cli_[A-Za-z0-9_]+", app) or not re.fullmatch(
        r"ou_[A-Za-z0-9_]+", owner
    ):
        raise ValueError("Expected cli_ App ID and ou_ Open ID")
    mail = input("Enable INBOX header monitoring? [y/N]: ").strip().lower() == "y"
    username = prompt("IMAP mailbox address", required=True) if mail else ""
    if mail and not re.fullmatch(r"[^\s@]+@[^\s@]+", username):
        raise ValueError("Invalid mailbox address")
    app_secret = getpass.getpass("Feishu app secret (hidden; blank keeps existing): ")
    if not app_secret and not (directory / "feishu-app-secret").is_file():
        raise ValueError("Feishu app secret required")
    password = (
        getpass.getpass(
            "IMAP client authorization password (hidden; blank keeps existing): "
        )
        if mail
        else ""
    )
    if (
        mail
        and not password
        and (
            not (directory / "mail-password").exists()
            or not (directory / "mail-password").read_text()
        )
    ):
        raise ValueError("IMAP client authorization password required")
    generate(directory, app_secret, password)
    content = {
        "DCR_REGISTRATION_UNTIL": (datetime.now(timezone.utc) + timedelta(hours=24))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "PUBLIC_ORIGIN": origin,
        "FEISHU_APP_ID": app,
        "FEISHU_TENANT_KEY": tenant,
        "OWNER_OPEN_ID": owner,
        "OWNER_DISPLAY_NAME": "Owner",
        "MAIL_ENABLED": str(mail).lower(),
        "MAIL_USERNAME": username,
        "MAIL_HOST": "imap.qiye.163.com",
        "CHAT_IDS": '["*"]',
        "CALENDAR_IDS": '["primary"]',
        "POLL_SECONDS": "300",
    }
    tmp = ROOT / ".env.tmp"
    write_private(tmp, "\n".join(f"{k}={v}" for k, v in content.items()) + "\n")
    os.replace(tmp, env)
    print("Created local .env and private .secrets/. Values were not printed.")
    print(
        "Next: docker compose up -d --build; then configure the CLI and ChatGPT connection as described in README."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyboardInterrupt):
        raise SystemExit(
            "Setup incomplete. Check required inputs and file permissions; no credentials were printed."
        )
