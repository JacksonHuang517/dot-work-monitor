"""Root bootstrap using no-follow directory descriptors; children run unprivileged."""

import json, os, secrets, stat
from pathlib import Path


def directory(path, uid, gid):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    os.fchmod(fd, 0o700)
    os.fchown(fd, uid, gid)
    return fd


def initialize(source, runtime, data, app, mail_enabled, uid=10001, gid=10001):
    os.umask(0o077)
    rfd = directory(runtime, uid, gid)
    dfd = directory(data, uid, gid)
    try:
        required = [
            "feishu-app-secret",
            "internal-key",
            "state-key",
            "jwks.json",
            "cookie-keys.json",
            "auth-db-key",
        ]
        if mail_enabled:
            required.append("mail-password")
        for name in required:
            # Source is read-only seed material, but still reject symlinks/special files.
            fd = os.open(source / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077
                    or not 0 < info.st_size <= 65536
                ):
                    raise ValueError("Unsafe secret file")
                value = os.read(fd, 65537)
            finally:
                os.close(fd)
            temporary = ".init-" + secrets.token_hex(12)
            out = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=rfd,
            )
            with os.fdopen(out, "wb") as f:
                f.write(value)
                os.fchmod(f.fileno(), 0o600)
                os.fchown(f.fileno(), uid, gid)
            # Atomically replaces a preexisting symlink rather than following it.
            os.replace(temporary, name, src_dir_fd=rfd, dst_dir_fd=rfd)
        try:
            os.mkdir(".lark-cli", mode=0o700, dir_fd=dfd)
        except FileExistsError:
            pass
        cfd = os.open(
            ".lark-cli", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd
        )
        try:
            os.fchmod(cfd, 0o700)
            os.fchown(cfd, uid, gid)
            try:
                fd = os.open(
                    "config.json",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=cfd,
                )
            except FileNotFoundError:
                fd = os.open(
                    "config.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=cfd,
                )
                with os.fdopen(fd, "w") as f:
                    json.dump(
                        {
                            "apps": [
                                {
                                    "appId": app,
                                    "brand": "feishu",
                                    "lang": "zh_cn",
                                    "appSecret": {
                                        "source": "file",
                                        "id": "/run/monitor-secrets/feishu-app-secret",
                                    },
                                }
                            ]
                        },
                        f,
                    )
                    os.fchown(f.fileno(), uid, gid)
            else:
                with os.fdopen(fd, "rb") as f:
                    info = os.fstat(f.fileno())
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size > 65536
                    ):
                        raise ValueError("Unsafe CLI config")
                    obj = json.loads(f.read(65537))
                if app not in [a.get("appId") for a in obj.get("apps", [])]:
                    raise ValueError("CLI data volume belongs to another app")
        finally:
            os.close(cfd)
    finally:
        os.close(rfd)
        os.close(dfd)


def main():
    try:
        initialize(
            Path("/seed-secrets"),
            Path("/run/monitor-secrets"),
            Path("/data"),
            os.environ["FEISHU_APP_ID"],
            os.environ.get("MAIL_ENABLED", "false").lower() == "true",
        )
    except (OSError, ValueError, KeyError):
        raise SystemExit(
            "Container configuration is incomplete or unsafe. No credential values displayed."
        )


if __name__ == "__main__":
    main()
