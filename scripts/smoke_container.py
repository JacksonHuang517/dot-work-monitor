#!/usr/bin/env python3
"""Start a built image with synthetic credentials and test public HTTP boundaries."""

import argparse, json, os, pathlib, subprocess, tempfile, time, urllib.request, urllib.error
from setup import generate


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--image", default="dot-work-monitor:check")
    args = p.parse_args()
    work = pathlib.Path(__file__).resolve().parents[1] / ".agent-work"
    work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work) as temp:
        secrets = pathlib.Path(temp) / "secrets"
        generate(secrets, "synthetic-ci-app-secret")
        name = "dot-work-monitor-smoke-" + str(os.getpid())
        try:
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--publish",
                "127.0.0.1::8560",
                "--mount",
                f"type=bind,src={secrets},dst=/seed-secrets,readonly",
                "--tmpfs",
                "/run/monitor-secrets:mode=0700",
                "--env",
                "PUBLIC_ORIGIN=https://monitor.example.com",
                "--env",
                "FEISHU_APP_ID=cli_test_app",
                "--env",
                "FEISHU_TENANT_KEY=test-tenant",
                "--env",
                "OWNER_OPEN_ID=ou_test_owner",
                "--env",
                "AUTH_HOST=0.0.0.0",
                "--env",
                "AUTH_TRUST_PROXY=1",
                "--env",
                "AUTH_DATABASE_PATH=/data/auth.sqlite",
                "--env",
                "FEISHU_APP_SECRET_FILE=/run/monitor-secrets/feishu-app-secret",
                "--env",
                "INTERNAL_KEY_FILE=/run/monitor-secrets/internal-key",
                "--env",
                "OAUTH_JWKS_FILE=/run/monitor-secrets/jwks.json",
                "--env",
                "COOKIE_KEYS_FILE=/run/monitor-secrets/cookie-keys.json",
                "--env",
                "AUTH_DB_KEY_FILE=/run/monitor-secrets/auth-db-key",
                "--env",
                "ENCRYPTION_KEY_FILE=/run/monitor-secrets/state-key",
                "--env",
                "HOME=/data",
                "--env",
                "DATA_DIR=/data",
                args.image,
            )
            port = docker("port", name, "8560/tcp").split(":")[-1]
            base = "http://127.0.0.1:" + port
            for _ in range(90):
                try:
                    with urllib.request.urlopen(
                        base + "/dot-feishu/health", timeout=2
                    ) as r:
                        assert r.status == 200
                    break
                except (OSError, AssertionError):
                    time.sleep(1)
            else:
                raise RuntimeError("container did not become healthy")
            with urllib.request.urlopen(
                base + "/.well-known/oauth-protected-resource/dot-feishu/mcp"
            ) as r:
                x = json.load(r)
                assert x["scopes_supported"] == ["feishu:read", "mail:read"]
            try:
                urllib.request.urlopen(base + "/dot-feishu/mcp")
            except urllib.error.HTTPError as e:
                assert e.code == 401 and e.headers.get("WWW-Authenticate")
            else:
                raise AssertionError("Unauthenticated MCP access was accepted")
            uid = docker("exec", "--user", "monitor", name, "id", "-u")
            assert uid == "10001"
            print(
                "Container HTTP discovery, unauthorized access and non-root CLI user checks passed."
            )
        finally:
            subprocess.run(
                ["docker", "rm", "-f", "-v", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
