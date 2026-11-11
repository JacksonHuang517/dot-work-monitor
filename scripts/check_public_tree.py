#!/usr/bin/env python3
"""Fail public-release checks for credentials, private identity values and runtime state.

This conservative policy is an extra check, not a replacement for secret
scanning or human review. Diagnostics show filenames/rule names, never values.
"""

import pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP = {".git", "node_modules", "dist", "__pycache__", ".venv", ".agent-work"}
RULES = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(
        rb"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"
    ),
    "api-token": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    "real-feishu-app": re.compile(rb"cli_[a-f0-9]{16}\b"),
    "real-feishu-user": re.compile(rb"ou_[a-f0-9]{20,}\b"),
    "home-path": re.compile(
        rb"/[U]sers/[^/\s]+/|/[h]ome/(?!app\b|monitor\b)[A-Za-z0-9_-]+/"
    ),
}


def files():
    try:
        p = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
        return [ROOT / pathlib.Path(x.decode()) for x in p.stdout.split(b"\0") if x]
    except subprocess.CalledProcessError:
        return [
            p
            for p in ROOT.rglob("*")
            if p.is_file()
            and not any(part in SKIP for part in p.relative_to(ROOT).parts)
        ]


def main():
    issues = []
    for p in files():
        rel = p.relative_to(ROOT)
        if p.is_symlink():
            issues.append((str(rel), "symlink"))
            continue
        if not p.is_file():
            continue
        if any(part in SKIP for part in rel.parts):
            continue
        if (
            ".secrets" in rel.parts
            or p.name == ".env"
            or p.suffix in (".db", ".sqlite", ".enc", ".key", ".pem", ".p12", ".pfx")
        ):
            issues.append((str(rel), "runtime-state"))
            continue
        data = p.read_bytes()
        for name, rx in RULES.items():
            if rx.search(data):
                issues.append((str(rel), name))
        for email in re.findall(
            rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", data
        ):
            if (
                email == b"user" + b"@chatgpt.com"
                and str(rel) == "auth/tests/auth.test.ts"
            ):
                continue
            domain = email.rsplit(b"@", 1)[1].lower()
            if domain not in (
                b"example.com",
                b"example.org",
                b"example.net",
            ) and not domain.endswith(
                (
                    b".example.com",
                    b".example.org",
                    b".example.net",
                    b".test",
                    b".invalid",
                    b".example",
                )
            ):
                issues.append((str(rel), "non-example-email"))
                break
        # Examples may document public bind addresses; real public IPv4 settings do not belong in source.
        for raw in re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", data):
            if raw not in (
                b"127.0.0.1",
                b"0.0.0.0",
                b"169.254.169.254",
            ) and not raw.startswith((b"192.0.2.", b"198.51.100.", b"203.0.113.")):
                # Version numbers can have four numeric components; reject valid IPv4 only.
                parts = list(map(int, raw.split(b".")))
                if all(v <= 255 for v in parts):
                    issues.append((str(rel), "non-example-ipv4"))
    if issues:
        for file, rule in sorted(set(issues)):
            print(f"{file}: {rule}")
        return 1
    print("Public source policy passed; no matched values printed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
