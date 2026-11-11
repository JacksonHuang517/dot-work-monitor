"""MCP Events webhook signatures and DNS-pinned public HTTPS delivery."""

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import time
from urllib.parse import urlsplit
import aiohttp


class DeliveryError(Exception):
    pass


def validate_url(url):
    p = urlsplit(url)
    if (
        p.scheme != "https"
        or not p.hostname
        or p.username
        or p.password
        or p.fragment
        or p.port not in (None, 443)
    ):
        raise DeliveryError(
            "callback must be HTTPS on port 443, without credentials or fragment"
        )
    if p.hostname.lower() in {"localhost", "metadata.google.internal"}:
        raise DeliveryError("non-public callback")
    try:
        addr = ipaddress.ip_address(p.hostname)
    except ValueError:
        return
    if not addr.is_global:
        raise DeliveryError("non-public callback")


def signing_key(secret):
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise DeliveryError("invalid signing secret")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, TypeError):
        raise DeliveryError("invalid signing secret") from None
    if not 24 <= len(key) <= 64:
        raise DeliveryError("invalid signing key length")
    return key


def headers(sub, event_id, body, now=None):
    stamp = str(int(time.time() if now is None else now))
    signed = event_id.encode() + b"." + stamp.encode() + b"." + body
    keys = [sub["secret"]]
    if sub.get("old_secret") and sub.get("rotate_until", 0) > time.time():
        keys.append(sub["old_secret"])
    sigs = [
        "v1,"
        + base64.b64encode(
            hmac.new(signing_key(k), signed, hashlib.sha256).digest()
        ).decode()
        for k in keys
    ]
    return {
        "Content-Type": "application/json",
        "webhook-id": event_id,
        "webhook-timestamp": stamp,
        "webhook-signature": " ".join(sigs),
        "X-MCP-Subscription-Id": sub["id"],
    }


class PublicResolver(aiohttp.abc.AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        import asyncio

        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM, family=family
        )
        if not infos or any(not ipaddress.ip_address(i[4][0]).is_global for i in infos):
            raise OSError("callback resolves to non-public address")
        return [
            {
                "hostname": host,
                "host": i[4][0],
                "port": port,
                "family": i[0],
                "proto": i[2],
                "flags": socket.AI_NUMERICHOST,
            }
            for i in infos
        ]

    async def close(self):
        pass


class Delivery:
    async def post(self, sub, obj, event_id):
        validate_url(sub["url"])
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        if len(body) > 262144:
            raise DeliveryError("payload too large")
        connector = aiohttp.TCPConnector(
            resolver=PublicResolver(), use_dns_cache=False, force_close=True
        )
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=10),
            trust_env=False,
        ) as session:
            async with session.post(
                sub["url"],
                data=body,
                headers=headers(sub, event_id, body),
                allow_redirects=False,
            ) as response:
                raw = await response.content.read(8193)
                return response.status, raw if len(raw) <= 8192 else b""

    async def verify(self, sub):
        challenge = secrets.token_urlsafe(32)
        status, body = await self.post(
            sub,
            {"type": "verification", "challenge": challenge},
            "verify_" + secrets.token_hex(16),
        )
        try:
            ok = 200 <= status < 300 and hmac.compare_digest(
                json.loads(body).get("challenge", ""), challenge
            )
        except (ValueError, TypeError, AttributeError):
            ok = False
        if not ok:
            raise DeliveryError("challenge_failed")
