"""A Postfix socketmap table that answers "where does this alias go?" from the
Qalaa API, so the operator's own Postfix forwards alias mail. Only the
recipient address is sent to the API, never the message.

    SENTINEL_API_URL=http://api:8000 SENTINEL_ALIAS_RELAY_TOKEN=… \
        python -m app.relay.socketmap --listen 127.0.0.1:8945

Postfix main.cf:
    virtual_alias_domains = relay.example.org
    virtual_alias_maps = socketmap:inet:127.0.0.1:8945:qalaa

Protocol (Postfix socketmap_table(5)): netstring requests "name key", netstring
replies "OK value", "NOTFOUND ", "TEMP reason" or "PERM reason".
"""

import argparse
import asyncio
import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable

MAX_REQUEST = 1024

Resolver = Callable[[str], tuple[str, str]]


def encode_netstring(payload: str) -> bytes:
    data = payload.encode()
    return str(len(data)).encode() + b":" + data + b","


def decode_netstring(buffer: bytes) -> tuple[str | None, bytes]:
    """One netstring from the front of `buffer`, and what's left; None if incomplete."""
    colon = buffer.find(b":")
    if colon < 0:
        if len(buffer) > 10:
            raise ValueError("bad netstring length")
        return None, buffer
    length_text = buffer[:colon]
    if not length_text.isdigit() or len(length_text) > 5:
        raise ValueError("bad netstring length")
    length = int(length_text)
    if length > MAX_REQUEST:
        raise ValueError("request too long")
    end = colon + 1 + length
    if len(buffer) < end + 1:
        return None, buffer
    if buffer[end : end + 1] != b",":
        raise ValueError("netstring without ','")
    return buffer[colon + 1 : end].decode(errors="replace"), buffer[end + 1 :]


def api_resolver(api_url: str, token: str, timeout: float = 5.0) -> Resolver:
    endpoint = api_url.rstrip("/") + "/api/v1/relay/aliases/resolve"

    def resolve(address: str) -> tuple[str, str]:
        request = urllib.request.Request(  # noqa: S310 - fixed http(s) URL from configuration
            endpoint,
            data=json.dumps({"address": address}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                body = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return "TEMP", f"alias lookup unavailable: {exc}"[:200]
        if body.get("action") == "forward" and body.get("to"):
            return "OK", str(body["to"])
        return "NOTFOUND", ""

    return resolve


def answer(request: str, resolve: Resolver) -> str:
    """The reply for one "name key" request."""
    name, _, key = request.partition(" ")
    if name != "qalaa" or "@" not in key:
        return "NOTFOUND "
    status, value = resolve(key.strip())
    return f"{status} {value}"


async def serve(host: str, port: int, resolve: Resolver) -> asyncio.Server:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        buffer = b""
        try:
            while chunk := await reader.read(4096):
                buffer += chunk
                while True:
                    request, buffer = decode_netstring(buffer)
                    if request is None:
                        break
                    reply = await asyncio.to_thread(answer, request, resolve)
                    writer.write(encode_netstring(reply))
                    await writer.drain()
        except ValueError:
            writer.write(encode_netstring("PERM malformed request"))
        finally:
            writer.close()

    return await asyncio.start_server(handle, host, port)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:8945")
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    token = os.environ.get("SENTINEL_ALIAS_RELAY_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("Set SENTINEL_ALIAS_RELAY_TOKEN (32+ characters), the same as the API's.")
    resolve = api_resolver(os.environ.get("SENTINEL_API_URL", "http://api:8000"), token)

    async def run() -> None:
        server = await serve(host, int(port), resolve)
        async with server:
            await server.serve_forever()

    asyncio.run(run())


if __name__ == "__main__":
    main()
