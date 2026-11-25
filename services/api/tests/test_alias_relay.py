"""The Postfix socketmap adapter for alias forwarding."""

import asyncio

import pytest

from app.relay.socketmap import answer, decode_netstring, encode_netstring, serve


def test_netstrings() -> None:
    assert encode_netstring("OK a@b") == b"6:OK a@b,"
    assert decode_netstring(b"13:qalaa x@y.org,rest") == ("qalaa x@y.org", b"rest")
    assert decode_netstring(b"13:qalaa x@") == (None, b"13:qalaa x@")
    for bad in (b"x:abc,", b"3:abcd", b"99999:a", b"123456789012"):
        with pytest.raises(ValueError):
            decode_netstring(bad)


def test_answers() -> None:
    table = {"shop@relay.example.org": ("OK", "amira@example.com")}
    resolve = lambda address: table.get(address, ("NOTFOUND", ""))  # noqa: E731
    assert answer("qalaa shop@relay.example.org", resolve) == "OK amira@example.com"
    assert answer("qalaa paused@relay.example.org", resolve) == "NOTFOUND "
    assert answer("other shop@relay.example.org", resolve) == "NOTFOUND "
    assert answer("qalaa not-an-address", resolve) == "NOTFOUND "
    assert answer("qalaa x@y", lambda _a: ("TEMP", "down")) == "TEMP down"


def test_postfix_style_session() -> None:
    async def scenario() -> list[bytes]:
        server = await serve(
            "127.0.0.1",
            0,
            lambda a: ("OK", "amira@example.com") if a.startswith("shop@") else ("NOTFOUND", ""),
        )
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Two requests in one write, as Postfix may pipeline them.
        writer.write(
            encode_netstring("qalaa shop@relay.example.org")
            + encode_netstring("qalaa gone@relay.example.org")
        )
        await writer.drain()
        replies = [await reader.readuntil(b","), await reader.readuntil(b",")]
        writer.write(b"garbage:")
        await writer.drain()
        replies.append(await reader.readuntil(b","))
        writer.close()
        server.close()
        await server.wait_closed()
        return replies

    assert asyncio.run(scenario()) == [
        b"20:OK amira@example.com,",
        b"9:NOTFOUND ,",
        b"22:PERM malformed request,",
    ]
