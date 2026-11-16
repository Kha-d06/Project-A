"""Minimal encoder for Android binary XML (AXML), used to build test APKs.

Supports what the tests need: one namespace, nested elements and string or
boolean attributes. Format reference: Android's ResourceTypes.h.
"""

import struct
from dataclasses import dataclass, field

ANDROID_URI = "http://schemas.android.com/apk/res/android"
_NO_INDEX = 0xFFFFFFFF


@dataclass
class Element:
    tag: str
    attrs: dict[str, str | bool] = field(default_factory=dict)  # "android:name" or "package"
    children: list["Element"] = field(default_factory=list)


class _Strings:
    def __init__(self) -> None:
        self.values: list[str] = []

    def index(self, value: str) -> int:
        if value not in self.values:
            self.values.append(value)
        return self.values.index(value)

    def chunk(self) -> bytes:
        offsets, data = [], b""
        for value in self.values:
            offsets.append(len(data))
            encoded = value.encode("utf-16-le")
            data += struct.pack("<H", len(value)) + encoded + b"\0\0"
        data += b"\0" * (-len(data) % 4)
        header_size = 28
        strings_start = header_size + 4 * len(offsets)
        body = struct.pack(f"<{len(offsets)}I", *offsets) + data
        return (
            struct.pack(
                "<HHIIIIII",
                0x0001,
                header_size,
                header_size + len(body),
                len(self.values),
                0,
                0,
                strings_start,
                0,
            )
            + body
        )


def encode(root: Element) -> bytes:
    strings = _Strings()
    prefix, uri = strings.index("android"), strings.index(ANDROID_URI)
    nodes: list[bytes] = []

    def node(chunk_type: int, payload: bytes) -> bytes:
        return struct.pack("<HHIII", chunk_type, 16, 16 + len(payload), 1, _NO_INDEX) + payload

    def walk(element: Element) -> None:
        attributes = b""
        for key, value in element.attrs.items():
            namespaced = key.startswith("android:")
            name = strings.index(key.split(":", 1)[-1])
            ns = uri if namespaced else _NO_INDEX
            if isinstance(value, bool):
                raw, data_type, data = _NO_INDEX, 0x12, 0xFFFFFFFF if value else 0
            else:
                raw = strings.index(value)
                data_type, data = 0x03, raw
            attributes += struct.pack("<IIIHBBI", ns, name, raw, 8, 0, data_type, data)
        count = len(element.attrs)
        start = struct.pack(
            "<IIHHHHHH", _NO_INDEX, strings.index(element.tag), 20, 20, count, 0, 0, 0
        )
        nodes.append(node(0x0102, start + attributes))
        for child in element.children:
            walk(child)
        nodes.append(node(0x0103, struct.pack("<II", _NO_INDEX, strings.index(element.tag))))

    walk(root)
    namespace = struct.pack("<II", prefix, uri)
    body = node(0x0100, namespace) + b"".join(nodes) + node(0x0101, namespace)
    pool = strings.chunk()
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(body)) + pool + body
