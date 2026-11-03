import hashlib
import struct
import zipfile
import zlib


def uleb(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def make_dex(
    extra_strings=(),
    url="https://events.example.org/collect?token=private-value",
    *,
    instructions=None,
):
    strings = [
        url,
        "Lcom/example/App;",
        "Ljava/net/URL;",
        "Ljava/net/URLConnection;",
        "V",
        "run",
        "openConnection",
        "Lcom/google/firebase/analytics/FirebaseAnalytics;",
        "device_id",
        *extra_strings,
    ]
    types = [1, 2, 3, 4, 7]
    string_offset = 112
    type_offset = string_offset + len(strings) * 4
    proto_offset = type_offset + len(types) * 4
    method_offset = proto_offset + 24
    class_offset = method_offset + 16
    data_offset = class_offset + 32
    data = bytearray(data_offset)
    string_positions = []
    for value in strings:
        encoded = value.encode("utf-16-le", "surrogatepass")
        units = struct.unpack("<" + "H" * (len(encoded) // 2), encoded)
        modified = b"".join(
            (b"\xc0\x80" if unit == 0 else chr(unit).encode("utf-8", "surrogatepass"))
            for unit in units
        )
        string_positions.append(len(data))
        data.extend(uleb(len(units)) + modified + b"\x00")
    while len(data) % 4:
        data.append(0)
    code_offset = len(data)
    if instructions is None:
        instructions = [0x001A, 0, 0x006E, 1, 0, 0x000E]
    data.extend(struct.pack("<HHHHII", 1, 0, 1, 0, 0, len(instructions)))
    data.extend(struct.pack("<" + "H" * len(instructions), *instructions))
    class_data_offset = len(data)
    data.extend(b"\x00\x00\x01\x00" + uleb(0) + uleb(9) + uleb(code_offset))
    data[0:8] = b"dex\n035\x00"
    struct.pack_into(
        "<20I",
        data,
        32,
        len(data),
        112,
        0x12345678,
        0,
        0,
        0,
        len(strings),
        string_offset,
        len(types),
        type_offset,
        2,
        proto_offset,
        0,
        0,
        2,
        method_offset,
        1,
        class_offset,
        len(data) - data_offset,
        data_offset,
    )
    for index, position in enumerate(string_positions):
        struct.pack_into("<I", data, string_offset + index * 4, position)
    for index, string_index in enumerate(types):
        struct.pack_into("<I", data, type_offset + index * 4, string_index)
    struct.pack_into("<III", data, proto_offset, 4, 3, 0)
    struct.pack_into("<III", data, proto_offset + 12, 3, 2, 0)
    struct.pack_into("<HHI", data, method_offset, 0, 0, 5)
    struct.pack_into("<HHI", data, method_offset + 8, 1, 1, 6)
    struct.pack_into(
        "<8I",
        data,
        class_offset,
        0,
        1,
        0xFFFFFFFF,
        0,
        0xFFFFFFFF,
        0,
        class_data_offset,
        0,
    )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def make_pool(strings, utf8=True):
    encoded = bytearray()
    offsets = []

    def length(value, wide):
        if wide:
            return (
                struct.pack("<H", value)
                if value < 0x8000
                else struct.pack("<HH", (value >> 16) | 0x8000, value & 0xFFFF)
            )
        return (
            bytes([value]) if value < 128 else bytes([(value >> 8) | 128, value & 255])
        )

    for value in strings:
        offsets.append(len(encoded))
        units = len(value.encode("utf-16-le")) // 2
        if utf8:
            text = value.encode("utf-8")
            encoded.extend(
                length(units, False) + length(len(text), False) + text + b"\x00"
            )
        else:
            encoded.extend(
                length(units, True) + value.encode("utf-16-le") + b"\x00\x00"
            )
    while len(encoded) % 4:
        encoded.append(0)
    start = 28 + len(strings) * 4
    return (
        struct.pack(
            "<HH6I",
            1,
            28,
            start + len(encoded),
            len(strings),
            0,
            0x100 if utf8 else 0,
            start,
            0,
        )
        + struct.pack("<" + "I" * len(offsets), *offsets)
        + encoded
    )


def make_axml():
    strings = [
        "manifest",
        "package",
        "com.example.binary",
        "http://schemas.android.com/apk/res/android",
        "versionCode",
        "uses-sdk",
        "targetSdkVersion",
        "uses-permission",
        "name",
        "android.permission.CAMERA",
        "application",
        "debuggable",
        "networkSecurityConfig",
        "provider",
        "com.example.Provider",
        "android.permission.READ_CONTACTS",
    ]
    chunks = [make_pool(strings)]

    def element(name, attrs=(), end=False):
        node = struct.pack("<II", 1, 0xFFFFFFFF)
        if end:
            payload = node + struct.pack("<II", 0xFFFFFFFF, strings.index(name))
            return struct.pack("<HHI", 0x0103, 16, len(payload) + 8) + payload
        extension = struct.pack(
            "<IIHHHHHH", 0xFFFFFFFF, strings.index(name), 20, 20, len(attrs), 0, 0, 0
        )
        attributes = bytearray()
        for key, value, value_type, android in attrs:
            attributes.extend(
                struct.pack(
                    "<IIIHBBI",
                    3 if android else 0xFFFFFFFF,
                    strings.index(key),
                    0xFFFFFFFF,
                    8,
                    0,
                    value_type,
                    value,
                )
            )
        payload = node + extension + attributes
        return struct.pack("<HHI", 0x0102, 16, len(payload) + 8) + payload

    chunks.append(
        element("manifest", [("package", 2, 3, False), ("versionCode", 7, 0x10, True)])
    )
    chunks.extend(
        [
            element("uses-sdk", [("targetSdkVersion", 34, 0x10, True)]),
            element("uses-sdk", end=True),
        ]
    )
    chunks.extend(
        [
            element("uses-permission", [("name", 9, 3, True)]),
            element("uses-permission", end=True),
        ]
    )
    chunks.append(
        element(
            "application",
            [
                ("debuggable", 0, 0x12, True),
                ("networkSecurityConfig", 0x7F010001, 1, True),
            ],
        )
    )
    chunks.extend(
        [element("provider", [("name", 14, 3, True)]), element("provider", end=True)]
    )
    chunks.extend([element("application", end=True), element("manifest", end=True)])
    body = b"".join(chunks)
    return struct.pack("<HHI", 3, 8, 8 + len(body)) + body


def make_apk(
    path,
    package="com.example.app",
    split=None,
    version="1",
    entries=None,
    manifest=None,
):
    split_attribute = f' split="{split}"' if split else ""
    text = f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="{version}"{split_attribute}><uses-sdk android:targetSdkVersion="34"/><uses-permission android:name="android.permission.CAMERA"/><application android:permission="com.example.PROTECTED"><service android:name=".Service" android:exported="true"/></application></manifest>'
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "AndroidManifest.xml", manifest if manifest is not None else text
        )
        for name, value in (entries or {}).items():
            archive.writestr(name, value)
    return path
