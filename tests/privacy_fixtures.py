import hashlib
import re
import struct
import zlib

from support import uleb

TYPE = re.compile(r"\[*L[^;]+;|\[*[VZBCSIJFD]")
IDENTITY = "Landroid/telephony/TelephonyManager;->getImei()Ljava/lang/String;"
URL_INIT = "Ljava/net/URL;-><init>(Ljava/lang/String;)V"
OPEN = "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
STREAM = "Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;"
BYTES = "Ljava/lang/String;->getBytes()[B"
WRITE = "Ljava/io/OutputStream;->write([B)V"
ROOT_METHOD = "Lsample/Main;->run(Landroid/telephony/TelephonyManager;)V"


def connection():
    return [
        ("new", 1, "Ljava/net/URL;"),
        ("string", 2, "https://private.example/register"),
        ("invoke", URL_INIT, [1, 2], False),
        ("invoke", OPEN, [1], False),
        ("result", 3),
        0x1212,
        ("invoke", "Ljava/net/URLConnection;->setDoOutput(Z)V", [3, 2], False),
        ("invoke", STREAM, [3], False),
        ("result", 4),
    ]


def transmission(value=0):
    return [
        *connection(),
        ("invoke", BYTES, [value], False),
        ("result", 5),
        ("invoke", WRITE, [4, 5], False),
    ]


def byte_transmission(value=0):
    return [*connection(), ("invoke", WRITE, [4, value], False)]


def privacy_dex(definitions, extra_methods=(), fields=()):
    methods = list(
        dict.fromkeys(
            [item["signature"] for item in definitions]
            + list(extra_methods)
            + [
                instruction[1]
                for item in definitions
                for instruction in item["code"]
                if isinstance(instruction, tuple)
                and instruction[0] in {"invoke", "invoke-range"}
            ]
        )
    )
    strings, types, protos = [], [], []

    def intern(values, value):
        if value not in values:
            values.append(value)
        return values.index(value)

    for signature in methods:
        owner, tail = signature.split("->")
        name, arguments = tail.split("(")
        params, result = arguments.split(")")
        intern(types, owner)
        for kind in TYPE.findall(params) + [result]:
            intern(types, kind)
        intern(protos, (tuple(TYPE.findall(params)), result))
        intern(strings, name)
    for definition in definitions:
        for instruction in definition["code"]:
            if isinstance(instruction, tuple) and instruction[0] in {"new", "array"}:
                intern(types, instruction[2])
            if isinstance(instruction, tuple) and instruction[0] == "string":
                intern(strings, instruction[2])
    for field in fields:
        owner, tail = field.split("->")
        name, kind = tail.split(":")
        intern(types, owner)
        intern(types, kind)
        intern(strings, name)
    for kind in types:
        intern(strings, kind)
    for params, result in protos:
        intern(
            strings,
            "".join(
                kind[0] if kind[0] in "VZBCSIJFD" else "L" for kind in (result, *params)
            ),
        )
    owners = list(
        dict.fromkeys(item["signature"].split("->")[0] for item in definitions)
    )
    string_offset = 112
    type_offset = string_offset + len(strings) * 4
    proto_offset = type_offset + len(types) * 4
    field_offset = proto_offset + len(protos) * 12
    method_offset = field_offset + len(fields) * 8
    class_offset = method_offset + len(methods) * 8
    data_offset = class_offset + len(owners) * 32
    data = bytearray(data_offset)
    for index, value in enumerate(strings):
        struct.pack_into("<I", data, string_offset + index * 4, len(data))
        data.extend(uleb(len(value)) + value.encode() + b"\0")
    for index, kind in enumerate(types):
        struct.pack_into("<I", data, type_offset + index * 4, strings.index(kind))
    for index, (params, result) in enumerate(protos):
        while len(data) % 4:
            data.append(0)
        offset = len(data) if params else 0
        if params:
            data.extend(
                struct.pack("<I", len(params))
                + b"".join(struct.pack("<H", types.index(kind)) for kind in params)
            )
        shorty = "".join(
            kind[0] if kind[0] in "VZBCSIJFD" else "L" for kind in (result, *params)
        )
        struct.pack_into(
            "<III",
            data,
            proto_offset + index * 12,
            strings.index(shorty),
            types.index(result),
            offset,
        )
    for index, signature in enumerate(methods):
        owner, tail = signature.split("->")
        name, arguments = tail.split("(")
        params, result = arguments.split(")")
        struct.pack_into(
            "<HHI",
            data,
            method_offset + index * 8,
            types.index(owner),
            protos.index((tuple(TYPE.findall(params)), result)),
            strings.index(name),
        )
    for index, field in enumerate(fields):
        owner, tail = field.split("->")
        name, kind = tail.split(":")
        struct.pack_into(
            "<HHI",
            data,
            field_offset + index * 8,
            types.index(owner),
            types.index(kind),
            strings.index(name),
        )
    code_offsets = {}
    for definition in definitions:
        code = []
        return_type = "V"
        for instruction in definition["code"]:
            if isinstance(instruction, int):
                code.append(instruction)
                continue
            op = instruction[0]
            if op == "invoke":
                _, target, registers, static = instruction
                return_type = target.split(")", 1)[1]
                packed = sum(
                    value << (4 * index) for index, value in enumerate(registers[:4])
                )
                fifth = registers[4] if len(registers) > 4 else 0
                code.extend(
                    [
                        (0x71 if static else 0x6E) | len(registers) << 12 | fifth << 8,
                        methods.index(target),
                        packed,
                    ]
                )
            elif op == "invoke-range":
                _, target, start, count, static = instruction
                return_type = target.split(")", 1)[1]
                code.extend(
                    [
                        (0x77 if static else 0x74) | count << 8,
                        methods.index(target),
                        start,
                    ]
                )
            elif op == "new":
                code.extend([0x22 | instruction[1] << 8, types.index(instruction[2])])
            elif op == "array":
                code.extend(
                    [
                        0x23 | instruction[1] << 8 | instruction[3] << 12,
                        types.index(instruction[2]),
                    ]
                )
            elif op in {"iget", "iput", "sget", "sput"}:
                _, register, field, *receiver = instruction
                opcode = {"iget": 0x54, "iput": 0x5B, "sget": 0x62, "sput": 0x69}[op]
                code.extend(
                    [
                        opcode | register << 8 | (receiver[0] << 12 if receiver else 0),
                        fields.index(field),
                    ]
                )
            elif op == "string":
                code.extend([0x1A | instruction[1] << 8, strings.index(instruction[2])])
            elif op == "result":
                result_opcode = (
                    0x0B
                    if return_type in {"J", "D"}
                    else 0x0C
                    if return_type.startswith(("L", "["))
                    else 0x0A
                )
                code.append(result_opcode | instruction[1] << 8)
            elif op == "return":
                code.append(0x11 | instruction[1] << 8)
        while len(data) % 4:
            data.append(0)
        access = definition.get("access", 9)
        if access & 0x100:
            code_offsets[definition["signature"]] = 0
            continue
        code_offsets[definition["signature"]] = len(data)
        params = definition["signature"].split("(")[1].split(")")[0]
        count = sum(2 if kind in {"J", "D"} else 1 for kind in TYPE.findall(params)) + (
            0 if access & 8 else 1
        )
        handlers = definition.get("handlers", [])
        data.extend(
            struct.pack(
                "<HHHHII",
                definition.get("registers", 8),
                count,
                5,
                len(handlers),
                0,
                len(code),
            )
        )
        data.extend(struct.pack("<" + "H" * len(code), *code))
        if handlers:
            while len(data) % 4:
                data.append(0)
            encoded = bytearray(uleb(len(handlers)))
            for start, end, target in handlers:
                data.extend(struct.pack("<IHH", start, end - start, len(encoded)))
                encoded.extend(b"\0" + uleb(target))
            data.extend(encoded)
    for index, owner in enumerate(owners):
        selected = sorted(
            (methods.index(item["signature"]), item)
            for item in definitions
            if item["signature"].startswith(owner + "->")
        )
        offset = len(data)
        data.extend(b"\0\0" + uleb(len(selected)) + b"\0")
        previous = 0
        for method_index, definition in selected:
            data.extend(
                uleb(method_index - previous)
                + uleb(definition.get("access", 9))
                + uleb(code_offsets[definition["signature"]])
            )
            previous = method_index
        struct.pack_into(
            "<8I",
            data,
            class_offset + index * 32,
            types.index(owner),
            1,
            0xFFFFFFFF,
            0,
            0xFFFFFFFF,
            0,
            offset,
            0,
        )
    data[:8] = b"dex\n035\0"
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
        len(protos),
        proto_offset,
        len(fields),
        field_offset,
        len(methods),
        method_offset,
        len(owners),
        class_offset,
        len(data) - data_offset,
        data_offset,
    )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)
