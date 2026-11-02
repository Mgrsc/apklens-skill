import hashlib
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib

from .common import AnalysisError, BudgetExceeded, Cancelled

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
NO_INDEX = 0xFFFFFFFF
SUPPORTED_DEX_VERSIONS = {b"035", b"037", b"038", b"039", b"040"}


class BinaryReader:
    def __init__(self, data):
        self.data = data

    def require(self, offset, size, end=None):
        boundary = len(self.data) if end is None else min(end, len(self.data))
        if offset < 0 or size < 0 or offset + size > boundary:
            raise AnalysisError("Binary offset is outside its container")

    def u16(self, offset):
        self.require(offset, 2)
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset):
        self.require(offset, 4)
        return struct.unpack_from("<I", self.data, offset)[0]

    def uleb(self, offset):
        result = 0
        for index in range(5):
            self.require(offset, 1)
            value = self.data[offset]
            offset += 1
            if index == 4 and value > 15:
                raise AnalysisError("Invalid 32-bit ULEB128 value")
            result |= (value & 127) << (index * 7)
            if not value & 128:
                return result, offset
        raise AnalysisError("Unterminated ULEB128 value")


def string_pool(reader, offset, limits):
    header_size = reader.u16(offset + 2)
    size = reader.u32(offset + 4)
    reader.require(offset, size)
    if header_size < 28 or size < header_size:
        raise AnalysisError("Invalid resource string pool header")
    count = reader.u32(offset + 8)
    style_count = reader.u32(offset + 12)
    flags = reader.u32(offset + 16)
    strings_start = reader.u32(offset + 20)
    styles_start = reader.u32(offset + 24)
    if count > limits.max_strings:
        raise BudgetExceeded("Resource string count exceeds the budget")
    reader.require(offset + header_size, (count + style_count) * 4, offset + size)
    if strings_start < header_size + (count + style_count) * 4 or strings_start > size:
        raise AnalysisError("Invalid resource string data offset")
    end = offset + (styles_start or size)
    if end > offset + size or end < offset + strings_start:
        raise AnalysisError("Invalid resource style data offset")
    output = []

    def length_at(position, wide):
        unit = 2 if wide else 1
        reader.require(position, unit, end)
        value = reader.u16(position) if wide else reader.data[position]
        marker = 0x8000 if wide else 0x80
        position += unit
        if value & marker:
            reader.require(position, unit, end)
            second = reader.u16(position) if wide else reader.data[position]
            value = ((value & (marker - 1)) << (16 if wide else 8)) | second
            position += unit
        return value, position

    for index in range(count):
        position = offset + strings_start + reader.u32(offset + header_size + index * 4)
        if flags & 0x100:
            _, position = length_at(position, False)
            length, position = length_at(position, False)
            width, encoding = 1, "utf-8"
        else:
            length, position = length_at(position, True)
            width, encoding = 2, "utf-16-le"
        byte_length = length * width
        if byte_length > limits.max_string_bytes:
            raise BudgetExceeded("Resource string length exceeds the budget")
        reader.require(position, byte_length + width, end)
        if any(reader.data[position + byte_length : position + byte_length + width]):
            raise AnalysisError("Resource string has no terminator")
        output.append(
            {
                "value": reader.data[position : position + byte_length].decode(
                    encoding, "strict"
                ),
                "offset": position,
                "string_index": index,
            }
        )
    return output


def resource_strings(data, limits, budget):
    reader = BinaryReader(data)
    result = []

    def walk(start, end, depth):
        if depth > 8:
            raise BudgetExceeded("Resource nesting exceeds the budget")
        offset = start
        while offset < end:
            budget.check()
            reader.require(offset, 8, end)
            kind = reader.u16(offset)
            header_size = reader.u16(offset + 2)
            size = reader.u32(offset + 4)
            if header_size < 8 or size < header_size:
                raise AnalysisError("Invalid resource chunk size")
            reader.require(offset, size, end)
            if kind == 1:
                result.extend(string_pool(reader, offset, limits))
            elif kind in {2, 3, 0x0200}:
                walk(offset + header_size, offset + size, depth + 1)
            if len(result) > limits.max_strings:
                raise BudgetExceeded("Resource string count exceeds the budget")
            offset += size

    walk(0, len(data), 0)
    return result


def xml_nodes(data, limits, budget):
    if data.lstrip().startswith((b"<", b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        root = ET.fromstring(data)
        nodes = []

        def visit(element, depth):
            budget.check()
            if depth > 128 or len(nodes) >= limits.max_strings:
                raise BudgetExceeded("XML structure exceeds the budget")
            attrs = {}
            for name, value in element.attrib.items():
                key = name.replace("{" + ANDROID_NAMESPACE + "}", "android:")
                attrs[key] = value
            nodes.append(
                {
                    "name": element.tag.rsplit("}", 1)[-1],
                    "attrs": attrs,
                    "depth": depth,
                    "text": element.text or "",
                    "tail": element.tail or "",
                }
            )
            for child in element:
                visit(child, depth + 1)

        visit(root, 0)
        return nodes
    reader = BinaryReader(data)
    if reader.u16(0) != 3 or reader.u16(2) < 8 or reader.u32(4) != len(data):
        raise AnalysisError("Input is not a supported Android XML document")
    strings = []
    nodes = []
    depth = 0
    element_stack = []
    offset = reader.u16(2)

    def lookup(index):
        if index == NO_INDEX:
            return None
        if index >= len(strings):
            raise AnalysisError("XML string index is outside the string pool")
        return strings[index]["value"]

    while offset < len(data):
        budget.check()
        reader.require(offset, 8)
        kind, header_size, size = (
            reader.u16(offset),
            reader.u16(offset + 2),
            reader.u32(offset + 4),
        )
        if header_size < 8 or size < header_size:
            raise AnalysisError("Invalid XML chunk header")
        reader.require(offset, size)
        if kind == 1:
            strings = string_pool(reader, offset, limits)
        elif kind == 0x0102:
            reader.require(offset + header_size, 20, offset + size)
            extension = offset + header_size
            attr_start, attr_size, attr_count = (
                reader.u16(extension + 8),
                reader.u16(extension + 10),
                reader.u16(extension + 12),
            )
            if attr_size < 20 or attr_start < 20:
                raise AnalysisError("Invalid XML attribute layout")
            attributes = {}
            start = extension + attr_start
            reader.require(start, attr_size * attr_count, offset + size)
            for index in range(attr_count):
                position = start + index * attr_size
                namespace = lookup(reader.u32(position))
                name = lookup(reader.u32(position + 4))
                if not name:
                    raise AnalysisError("XML attribute name is missing")
                raw = lookup(reader.u32(position + 8))
                value_type = data[position + 15]
                value = reader.u32(position + 16)
                if value_type == 3:
                    value = lookup(value)
                elif value_type == 0x12:
                    value = bool(value)
                elif value_type in {1, 2, 7, 8}:
                    value = f"@0x{value:08x}"
                elif value_type not in {0x10, 0x11}:
                    value = (
                        raw if raw is not None else {"type": value_type, "data": value}
                    )
                key = (
                    "android:" + name
                    if namespace == ANDROID_NAMESPACE
                    else (f"{{{namespace}}}{name}" if namespace else name)
                )
                attributes[key] = value
            name = lookup(reader.u32(extension + 4))
            if not name or depth >= 128 or len(nodes) >= limits.max_strings:
                raise AnalysisError("XML name or nesting is unsupported")
            nodes.append({"name": name, "attrs": attributes, "depth": depth})
            element_stack.append(name)
            depth += 1
        elif kind == 0x0103:
            reader.require(offset + header_size, 8, offset + size)
            name = lookup(reader.u32(offset + header_size + 4))
            if not element_stack or element_stack.pop() != name:
                raise AnalysisError("Unbalanced XML element names")
            depth -= 1
            if depth < 0:
                raise AnalysisError("Unbalanced XML elements")
        elif kind == 0x0104:
            reader.require(offset + header_size, 12, offset + size)
            nodes.append(
                {
                    "name": "#text",
                    "attrs": {},
                    "depth": depth,
                    "text": lookup(reader.u32(offset + header_size)) or "",
                }
            )
        offset += size
    if depth or not nodes or nodes[0]["depth"] != 0:
        raise AnalysisError("Incomplete XML document")
    return nodes


def instruction_width(units, position):
    word = units[position]
    opcode = word & 255
    if opcode == 0 and word >> 8:
        if position + 1 >= len(units):
            raise AnalysisError("Truncated DEX payload")
        size = units[position + 1]
        if word == 0x0100:
            return 4 + 2 * size
        if word == 0x0200:
            return 2 + 4 * size
        if word == 0x0300:
            if position + 3 >= len(units):
                raise AnalysisError("Truncated DEX array payload")
            length = units[position + 2] | (units[position + 3] << 16)
            return 4 + (size * length + 1) // 2
        raise AnalysisError("Unsupported DEX payload")
    if (
        opcode
        in {
            0x03,
            0x06,
            0x09,
            0x14,
            0x17,
            0x1B,
            0x24,
            0x25,
            0x26,
            0x2A,
            0x2B,
            0x2C,
            0xFC,
            0xFD,
        }
        or 0x6E <= opcode <= 0x72
        or 0x74 <= opcode <= 0x78
    ):
        return 3
    if opcode in {0xFA, 0xFB}:
        return 4
    if opcode == 0x18:
        return 5
    if (
        opcode
        in {
            0x02,
            0x05,
            0x08,
            0x13,
            0x15,
            0x16,
            0x19,
            0x1A,
            0x1C,
            0x1F,
            0x20,
            0x22,
            0x23,
            0x29,
            0xFE,
            0xFF,
        }
        or 0x2D <= opcode <= 0x3D
        or 0x44 <= opcode <= 0x6D
        or 0x90 <= opcode <= 0xAF
        or 0xD0 <= opcode <= 0xE2
    ):
        return 2
    if (
        opcode <= 0x12
        or opcode in {0x1D, 0x1E, 0x21, 0x27, 0x28}
        or 0x7B <= opcode <= 0x8F
        or 0xB0 <= opcode <= 0xCF
    ):
        return 1
    raise AnalysisError(f"Unsupported DEX opcode: 0x{opcode:02x}")


def dex_index(data, limits, budget, inspect_code=True):
    reader = BinaryReader(data)
    reader.require(0, 112)
    if data[:4] != b"dex\n" or data[4:7] not in SUPPORTED_DEX_VERSIONS or data[7] != 0:
        raise AnalysisError("Unsupported DEX format or version")
    if (
        reader.u32(32) != len(data)
        or reader.u32(36) != 112
        or reader.u32(40) != 0x12345678
    ):
        raise AnalysisError("Invalid or unsupported DEX header")
    if (
        reader.u32(8) != zlib.adler32(data[12:]) & 0xFFFFFFFF
        or data[12:32] != hashlib.sha1(data[32:]).digest()
    ):
        raise AnalysisError("DEX checksum or signature does not match its contents")

    def table(size_offset, width):
        count, offset = reader.u32(size_offset), reader.u32(size_offset + 4)
        if count > limits.max_strings:
            raise BudgetExceeded("DEX table count exceeds the budget")
        if count and offset < 112:
            raise AnalysisError("DEX table overlaps its header")
        reader.require(offset, count * width)
        return count, offset

    count, offset = table(56, 4)
    strings = []
    for index in range(count):
        if index % 1024 == 0:
            budget.check()
        position = reader.u32(offset + index * 4)
        declared_length, start = reader.uleb(position)
        end = data.find(
            b"\x00", start, min(len(data), start + limits.max_string_bytes + 1)
        )
        if end < 0:
            raise AnalysisError("DEX string is unterminated or exceeds the budget")
        value = (
            data[start:end]
            .replace(b"\xc0\x80", b"\x00")
            .decode("utf-8", "surrogatepass")
        )
        encoded = value.encode("utf-16-le", "surrogatepass")
        if len(encoded) // 2 != declared_length:
            raise AnalysisError("DEX string length does not match its header")
        strings.append(
            {
                "value": encoded.decode("utf-16-le", "replace"),
                "offset": start,
                "string_index": index,
            }
        )

    def string_at(index):
        if index >= len(strings):
            raise AnalysisError("DEX string index is outside the string table")
        return strings[index]["value"]

    count, offset = table(64, 4)
    types = [string_at(reader.u32(offset + index * 4)) for index in range(count)]

    def type_at(index):
        if index >= len(types):
            raise AnalysisError("DEX type index is outside the type table")
        return types[index]

    count, offset = table(72, 12)
    prototypes = []
    for index in range(count):
        position = offset + index * 12
        return_type = type_at(reader.u32(position + 4))
        parameters = reader.u32(position + 8)
        args = []
        if parameters:
            length = reader.u32(parameters)
            reader.require(parameters + 4, length * 2)
            args = [
                type_at(reader.u16(parameters + 4 + item * 2)) for item in range(length)
            ]
        prototypes.append("(" + "".join(args) + ")" + return_type)
    count, offset = table(88, 8)
    methods = []
    for index in range(count):
        position = offset + index * 8
        proto = reader.u16(position + 2)
        if proto >= len(prototypes):
            raise AnalysisError("DEX prototype index is outside the prototype table")
        methods.append(
            type_at(reader.u16(position))
            + "->"
            + string_at(reader.u32(position + 4))
            + prototypes[proto]
        )
    count, offset = table(96, 32)
    references = {}
    calls = []
    gaps = []
    scanned_methods = 0
    reference_count = 0
    if inspect_code:
        for class_index in range(count):
            budget.check()
            class_data = reader.u32(offset + class_index * 32 + 24)
            if not class_data:
                continue
            try:
                counts = []
                position = class_data
                for _ in range(4):
                    value, position = reader.uleb(position)
                    counts.append(value)
                if sum(counts) > limits.max_strings:
                    raise BudgetExceeded("DEX class data exceeds the budget")
                for _ in range(counts[0] + counts[1]):
                    _, position = reader.uleb(position)
                    _, position = reader.uleb(position)
                for method_count in counts[2:]:
                    method_index = 0
                    for _ in range(method_count):
                        delta, position = reader.uleb(position)
                        method_index += delta
                        _, position = reader.uleb(position)
                        code_offset, position = reader.uleb(position)
                        if method_index >= len(methods):
                            raise AnalysisError(
                                "DEX method index is outside the method table"
                            )
                        if not code_offset:
                            continue
                        reader.require(code_offset, 16)
                        unit_count = reader.u32(code_offset + 12)
                        reader.require(code_offset + 16, unit_count * 2)
                        units = memoryview(data)[
                            code_offset + 16 : code_offset + 16 + unit_count * 2
                        ].cast("H")
                        if sys.byteorder != "little":
                            units = struct.unpack_from(
                                "<" + "H" * unit_count, data, code_offset + 16
                            )
                        cursor = 0
                        while cursor < unit_count:
                            if cursor % 1024 == 0:
                                budget.check()
                            width = instruction_width(units, cursor)
                            if cursor + width > unit_count:
                                raise AnalysisError("Truncated DEX instruction")
                            opcode = units[cursor] & 255
                            location = {
                                "method": methods[method_index],
                                "instruction_offset": cursor,
                                "code_offset": code_offset,
                            }
                            if opcode in {0x1A, 0x1B}:
                                string_index = units[cursor + 1] | (
                                    units[cursor + 2] << 16 if opcode == 0x1B else 0
                                )
                                string_at(string_index)
                                references.setdefault(string_index, []).append(location)
                                reference_count += 1
                            elif (
                                0x6E <= opcode <= 0x72
                                or 0x74 <= opcode <= 0x78
                                or opcode in {0xFA, 0xFB}
                            ):
                                target_index = units[cursor + 1]
                                if target_index >= len(methods):
                                    raise AnalysisError(
                                        "DEX invocation target is outside the method table"
                                    )
                                calls.append(
                                    {**location, "target": methods[target_index]}
                                )
                                reference_count += 1
                            elif opcode in {0xFC, 0xFD}:
                                gaps.append(
                                    "DEX invoke-custom call sites are not resolved"
                                )
                            if reference_count > limits.max_references:
                                raise BudgetExceeded(
                                    "DEX reference count exceeds the budget"
                                )
                            cursor += width
                        scanned_methods += 1
            except Cancelled:
                raise
            except AnalysisError as error:
                gaps.append(str(error))
                if isinstance(error, BudgetExceeded):
                    break
    return {
        "strings": strings,
        "types": types,
        "methods": methods,
        "references": references,
        "calls": calls,
        "scanned_methods": scanned_methods,
        "gaps": sorted(set(gaps)),
    }


def printable_strings(data, minimum=5):
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        yield {
            "value": match.group().decode("ascii"),
            "offset": match.start(),
            "encoding": "ascii",
        }
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, data):
        yield {
            "value": match.group().decode("utf-16-le"),
            "offset": match.start(),
            "encoding": "utf-16-le",
        }
