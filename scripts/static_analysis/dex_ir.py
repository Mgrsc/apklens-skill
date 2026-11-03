from .common import AnalysisError

MAX_METHOD_UNITS = 16384
MAX_ARTIFACT_UNITS = 131072
MAX_INDEXED_METHODS = 4096


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def indexed(values, index):
    if index >= len(values):
        raise AnalysisError("DEX operand is outside its reference table")
    return values[index]


def decode_instruction(units, position, width, strings, types, fields, methods):
    word = units[position]
    op = word & 255
    a, b = word >> 8 & 15, word >> 12
    item = {"offset": position, "opcode": op, "next": position + width}
    if op == 0 and word:
        item["payload"] = True
    elif op in {1, 4, 7}:
        item.update(dest=a, regs=[b])
    elif op in {2, 5, 8}:
        item.update(dest=word >> 8, regs=[units[position + 1]])
    elif op in {3, 6, 9}:
        item.update(dest=units[position + 1], regs=[units[position + 2]])
    elif op in {10, 11, 12, 13}:
        item["dest"] = word >> 8
    elif op in {15, 16, 17, 29, 30, 31, 39}:
        item["regs"] = [word >> 8]
    elif op == 18:
        item.update(dest=a, value=signed(b, 4))
    elif op in {19, 22}:
        item.update(dest=word >> 8, value=signed(units[position + 1], 16))
    elif op in {20, 23}:
        item.update(
            dest=word >> 8,
            value=signed(units[position + 1] | units[position + 2] << 16, 32),
        )
    elif op in {21, 25}:
        item.update(
            dest=word >> 8,
            value=signed(units[position + 1], 16) << (16 if op == 21 else 48),
        )
    elif op == 24:
        value = sum(units[position + i + 1] << (16 * i) for i in range(4))
        item.update(dest=word >> 8, value=signed(value, 64))
    elif op in {26, 27}:
        index = units[position + 1] | (units[position + 2] << 16 if op == 27 else 0)
        item.update(dest=word >> 8, value=indexed(strings, index)["value"])
    elif op in {28, 34}:
        item.update(dest=word >> 8, type=indexed(types, units[position + 1]))
    elif op == 32:
        item.update(dest=a, regs=[b], type=indexed(types, units[position + 1]))
    elif op == 33:
        item.update(dest=a, regs=[b])
    elif op == 35:
        item.update(dest=a, regs=[b], type=indexed(types, units[position + 1]))
    elif op in {36, 37}:
        item["type"] = indexed(types, units[position + 1])
        if op == 36:
            packed = units[position + 2]
            item["regs"] = [packed >> (4 * i) & 15 for i in range(4)] + [a]
            item["regs"] = item["regs"][:b]
        else:
            item["regs"] = list(
                range(units[position + 2], units[position + 2] + (word >> 8))
            )
    elif op in {40, 41, 42}:
        displacement = (
            signed(word >> 8, 8)
            if op == 40
            else signed(units[position + 1], 16)
            if op == 41
            else signed(units[position + 1] | units[position + 2] << 16, 32)
        )
        item["target"] = position + displacement
    elif op in {43, 44, 38}:
        item["regs"] = [word >> 8]
        item["unsupported"] = "switch_or_array_payload"
    elif 45 <= op <= 49:
        item.update(
            dest=word >> 8, regs=[units[position + 1] & 255, units[position + 1] >> 8]
        )
    elif 50 <= op <= 61:
        item["regs"] = [a, b] if op <= 55 else [word >> 8]
        item["target"] = position + signed(units[position + 1], 16)
    elif 68 <= op <= 81:
        item.update(
            regs=[word >> 8, units[position + 1] & 255, units[position + 1] >> 8]
        )
    elif 82 <= op <= 95:
        item.update(regs=[a, b], field=indexed(fields, units[position + 1]))
    elif 96 <= op <= 109:
        item.update(regs=[word >> 8], field=indexed(fields, units[position + 1]))
    elif 110 <= op <= 114 or 116 <= op <= 120:
        item["target"] = indexed(methods, units[position + 1])
        if op <= 114:
            packed = units[position + 2]
            item["regs"] = ([packed >> (4 * i) & 15 for i in range(4)] + [a])[:b]
        else:
            item["regs"] = list(
                range(units[position + 2], units[position + 2] + (word >> 8))
            )
        item["static"] = op in {113, 119}
    elif 123 <= op <= 143:
        item.update(dest=a, regs=[b])
    elif 144 <= op <= 175:
        item.update(
            dest=word >> 8, regs=[units[position + 1] & 255, units[position + 1] >> 8]
        )
    elif 176 <= op <= 207:
        item.update(dest=a, regs=[a, b])
    elif 208 <= op <= 215:
        item.update(dest=a, regs=[b], literal=signed(units[position + 1], 16))
    elif 216 <= op <= 226:
        item.update(
            dest=word >> 8,
            regs=[units[position + 1] & 255],
            literal=signed(units[position + 1] >> 8, 8),
        )
    elif op not in {0, 14}:
        item["unsupported"] = "unmodeled_instruction"
    return item


def exception_regions(reader, code_offset, unit_count, types, budget):
    count = reader.u16(code_offset + 6)
    if not count:
        return []
    start = (code_offset + 16 + unit_count * 2 + 3) & ~3
    reader.require(start, count * 8)
    handlers = start + count * 8

    def sleb(position):
        result, shift = 0, 0
        while shift < 35:
            reader.require(position, 1)
            byte = reader.data[position]
            position += 1
            result |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                return (result - (1 << shift) if byte & 64 else result), position
        raise AnalysisError("Invalid DEX signed LEB128")

    regions = []
    for index in range(count):
        if index % 256 == 0:
            budget.check()
        position = start + index * 8
        first, length = reader.u32(position), reader.u16(position + 4)
        size, cursor = sleb(handlers + reader.u16(position + 6))
        targets = []
        for handler_index in range(abs(size)):
            if handler_index % 256 == 0:
                budget.check()
            kind, cursor = reader.uleb(cursor)
            indexed(types, kind)
            target, cursor = reader.uleb(cursor)
            targets.append(target)
        if size <= 0:
            target, cursor = reader.uleb(cursor)
            targets.append(target)
        if first + length > unit_count or any(
            target >= unit_count for target in targets
        ):
            raise AnalysisError("DEX exception region is outside its method")
        regions.append({"start": first, "end": first + length, "targets": targets})
    budget.check()
    return regions
