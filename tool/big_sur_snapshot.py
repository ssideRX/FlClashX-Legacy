"""Expose the Dart AOT snapshot via the legacy dyld export command on Intel."""
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
if data[:4] == bytes.fromhex("cafebabe"):
    count, cpu, _, base, size = struct.unpack_from(">IIIII", data, 4)
    if count != 1 or cpu != 0x01000007:
        raise SystemExit("Expected a single Intel Mach-O slice")
else:
    base, size = 0, len(data)

magic, cpu, _, kind, count, commands_size = struct.unpack_from("<6I", data, base)
if (magic, cpu, kind) != (0xFEEDFACF, 0x01000007, 6):
    raise SystemExit("Expected an Intel Mach-O dylib")

start = base + 32
end = start + commands_size
cursor = start
exports = None
first_section = size
for _ in range(count):
    command, length = struct.unpack_from("<II", data, cursor)
    if length < 8 or cursor + length > end:
        raise SystemExit("Invalid load command")
    if command in (0x22, 0x80000022, 0x80000034):
        raise SystemExit("Unexpected existing dyld info or chained fixups")
    if command == 0x80000033:
        if length != 16 or exports is not None:
            raise SystemExit("Unexpected exports command")
        exports = cursor
    if command == 0x19:
        sections = struct.unpack_from("<I", data, cursor + 64)[0]
        for section in range(sections):
            offset = struct.unpack_from("<I", data, cursor + 72 + section * 80 + 48)[0]
            if offset:
                first_section = min(first_section, offset)
    cursor += length

if exports is None or cursor != end or end + 32 > base + first_section:
    raise SystemExit("AOT dylib has no exports command or insufficient header space")
if any(data[end:end + 32]):
    raise SystemExit("Expected zero-filled header padding")

offset, length = struct.unpack_from("<II", data, exports + 8)
if not length or offset + length > size:
    raise SystemExit("Invalid exports trie")
data[exports + 48:end + 32] = data[exports + 16:end]
struct.pack_into("<12I", data, exports, 0x80000022, 48, *([0] * 8), offset, length)
struct.pack_into("<I", data, base + 20, commands_size + 32)
path.write_bytes(data)
