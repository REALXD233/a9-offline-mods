"""Read-only decoder for the inspected C9 610k packaged resource index.

The algorithms are from the local ARM64 resource loader, not an A8 parser.
This module does not modify APKs, contact devices or assign physical units.
Index names are numeric formatted values, NOT hexadecimal string literals.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
import zlib

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
MURMUR_M = 0x5BD1E995
HASH_SEED = 0xC6A4A7935BD1E995
DEFAULT_MANIFEST_KEY = b'Error 3452: file not found'
MAX_MANIFEST = 16 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_RESOURCE = 32 * 1024 * 1024


def murmur32(data: bytes, seed: int = 0) -> int:
    """0x4b1a080/0x4b1a2dc; cached string hash used by 0x3654330."""
    h = len(data) ^ (seed & MASK32)
    cursor = 0
    while len(data) - cursor >= 4:
        k, = struct.unpack_from('<I', data, cursor)
        cursor += 4
        k = k * MURMUR_M & MASK32
        k ^= k >> 24
        k = k * MURMUR_M & MASK32
        h = (h * MURMUR_M & MASK32) ^ k
    if cursor < len(data):
        h ^= int.from_bytes(data[cursor:], 'little')
        h = h * MURMUR_M & MASK32
    h ^= h >> 13
    h = h * MURMUR_M & MASK32
    return h ^ (h >> 15)


def murmur64b(data: bytes, seed: int = 0) -> int:
    """0x4b1a0f4/0x4b1a2a0, 32-bit seed variant, low h2/high h1."""
    h1, h2 = len(data) ^ (seed & MASK32), 0
    cursor = 0
    while len(data) - cursor >= 8:
        k1, k2 = struct.unpack_from('<II', data, cursor)
        cursor += 8
        for index, k in enumerate((k1, k2)):
            k = k * MURMUR_M & MASK32
            k ^= k >> 24
            k = k * MURMUR_M & MASK32
            if index == 0:
                h1 = (h1 * MURMUR_M & MASK32) ^ k
            else:
                h2 = (h2 * MURMUR_M & MASK32) ^ k
    if len(data) - cursor >= 4:
        k, = struct.unpack_from('<I', data, cursor)
        cursor += 4
        k = k * MURMUR_M & MASK32
        k ^= k >> 24
        k = k * MURMUR_M & MASK32
        h1 = (h1 * MURMUR_M & MASK32) ^ k
    if cursor < len(data):
        h2 ^= int.from_bytes(data[cursor:], 'little')
        h2 = h2 * MURMUR_M & MASK32
    h1 = (h1 ^ (h2 >> 18)) * MURMUR_M & MASK32
    h2 = (h2 ^ (h1 >> 22)) * MURMUR_M & MASK32
    h1 = (h1 ^ (h2 >> 17)) * MURMUR_M & MASK32
    h2 = (h2 ^ (h1 >> 19)) * MURMUR_M & MASK32
    return h2 | (h1 << 32)


def resource_name(mount: str, logical_path: str) -> str:
    """Hash used to locate a manifest; ordinary files use field 7 instead.

    Do not recompute an ordinary resource's packaged filename from its path:
    the manifest stores actual names, which may reflect offline build naming.
    """
    seed = HASH_SEED
    for string in (mount, logical_path):
        h = (murmur32(string.encode('utf-8')) + 0x9E3779B9) & MASK32
        seed ^= (h + (seed << 6) + (seed >> 2)) & MASK64
    return f'{seed:016X}'


def derive_stream_key(password: bytes) -> tuple[int, int, int, int]:
    """0x4b38d54; an empty password leaves native temporary bytes undefined."""
    if not password:
        raise ValueError('A nonempty stream key is required')
    first = struct.pack('<Q', murmur64b(password))
    mixed = bytes(password[i % len(password)] ^ first[i] for i in range(8))
    return struct.unpack('<4I', first + struct.pack('<Q', murmur64b(mixed)))


def decrypt_stream(data: bytes, password: bytes, rounds: int = 8,
                   check_all_padding: bool = True) -> bytes:
    """4-byte IV, XTEA then XOR each uint32 with the incrementing IV.

    0x4b38fc0/0x4b38e28/0x4b38eac. Native checks only the last padding
    length byte; this offline extractor additionally checks the padding body.
    """
    if rounds not in (8, 32) or len(data) < 12 or (len(data) - 4) % 8:
        raise ValueError('Invalid encrypted stream framing or round count')
    k = derive_stream_key(password)
    counter, = struct.unpack_from('<I', data)
    result = bytearray(len(data) - 4)
    for pos in range(4, len(data), 8):
        a, b = struct.unpack_from('<II', data, pos)
        total = rounds * 0x9E3779B9 & MASK32
        for _ in range(rounds):
            b = (b - (((((a << 4 & MASK32) ^ (a >> 5)) + a) & MASK32)
                      ^ ((total + k[(total >> 11) & 3]) & MASK32))) & MASK32
            total = (total - 0x9E3779B9) & MASK32
            a = (a - (((((b << 4 & MASK32) ^ (b >> 5)) + b) & MASK32)
                      ^ ((total + k[total & 3]) & MASK32))) & MASK32
        a ^= counter
        counter = (counter + 1) & MASK32
        b ^= counter
        counter = (counter + 1) & MASK32
        struct.pack_into('<II', result, pos - 4, a, b)
    padding = result[-1]
    if not 1 <= padding <= 8 or padding > len(result):
        raise ValueError('Invalid decrypted stream padding')
    if check_all_padding and result[-padding:] != bytes([padding]) * padding:
        raise ValueError('Inconsistent decrypted stream padding')
    return bytes(result[:-padding])


@dataclass(frozen=True)
class ManifestEntry:
    field0: int
    field1: int
    logical_path: str
    compression_flags: str
    size_value: int | None
    encryption_flags: str
    stream_password: str
    storage_name: str

    def as_dict(self, mount: str) -> dict:
        result = dict(self.__dict__)
        result['apk_entry'] = f'assets/{mount}/{self.storage_name}'
        return result


def parse_manifest(data: bytes) -> list[ManifestEntry]:
    if len(data) > MAX_MANIFEST:
        raise ValueError('Manifest exceeds offline size budget')
    lines = data.decode('utf-8').splitlines()
    if len(lines) > MAX_ENTRIES:
        raise ValueError('Manifest exceeds offline entry budget')
    result = []
    seen = set()
    for line in lines:
        if not line:
            continue
        fields = line.split(':')
        if len(fields) != 8:
            raise ValueError('Expected eight manifest fields')
        if not fields[2].startswith('/') or fields[2] in seen:
            raise ValueError('Invalid or duplicate logical resource path')
        if not re.fullmatch(r'[0-9A-F]{16}', fields[7]):
            raise ValueError('Unsupported packaged storage name')
        if fields[3] not in ('C', 'NC') or fields[5] not in ('X', 'NX'):
            raise ValueError('Unsupported compression/encryption flags')
        numbers = []
        for index in (0, 1, 4):
            field = fields[index]
            if index == 4 and field == '-':
                numbers.append(None)
                continue
            if not field.isascii() or not field.isdecimal() or len(field) > 20:
                raise ValueError('Expected uint64 decimal manifest field')
            value = int(field)
            if value > MASK64:
                raise ValueError('Manifest uint64 overflow')
            numbers.append(value)
        if fields[3] == 'C' and numbers[2] is None:
            raise ValueError('Compressed resource needs its uncompressed size')
        if fields[5] == 'X' and (not fields[6].isascii() or not fields[6].isdecimal()
                                 or len(fields[6]) > 20 or int(fields[6]) > MASK64):
            raise ValueError('Encrypted resource needs a uint64 decimal key')
        result.append(ManifestEntry(numbers[0], numbers[1], fields[2], fields[3],
                                    numbers[2], fields[5], fields[6], fields[7]))
        seen.add(fields[2])
    return result


def read_bounded(z: zipfile.ZipFile, name: str, limit: int) -> bytes:
    info = z.getinfo(name)
    if info.file_size > limit:
        raise ValueError('APK entry exceeds offline read budget')
    with z.open(info) as stream:
        data = stream.read(limit + 1)
    if len(data) != info.file_size:
        raise ValueError('APK entry length changed or exceeded read budget')
    return data


def read_manifest(z: zipfile.ZipFile, mount: str = 'main') -> tuple[str, bytes, list[ManifestEntry]]:
    # Second format argument at 0x67bca38 is uint32 100, NOT the string "d".
    name = f'assets/{mount}/{resource_name(mount, "__manifest_X_100__")}'
    encrypted = read_bounded(z, name, MAX_MANIFEST + 12)
    plain = decrypt_stream(encrypted, DEFAULT_MANIFEST_KEY)
    return name, plain, parse_manifest(plain)


def inflate_raw_bounded(data: bytes, expected_size: int) -> bytes:
    """Full-file reader 0x4b33bd0 uses decryption then raw DEFLATE.

    No unconstrained zlib.decompress: bound expansion and require one complete
    stream with no trailing bytes, matching the manifest's recorded length.
    """
    if not 0 <= expected_size <= MAX_RESOURCE:
        raise ValueError('Resource exceeds offline expansion budget')
    decoder = zlib.decompressobj(-15)
    result = decoder.decompress(data, expected_size + 1)
    if len(result) != expected_size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('Compressed resource length/framing does not match manifest')
    return result


def decode_resource(z: zipfile.ZipFile, entry: ManifestEntry, mount: str = 'main') -> tuple[bytes, dict]:
    name = entry.as_dict(mount)['apk_entry']
    raw = read_bounded(z, name, MAX_RESOURCE + 12)
    data = decrypt_stream(raw, entry.stream_password.encode('ascii')) if entry.encryption_flags == 'X' else raw
    if entry.compression_flags == 'C':
        if entry.size_value is None or entry.size_value > MASK32:
            raise ValueError('Unsupported packed compressed size/codec field')
        data = inflate_raw_bounded(data, entry.size_value)
    return data, {
        **entry.as_dict(mount),
        'packaged_bytes': len(raw),
        'packaged_sha256': hashlib.sha256(raw).hexdigest(),
        'decoded_bytes': len(data),
        'decoded_sha256': hashlib.sha256(data).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with zipfile.ZipFile(args.apk) as z:
        name, plain, entries = read_manifest(z)
        paths = set(z.namelist())
        candidates = [e for e in entries if e.logical_path.rsplit('/', 1)[-1]
                      in ('Asphalt9.idb', 'CarDef.gdb', 'CarPhysics.gdb', 'CarChassis.gdb')]
        report = {
            'schema': 'C9_PACKAGED_RESOURCE_INDEX_PROBE_V1',
            'apk_path': str(args.apk.resolve()),
            'manifest_apk_entry': name,
            'manifest_plain_size': len(plain),
            'manifest_plain_sha256': hashlib.sha256(plain).hexdigest(),
            'entry_count': len(entries),
            'resolved_apk_entries': sum(e.as_dict('main')['apk_entry'] in paths for e in entries),
            'compression_flags': dict(Counter(e.compression_flags for e in entries)),
            'encryption_flags': dict(Counter(e.encryption_flags for e in entries)),
            'vehicle_resource_candidates': [e.as_dict('main') for e in candidates],
            'actual_physics_resource_bodies_extracted': False,
            'vehicle_identity_verified': False,
            'si_units_calibrated': False,
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Do not overwrite an earlier extraction receipt.
    with args.out.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'vehicle_resource_candidates'},
                     ensure_ascii=False))
    print(json.dumps(report['vehicle_resource_candidates'][:12], ensure_ascii=False))


if __name__ == '__main__':
    main()
