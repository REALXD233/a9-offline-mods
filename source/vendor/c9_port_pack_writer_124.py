"""Bounded offline pack/GDB writer for the three-car compatibility port.

No game execution or installation. Unknown GDB bodies and pack members are
preserved. Native legacy-reader compatibility remains a separate runtime test.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
from pathlib import Path
import struct
import zipfile
import zlib

from c9_packaged_resource_index import (
    DEFAULT_MANIFEST_KEY, MASK32, derive_stream_key, decrypt_stream,
    decode_resource, parse_manifest,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encrypt_stream(data, password, iv=0x124C9001, rounds=8):
    if rounds not in (8, 32):
        raise ValueError('Unsupported rounds')
    key = derive_stream_key(password)
    padding = 8-len(data) % 8
    plain = data+bytes([padding])*padding
    result = bytearray(struct.pack('<I', iv))
    counter = iv
    for pos in range(0, len(plain), 8):
        a, b = struct.unpack_from('<II', plain, pos)
        a ^= counter
        counter = (counter+1) & MASK32
        b ^= counter
        counter = (counter+1) & MASK32
        total = 0
        for _ in range(rounds):
            a = (a + (((((b << 4 & MASK32) ^ (b >> 5))+b) & MASK32)
                       ^ ((total+key[total & 3]) & MASK32))) & MASK32
            total = (total+0x9E3779B9) & MASK32
            b = (b + (((((a << 4 & MASK32) ^ (a >> 5))+a) & MASK32)
                       ^ ((total+key[(total >> 11) & 3]) & MASK32))) & MASK32
        result.extend(struct.pack('<II', a, b))
    encoded = bytes(result)
    if decrypt_stream(encoded, password, rounds) != data:
        raise ValueError('Encryption roundtrip failed')
    return encoded


def encode_entry(entry, plain, original_raw=None):
    data = plain
    updated = replace(entry, size_value=len(plain)) if entry.compression_flags == 'C' else entry
    if entry.compression_flags == 'C':
        compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
        data = compressor.compress(data)+compressor.flush()
    if entry.encryption_flags == 'X':
        iv = struct.unpack_from('<I', original_raw)[0] if original_raw else 0x124C9001
        data = encrypt_stream(data, entry.stream_password.encode('ascii'), iv)
    return updated, data


def manifest_line(entry):
    return ':'.join(map(str, (
        entry.field0, entry.field1, entry.logical_path, entry.compression_flags,
        '-' if entry.size_value is None else entry.size_value,
        entry.encryption_flags, entry.stream_password, entry.storage_name,
    )))


def prepare_members(pack, replacements, additions=()):
    """Return encoded ZIP members, updated manifest, decoded-body receipts."""
    entries = list(pack.entries)
    by_path = dict(pack.by_path)
    if set(replacements)-set(by_path):
        raise ValueError('Unknown replacement path')
    modified = {}
    receipts = []
    for i, entry in enumerate(entries):
        if entry.logical_path not in replacements:
            continue
        plain = replacements[entry.logical_path]
        old = pack.z.read(entry.storage_name)
        updated, encoded = encode_entry(entry, plain, old)
        entries[i] = updated
        modified[entry.storage_name] = encoded
        receipts.append(dict(path=entry.logical_path, storage=entry.storage_name,
                             decoded_bytes=len(plain), decoded_sha256=sha(plain),
                             encoded_sha256=sha(encoded), added=False))
    for entry, plain in additions:
        if entry.logical_path in by_path or entry.storage_name in pack.names or entry.storage_name in modified:
            raise ValueError('Duplicate added member/path')
        updated, encoded = encode_entry(entry, plain)
        by_path[entry.logical_path] = updated
        entries.append(updated)
        modified[entry.storage_name] = encoded
        receipts.append(dict(path=entry.logical_path, storage=entry.storage_name,
                             decoded_bytes=len(plain), decoded_sha256=sha(plain),
                             encoded_sha256=sha(encoded), added=True))
    # All line fields, including opaque build metadata, are retained.
    newline = '\r\n' if b'\r\n' in pack.manifest else '\n'
    manifest = newline.join(manifest_line(e) for e in entries).encode('utf-8')
    if pack.manifest.endswith((b'\r', b'\n')):
        manifest += newline.encode('ascii')
    if parse_manifest(manifest) != entries:
        raise ValueError('Manifest serialization failed')
    original_manifest = pack.z.read(pack.manifest_name)
    iv = struct.unpack_from('<I', original_manifest)[0]
    modified[pack.manifest_name] = encrypt_stream(manifest, DEFAULT_MANIFEST_KEY, iv)
    return modified, entries, receipts


def without_zip64_extra(extra):
    """Do not carry absolute offsets/sizes from a previous ZIP layout.

    zipfile generates fresh ZIP64 fields itself when sentinel values require
    them. Blindly preserving the original tag-1 data creates two incompatible
    index views for legacy readers which consult the extra independently.
    """
    result = bytearray()
    pos = 0
    while pos < len(extra):
        if len(extra)-pos < 4:
            raise ValueError('Truncated ZIP extra header')
        kind, length = struct.unpack_from('<HH', extra, pos)
        end = pos+4+length
        if end > len(extra):
            raise ValueError('Truncated ZIP extra body')
        if kind != 1:
            result.extend(extra[pos:end])
        pos = end
    return bytes(result)


def write_pack(source_path, destination, modified):
    """Create-only classic ZIP, retaining the source's two-byte wrapper."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    with Path(source_path).open('rb') as src:
        if src.read(6) != b'\0\0PK\x03\x04':
            raise ValueError('Unexpected pack wrapper')
    with zipfile.ZipFile(source_path) as zin, destination.open('xb') as target:
        target.write(b'\0\0')
        with zipfile.ZipFile(target, 'w', allowZip64=True) as zout:
            zout.comment = zin.comment
            old_names = set()
            for info in zin.infolist():
                old_names.add(info.filename)
                data = modified.get(info.filename)
                if data is None:
                    data = zin.read(info)
                updated = copy.copy(info)
                updated.extra = without_zip64_extra(info.extra)
                zout.writestr(updated, data)
            for name in sorted(set(modified)-old_names):
                info = zipfile.ZipInfo(name, (2026, 10, 22, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                zout.writestr(info, modified[name])
    with zipfile.ZipFile(source_path) as zin, zipfile.ZipFile(destination) as zout:
        expected_names = set(zin.namelist()) | set(modified)
        if set(zout.namelist()) != expected_names or len(zout.namelist()) != len(expected_names):
            raise ValueError('Pack member identity mismatch')
        for name in expected_names:
            expected = modified[name] if name in modified else zin.read(name)
            if zout.read(name) != expected:
                raise ValueError('Pack byte preservation failed: '+name)

