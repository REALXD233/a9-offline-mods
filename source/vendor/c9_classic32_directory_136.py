"""Downgrade offset-only ZIP64 metadata for legacy packs smaller than 4 GiB.

The pure directory function retains entry order and opaque extra fields. The
create-only file wrapper copies the entire local-header/payload region exactly,
then emits a classic central directory and EOCD. No encryption or compression
is performed. Local ZIP64 payload headers and split archives are rejected.
"""
import hashlib
from pathlib import Path
import struct
import zipfile

from c9_port_pack_writer_124 import write_pack

LIMIT32 = 0xffffffff


def validate_classic32_pack(path):
    """Inspect physical central fields, extras and footer; no payload decoding."""
    path = Path(path)
    if path.stat().st_size >= LIMIT32:
        raise ValueError('Pack exceeds classic ZIP32 length')
    with zipfile.ZipFile(path) as archive, path.open('rb') as stream:
        infos = archive.infolist()
        if len(infos) >= 0xffff:
            raise ValueError('Pack exceeds classic ZIP32 member count')
        end_at = path.stat().st_size - 22 - len(archive.comment)
        stream.seek(end_at)
        eocd = stream.read(22)
        if len(eocd) != 22 or eocd[:4] != b'PK\x05\x06':
            raise ValueError('Missing classic EOCD')
        _, disk, cddisk, n_disk, count, size, offset, comment = struct.unpack('<4s4H2IH', eocd)
        if disk or cddisk or count != len(infos) or n_disk != count or comment != len(archive.comment):
            raise ValueError('Split archive or classic EOCD count mismatch')
        if offset != archive.start_dir or offset + size != end_at:
            raise ValueError('ZIP64 footer or central offset/size mismatch')
        stream.seek(offset)
        for info in infos:
            raw = stream.read(46)
            if len(raw) != 46 or raw[:4] != b'PK\x01\x02':
                raise ValueError('Malformed central header')
            n, x, c = struct.unpack_from('<HHH', raw, 28)
            name = stream.read(n).decode('utf-8')
            extra = stream.read(x)
            stream.read(c)
            values = (*struct.unpack_from('<II', raw, 20), struct.unpack_from('<I', raw, 42)[0])
            if LIMIT32 in values or struct.unpack_from('<H', raw, 34)[0]:
                raise ValueError('Central ZIP64 sentinel or split disk')
            if name != info.filename or values != (info.compress_size, info.file_size, info.header_offset):
                raise ValueError('Central parsed/raw field mismatch')
            pos = 0
            while pos < len(extra):
                if pos + 4 > len(extra):
                    raise ValueError('Truncated central extra')
                kind, length = struct.unpack_from('<HH', extra, pos)
                if kind == 1:
                    raise ValueError('Central ZIP64 extra is forbidden')
                pos += 4 + length
                if pos > len(extra):
                    raise ValueError('Truncated central extra body')
            if info.extract_version > 20:
                raise ValueError('Legacy pack requires extraction version above 20')
        if stream.tell() != end_at:
            raise ValueError('Unexpected data between central directory and EOCD')
    return dict(schema='C9_CLASSIC_ZIP32_PHYSICAL_VALIDATION_136_V1', path=str(path),
                bytes=path.stat().st_size, entries=len(infos), central_offset=offset,
                central_bytes=size, zip64_central_sentinels=0, zip64_extras=0,
                zip64_footer=False, native_game_tested=False)


def write_classic32_pack(source, destination, modified):
    """Scoped wrapper around the existing writer, for sequential calls only.

    Python's ZIP64_LIMIT is process-global: this wrapper is not thread-safe.
    The original limit is restored on success and exception. Existing source
    version-45 indices must first pass the offset-only directory repair.
    """
    source, destination = Path(source), Path(destination)
    if destination.exists() or source.stat().st_size >= LIMIT32:
        raise ValueError('Existing output or oversized source')
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        new_names = set(modified) - {i.filename for i in infos}
        if len(infos) + len(new_names) >= 0xffff or any(i.file_size >= LIMIT32 for i in infos):
            raise ValueError('Classic member/count limit exceeded')
        if any(i.extract_version > 20 for i in infos):
            raise ValueError('Normalize offset-only ZIP64 source directory before building')
    if any(len(payload) >= LIMIT32 for payload in modified.values()):
        raise ValueError('Modified member exceeds classic32')
    previous = zipfile.ZIP64_LIMIT
    try:
        zipfile.ZIP64_LIMIT = LIMIT32
        write_pack(source, destination, modified)
    finally:
        zipfile.ZIP64_LIMIT = previous
    return validate_classic32_pack(destination)


def classic32_directory(data, expected_entries):
    if not 0 <= expected_entries < 0xffff:
        raise ValueError('Entry count exceeds classic ZIP32')
    pos, result, changed = 0, bytearray(), []
    for ordinal in range(expected_entries):
        raw = data[pos:pos + 46]
        if len(raw) != 46 or raw[:4] != b'PK\x01\x02':
            raise ValueError('Malformed central directory header')
        header = bytearray(raw)
        name_len, extra_len, comment_len = struct.unpack_from('<HHH', raw, 28)
        end = pos + 46 + name_len + extra_len + comment_len
        if end > len(data):
            raise ValueError('Truncated central entry')
        name = data[pos + 46:pos + 46 + name_len]
        extra = data[pos + 46 + name_len:pos + 46 + name_len + extra_len]
        comment = data[end - comment_len:end] if comment_len else b''
        compressed, size = struct.unpack_from('<II', raw, 20)
        disk, = struct.unpack_from('<H', raw, 34)
        offset, = struct.unpack_from('<I', raw, 42)
        xp, retained, zip64 = 0, bytearray(), None
        while xp < len(extra):
            if len(extra) - xp < 4:
                raise ValueError('Truncated ZIP extra header')
            kind, length = struct.unpack_from('<HH', extra, xp)
            xe = xp + 4 + length
            if xe > len(extra):
                raise ValueError('Truncated ZIP extra body')
            if kind == 1:
                if zip64 is not None:
                    raise ValueError('Repeated ZIP64 extra')
                zip64 = extra[xp + 4:xe]
            else:
                retained.extend(extra[xp:xe])
            xp = xe
        cursor = 0

        def take(fmt):
            nonlocal cursor
            width = struct.calcsize(fmt)
            if zip64 is None or cursor + width > len(zip64):
                raise ValueError('Missing ZIP64 sentinel value')
            value, = struct.unpack_from(fmt, zip64, cursor)
            cursor += width
            return value

        if size == LIMIT32:
            size = take('<Q')
        if compressed == LIMIT32:
            compressed = take('<Q')
        if offset == LIMIT32:
            offset = take('<Q')
        if disk == 0xffff:
            disk = take('<I')
        if zip64 is not None and cursor != len(zip64):
            raise ValueError('Unsupported redundant ZIP64 fields')
        if any(value >= LIMIT32 for value in (size, compressed, offset)) or disk:
            raise ValueError('Entry requires ZIP64 or a split archive')
        if zip64 is not None:
            struct.pack_into('<II', header, 20, compressed, size)
            struct.pack_into('<H', header, 30, len(retained))
            struct.pack_into('<H', header, 34, 0)
            struct.pack_into('<I', header, 42, offset)
            # The low byte is the ZIP specification version; retain host OS.
            if header[4] == 45:
                header[4] = 20
            if struct.unpack_from('<H', header, 6)[0] == 45:
                struct.pack_into('<H', header, 6, 20)
            changed.append(dict(ordinal=ordinal, name=name.decode('utf-8'), offset=offset,
                                removed_extra_bytes=len(extra) - len(retained)))
        result.extend(header + name + retained + comment)
        pos = end
    if pos != len(data):
        raise ValueError('Unconsumed central directory bytes')
    return bytes(result), dict(entries=expected_entries, converted_entries=changed,
                               converted_count=len(changed),
                               source_directory_bytes=len(data), output_directory_bytes=len(result),
                               local_payload_bytes_modified=0)


def rewrite_classic32_directory(source, destination):
    """Create a new pack; never edit/replace the source or an existing output."""
    source, destination = Path(source), Path(destination)
    if destination.exists() or source.resolve() == destination.resolve():
        raise FileExistsError(destination)
    with zipfile.ZipFile(source) as archive, source.open('rb') as stream:
        infos = archive.infolist()
        start = archive.start_dir
        if len(infos) >= 0xffff or source.stat().st_size >= LIMIT32 or start >= LIMIT32:
            raise ValueError('Pack exceeds supported classic32 limits')
        stream.seek(0)
        if stream.read(6) != b'\0\0PK\x03\x04':
            raise ValueError('Unexpected pack wrapper')
        total = 0
        for info in infos:
            stream.seek(info.header_offset)
            header = stream.read(30)
            if header[:4] != b'PK\x03\x04':
                raise ValueError('Invalid local header')
            version, = struct.unpack_from('<H', header, 4)
            comp, size = struct.unpack_from('<II', header, 18)
            if version > 20 or comp == LIMIT32 or size == LIMIT32:
                raise ValueError('Local ZIP64/features require a separate payload-header rewrite')
        # Bound the directory by its declared entry framing, excluding the ZIP64
        # EOCD/locator/footer which Python can append at offsets above 2 GiB.
        stream.seek(start)
        central = bytearray()
        for _ in infos:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b'PK\x01\x02':
                raise ValueError('Missing central directory')
            n, x, c = struct.unpack_from('<HHH', header, 28)
            payload = stream.read(n + x + c)
            if len(payload) != n + x + c:
                raise ValueError('Truncated central directory')
            central.extend(header + payload)
        classic, receipt = classic32_directory(bytes(central), len(infos))
        if start + len(classic) + 22 + len(archive.comment) >= LIMIT32:
            raise ValueError('Rebuilt classic archive exceeds 4 GiB')
        digest = hashlib.sha256()
        with destination.open('xb') as out:
            stream.seek(0)
            remaining = start
            while remaining:
                part = stream.read(min(8 * 1024 * 1024, remaining))
                if not part:
                    raise ValueError('Source truncated during payload copy')
                out.write(part)
                digest.update(part)
                remaining -= len(part)
            out.write(classic)
            out.write(struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, len(infos), len(infos),
                                  len(classic), start, len(archive.comment)))
            out.write(archive.comment)
    with zipfile.ZipFile(destination) as after:
        expected = [(i.filename, i.header_offset, i.file_size, i.compress_size, i.CRC) for i in infos]
        actual = [(i.filename, i.header_offset, i.file_size, i.compress_size, i.CRC) for i in after.infolist()]
        if expected != actual or after.start_dir != start:
            raise ValueError('Rewritten pack index differs')
    receipt['classic32_validation'] = validate_classic32_pack(destination)
    receipt.update(source=str(source), destination=str(destination),
                   exact_copied_body_bytes=start, exact_copied_body_sha256=digest.hexdigest(),
                   source_writes=0, native_game_tested=False)
    return receipt
