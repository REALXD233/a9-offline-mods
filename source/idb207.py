"""Pure old47 IDB library-row codec and stable module union.

IDB is not a generic GDB. Its opaque 8-byte header, original row order and
library string order are retained. This helper performs no file or process IO.
"""
import struct

def parse_idb(raw):
    if not isinstance(raw, bytes) or len(raw)<12:
        raise ValueError('Short IDB')
    count,=struct.unpack_from('<I',raw,8)
    if count>100000:
        raise ValueError('IDB row limit')
    at=12;rows=[];seen=set()
    for _ in range(count):
        if at+12>len(raw):raise ValueError('Truncated IDB row')
        uid,n=struct.unpack_from('<QI',raw,at);at+=12
        if n>1000 or uid in seen:raise ValueError('Duplicate IDB UID or library limit')
        seen.add(uid);names=[]
        for _ in range(n):
            if at+4>len(raw):raise ValueError('Truncated IDB string length')
            size,=struct.unpack_from('<I',raw,at);at+=4
            if not 0<size<4096 or at+size>len(raw):raise ValueError('Invalid IDB string')
            name=raw[at:at+size].decode('utf-8');at+=size
            if '\0' in name:raise ValueError('NUL in IDB library')
            names.append(name)
        rows.append(dict(key=f'{uid:016x}',names=names))
    if at!=len(raw):raise ValueError('Unknown IDB footer')
    return raw[:8],rows

def _row(row):
    uid=row.get('key');names=row.get('names')
    if not isinstance(uid,str) or len(uid)!=16 or any(c not in '0123456789abcdef' for c in uid):raise ValueError('Invalid IDB UID')
    if not isinstance(names,list) or len(names)>1000:raise ValueError('Invalid IDB libraries')
    out=bytearray(struct.pack('<QI',int(uid,16),len(names)))
    for name in names:
        if not isinstance(name,str) or '\0' in name:raise ValueError('Invalid library string')
        b=name.encode('utf-8')
        if not 0<len(b)<4096:raise ValueError('Invalid library length')
        out.extend(struct.pack('<I',len(b)));out.extend(b)
    return bytes(out)

def compose_idb(base, contributions):
    """Append active groups, preserving their authenticated source order.

    contributions is a list of rows {key,names,source_ordinal}. Owner selection
    is the caller's responsibility. No generic typed-record API is involved.
    Existing UIDs, duplicate new UIDs/order ordinals, or unbounded rows reject.
    """
    header,old=parse_idb(base);seen={r['key'] for r in old};new=[];ordinals=set()
    for row in contributions:
        if set(row)!={'key','names','source_ordinal'}:raise ValueError('Unknown IDB contribution fields')
        ordinal=row['source_ordinal']
        if type(ordinal) is not int or ordinal<len(old) or ordinal in ordinals:raise ValueError('Invalid or duplicate IDB source ordinal')
        _row(row)
        if row['key'] in seen:raise ValueError('IDB contribution UID collision')
        seen.add(row['key']);ordinals.add(ordinal);new.append(row)
    new.sort(key=lambda r:r['source_ordinal'])
    rows=old+[dict(key=r['key'],names=r['names']) for r in new]
    if len(rows)>100000:raise ValueError('IDB row limit')
    result=header+struct.pack('<I',len(rows))+b''.join(_row(r) for r in rows)
    assert parse_idb(result)==(header,rows)
    if not new and result!=base:raise ValueError('IDB baseline not canonical')
    return result
