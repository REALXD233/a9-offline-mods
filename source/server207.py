"""Trusted, deterministic public-server composer for the known stable r203/206.

No filesystem access in compose(). Inputs are immutable public base bytes;
the engine must retain that base and compare current files before transactions.
Never execute Python supplied by a mod package.
"""
import ast
import hashlib
import json
import struct

SCHEMA = 'A9_MOD_SERVER207_V1'
MODULES = {'career': (), 'fastest': (1003,), 'CN': (5018, 5002, 5021, 5009), 'ALU': (294, 345)}
ALL_CIDS = frozenset(c for group in MODULES.values() for c in group)
TRUSTED_RUNTIME_SHA256 = '1386ca621a006b2e15bfb557c291386e2a166e46ca6230a0c41542177100d9d7'
SOURCE_SHA256 = {
    'a9emu/profile.py': 'fbabee0b5890f2d637f9740197e78a87e32f9a99b1d4009fc1cda39835540c7d',
    'a9emu/business.py': '284a5037ce47584752998c7ba0458d26eb6567ee07a16118cc2cb546fbfeb33b',
    'a9emu/cardb.py': 'ca9271a339ea19df8f08935d87ff46a3807319d608ee7b42ecc3fe014ba7c4c6',
    'a9emu/gamedata/A9-business.gdb': 'd9240a8b46f392739ec9f27e41a9b40800ab33b9aa2ad746b96a3b1bdf83b1e9',
    'a9emu/gamedata/car_ids.json': 'd2d48a467dec6fdce94a72870be8893f330b796ea668293781078429ed55f820',
}
CAR_TYPE = 0x09D4095A
ROOT_TYPE = 0x88D9CFC1


def sha(b):
    return hashlib.sha256(b).hexdigest()


def active_for_modules(names):
    names = tuple(names)
    if len(names) != len(set(names)) or any(n not in MODULES for n in names):
        raise ValueError('unknown or duplicate module')
    return frozenset(c for n in names for c in MODULES[n])


def validate_active(active):
    values = tuple(active)
    if any(type(c) is not int for c in values) or len(values) != len(set(values)):
        raise ValueError('invalid or duplicate active CID')
    active = frozenset(values)
    if not active <= ALL_CIDS:
        raise ValueError('unknown active CID')
    for name, group in MODULES.items():
        if active.intersection(group) and not set(group) <= active:
            raise ValueError('partial module not supported: ' + name)
    return active


def parse_bank(raw):
    if len(raw) < 32:
        raise ValueError('short bank')
    kind, start, end = struct.unpack_from('<QQQ', raw)
    if start != 24 or not start <= end < len(raw):
        raise ValueError('invalid bank header')
    pos = end
    def take(fmt):
        nonlocal pos
        size = struct.calcsize(fmt)
        if pos + size > len(raw):
            raise ValueError('truncated bank index')
        result = struct.unpack_from(fmt, raw, pos)
        pos += size
        return result
    def count():
        n, = take('<I')
        if n > 100000:
            raise ValueError('bank count limit')
        return n
    groups = []
    for _ in range(count()):
        key, = take('<Q')
        lists = [[take('<Q')[0] for _ in range(count())] for _ in range(2)]
        groups.append((key, *lists))
    rows = []
    for _ in range(count()):
        key, offset, length, typ = take('<QQQQ')
        if offset < 24 or offset + length > end:
            raise ValueError('bank row outside payload')
        rows.append((key, offset, length, typ))
    if pos != len(raw) or len({r[0] for r in rows}) != len(rows):
        raise ValueError('bank index ambiguity')
    cursor = 24
    for row in sorted(rows, key=lambda r: r[1]):
        if row[1] < cursor:
            raise ValueError('overlapping bank body')
        cursor = row[1] + row[2]
    return kind, end, groups, rows


def filter_business(raw, active):
    active = validate_active(active)
    kind, end, groups, rows = parse_bank(raw)
    cars = {}
    for row in rows:
        if row[3] == CAR_TYPE:
            cid, = struct.unpack_from('<Q', raw, row[1])
            if cid in cars:
                raise ValueError('duplicate business CID')
            cars[cid] = row
    if not ALL_CIDS <= cars.keys():
        raise ValueError('missing full core metadata')
    keys = {r[0] for r in cars.values()}
    roots = []
    for row in rows:
        if row[3] != ROOT_TYPE or row[2] < 12:
            continue
        body = raw[row[1]:row[1]+row[2]]
        n = struct.unpack_from('<I', body, 8)[0]
        if n == len(keys) and 12+n*8 <= len(body):
            refs = struct.unpack_from('<' + 'Q'*n, body, 12)
            if len(set(refs)) == n and set(refs) == keys:
                roots.append((row, body, refs))
    if len(roots) != 1:
        raise ValueError('ambiguous business registration root')
    root, rootbody, refs = roots[0]
    removed = {cars[c][0] for c in ALL_CIDS-active}
    kept_refs = [k for k in refs if k not in removed]
    replacement = rootbody[:8] + struct.pack('<I', len(kept_refs)) + b''.join(struct.pack('<Q', k) for k in kept_refs) + rootbody[12+8*len(refs):]
    payload, positions, cursor = bytearray(raw[:24]), {}, 24
    for row in sorted(rows, key=lambda r: r[1]):
        key, offset, length, typ = row
        payload.extend(raw[cursor:offset])  # preserve unrelated source gaps
        if key not in removed:
            body = replacement if key == root[0] else raw[offset:offset+length]
            positions[key] = (len(payload), len(body))
            payload.extend(body)
        cursor = offset+length
    payload.extend(raw[cursor:end])
    tail = bytearray(struct.pack('<I', len(groups)))
    for key, list0, list1 in groups:
        tail.extend(struct.pack('<Q', key))
        for items in (list0, list1):
            items = [k for k in items if k not in removed]
            tail.extend(struct.pack('<I', len(items)))
            tail.extend(b''.join(struct.pack('<Q', k) for k in items))
    kept_rows = [r for r in rows if r[0] not in removed]
    tail.extend(struct.pack('<I', len(kept_rows)))
    for key, _, _, typ in kept_rows:
        at, length = positions[key]
        tail.extend(struct.pack('<QQQQ', key, at, length, typ))
    struct.pack_into('<Q', payload, 16, len(payload))
    result = bytes(payload+tail)
    # No retired record bytes remain indexed or deliberately orphaned.
    _, _, _, after = parse_bank(result)
    actual = {struct.unpack_from('<Q', result, r[1])[0] for r in after if r[3] == CAR_TYPE}
    if actual != set(cars)- (ALL_CIDS-active):
        raise ValueError('business active set mismatch')
    return result


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('public source anchor mismatch: ' + old[:70])
    return source.replace(old, new, 1)


def patch_business(source):
    # Source-bound edits prevent login repair of retired records, preserve the
    # canonical save, and send a filtered *copy* at the one profile wire site.
    source = replace_once(source, '        self.state, self.save_path = load_state(self.fed, country, language)',
                          '        self.state, self.save_path = load_state(self.fed, country, language)\n        self._mod_retired_snapshot = profile.mod_prepare_login(self.state)')
    source = replace_once(source, '        w.raw(bytes(self.state))', '        w.raw(profile.mod_client_state(self.state))')
    source = replace_once(source, '    def save(self):\n', '    def save(self):\n        profile.mod_restore_retired(self.state, getattr(self, "_mod_retired_snapshot", profile.mod_retired_snapshot(self.state)))\n')
    source = replace_once(source, "        sl = m['slots'][slot]\n        amount = min(amount, sl['remaining'])",
                          "        sl = m['slots'][slot]\n        if sl['item'][0] in ('bp', 'epic') and not profile.mod_car_allowed(sl['item'][1]):\n            return None\n        amount = min(amount, sl['remaining'])")
    source = replace_once(source, "                if rw['kind'] == gachadb.BLUEPRINTS and rw['id'] in cardb.load() and rw['id'] not in cars:",
                          "                if rw['kind'] == gachadb.BLUEPRINTS and profile.mod_car_allowed(rw['id']) and rw['id'] in cardb.load() and rw['id'] not in cars:")
    # Use AST bounds so unrelated historical garage-value calculations still
    # see retained metadata and progression.
    tree = ast.parse(source)
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in ('on_login', 'fix_blueprint_counts'):
            spans.append((node.lineno, node.end_lineno))
    lines = source.splitlines(True)
    changes = 0
    for start, stop in spans:
        for i in range(start-1, stop):
            if 'profile.car_ids(' in lines[i]:
                lines[i] = lines[i].replace('profile.car_ids(', 'profile.mod_active_car_ids(')
                changes += 1
    if changes != 3:
        raise ValueError('unexpected login car-loop count')
    source = ''.join(lines)
    source += '\n# BEGIN trusted modular core 207\nfrom a9mod_runtime import configure_business as _a9mod_configure_business\n_a9mod_configure_business(globals())\n# END trusted modular core 207\n'
    compile(source, 'business.py', 'exec')
    return source


def compose(public_base, active_cids, *, runtime_source):
    """Return relative public paths -> bytes. Pure; no target or user reads.

    public_base is the pinned all-installed public five-file mapping. Calling
    against a current composed edition is intentionally rejected; the engine
    uses its immutable core base for every enable/disable transaction.
    """
    active = validate_active(active_cids)
    if set(public_base) != set(SOURCE_SHA256):
        raise ValueError('public base whitelist mismatch')
    for path, expected in SOURCE_SHA256.items():
        if type(public_base[path]) is not bytes or sha(public_base[path]) != expected:
            raise ValueError('unsupported public base drift: ' + path)
    # runtime_source is the trusted application-owned module, not mod data.
    if type(runtime_source) is not bytes or sha(runtime_source) != TRUSTED_RUNTIME_SHA256:
        raise ValueError('missing trusted runtime source')
    compile(runtime_source, 'a9mod_runtime.py', 'exec')
    out = {}
    profile = public_base['a9emu/profile.py'].decode('utf-8-sig').replace('\r\n', '\n')
    profile += '\n# BEGIN trusted modular core 207\nfrom a9mod_runtime import configure_profile as _a9mod_configure_profile\n_a9mod_configure_profile(globals(), ' + repr(tuple(sorted(active))) + ')\n# END trusted modular core 207\n'
    compile(profile, 'profile.py', 'exec')
    out['a9emu/profile.py'] = profile.encode('utf-8')
    business = public_base['a9emu/business.py'].decode('utf-8-sig').replace('\r\n', '\n')
    out['a9emu/business.py'] = patch_business(business).encode('utf-8')
    cardb = public_base['a9emu/cardb.py'].decode('utf-8-sig').replace('\r\n', '\n')
    if cardb.count("'A9-business.gdb'") != 2:
        raise ValueError('cardb database source anchor drift')
    cardb = cardb.replace("'A9-business.gdb'", "'A9-mod-retired.gdb'")
    compile(cardb, 'cardb.py', 'exec')
    out['a9emu/cardb.py'] = cardb.encode('utf-8')
    full = public_base['a9emu/gamedata/A9-business.gdb']
    out['a9emu/gamedata/A9-business.gdb'] = filter_business(full, active)
    out['a9emu/gamedata/A9-mod-retired.gdb'] = full
    ids = json.loads(public_base['a9emu/gamedata/car_ids.json'])
    if not isinstance(ids, list) or any(type(c) is not int for c in ids) or len(ids) != len(set(ids)):
        raise ValueError('invalid public car_ids catalog')
    out['a9emu/gamedata/car_ids.json'] = (json.dumps([c for c in ids if c not in ALL_CIDS-active], ensure_ascii=False) + '\n').encode('utf-8')
    out['a9emu/a9mod_runtime.py'] = runtime_source
    return out


def compose_result(public_base, active_cids, *, runtime_source):
    active = validate_active(active_cids)
    relative_files = compose(public_base, active, runtime_source=runtime_source)
    business = relative_files['a9emu/gamedata/A9-business.gdb']
    return dict(schema=SCHEMA, active_cids=sorted(active),
                relative_files=relative_files, main_business_bytes=business,
                main_business_sha256=sha(business),
                retired_metadata_client_published=False,
                official_1003_panel_verified=False)
