"""Pure stock269 + selectedmodule garagefilter, no filesystem/game/save access."""
import struct
import hashlib
FILTER_KEY='00000953c843f2fc';FILTER_TYPE=0x543e051f
GARAGE_KEY='00000a426d5f4daf';GARAGE_TYPE=0x2d70f3dc
GARAGE_REFERENCE_OFFSET=3504;TYPE_DEF=0xa14668db
# Bounded genericbank framing; typedCarDefCID is the authenticatedu64 at+8.
# No nativecalls, filesystem or runtimepaths are partofthis module.
def database(data):
    if type(data)is not bytes or not 32<=len(data)<=64*1024*1024:raise ValueError('Banksize')
    h,start,end=struct.unpack_from('<QQQ',data)
    if start!=24 or not 24<=end<len(data):raise ValueError('Bankheader')
    pos=end
    def take(fmt):
        nonlocal pos
        n=struct.calcsize('<'+fmt)
        if pos+n>len(data):raise ValueError('Truncatedindex')
        v=struct.unpack_from('<'+fmt,data,pos);pos+=n;return v[0]if len(v)==1 else v
    def count():
        n=take('I')
        if n>100000:raise ValueError('Indexcount')
        return n
    groups=[]
    for _ in range(count()):
        key=take('Q');lists=[[f'{take("Q"):016x}'for _ in range(count())]for _ in range(2)]
        groups.append(dict(opaque_key=f'{key:016x}',list0=lists[0],list1=lists[1]))
    rows=[]
    for _ in range(count()):
        key,at,n,typ=take('QQQQ')
        if at<24 or at>end or n>end-at:raise ValueError('Recordextent')
        rows.append(dict(opaque_key=f'{key:016x}',offset_candidate=at,length_candidate=n,opaque_last=f'{typ:016x}'))
    if pos!=len(data):raise ValueError('IndexEOF')
    cursor=24;gaps=overlap=0
    for r in sorted(rows,key=lambda r:r['offset_candidate']):
        at,n=r['offset_candidate'],r['length_candidate'];gaps+=max(0,at-cursor);overlap+=max(0,min(cursor-at,n));cursor=max(cursor,at+n)
    gaps+=end-cursor
    return dict(data=data,index=dict(groups=groups,records=rows),receipt=dict(body_end=end,gaps_in_indexed_body_bytes=gaps,overlapping_indexed_body_bytes=overlap))
def record_body(db,r):return db['data'][r['offset_candidate']:r['offset_candidate']+r['length_candidate']]
def exact_record(db,key,typ):
    rows=[r for r in db['index']['records']if r['opaque_key']==key and int(r['opaque_last'],16)==typ]
    if len(rows)!=1:raise ValueError('Exacttypedrecord')
    return rows[0]
def car_def_prefix(body):
    if len(body)<16:raise ValueError('CarDefprefix')
    cid=struct.unpack_from('<Q',body,8)[0]
    if not 0<cid<2**32:raise ValueError('CarDefCID')
    return dict(numeric_car_id=cid)
def filter_members(raw):
    if len(raw)<5 or raw[0]!=1:raise ValueError('Filteroptional')
    n=struct.unpack_from('<I',raw,1)[0]
    if n>10000 or len(raw)!=5+8*n:raise ValueError('Filtervector')
    keys=[f'{struct.unpack_from("<Q",raw,5+8*i)[0]:016x}'for i in range(n)]
    if len(keys)!=len(set(keys)):raise ValueError('Repeatedfiltermember')
    return keys
def _compact_replace(source,selected,payload):
    db=database(source)
    if db['index']['groups']or db['receipt']['gaps_in_indexed_body_bytes']or db['receipt']['overlapping_indexed_body_bytes']:raise ValueError('Notcompactungroupedfilterbank')
    out=bytearray(source[:24]);positions={}
    for r in sorted(db['index']['records'],key=lambda x:x['offset_candidate']):
        identity=(r['opaque_key'],int(r['opaque_last'],16));b=payload if identity==selected else record_body(db,r)
        if identity in positions:raise ValueError('Ambiguoustypedfilterrow')
        positions[identity]=(len(out),len(b));out.extend(b)
    struct.pack_into('<Q',out,16,len(out));out.extend(struct.pack('<II',0,len(db['index']['records'])))
    for r in db['index']['records']:
        key,typ=r['opaque_key'],int(r['opaque_last'],16);at,n=positions[(key,typ)];out.extend(struct.pack('<QQQQ',int(key,16),at,n,typ))
    result=bytes(out);after=database(result)
    for a,b in zip(db['index']['records'],after['index']['records'],strict=True):
        ident=(a['opaque_key'],int(a['opaque_last'],16))
        if ident!=(b['opaque_key'],int(b['opaque_last'],16))or record_body(after,b)!=(payload if ident==selected else record_body(db,a)):raise ValueError('Filterpreservation')
    return result
MODULE_CIDS={'hidden1003':(1003,),'cn':(5018,5002,5021,5009),'alu':(294,345)}
ORDER=('hidden1003','cn','alu')
def sha(b):return hashlib.sha256(b).hexdigest()
def selected_cids(modules):
    values=tuple(modules)
    if len(values)!=len(set(values)) or any(type(x)is not str or x not in MODULE_CIDS for x in values):
        raise ValueError('Unknown or duplicate vehiclemodule')
    return tuple(cid for name in ORDER if name in values for cid in MODULE_CIDS[name])
def compose_filter(stock_filter,merged_defs,garage,modules,*,expected_stock_filter_sha256):
    """Always derive from a pinned269-entry stockbank, including emptyselection.

    Physicalremoval/stockrestoration ofCarDef rows is ownedbythemaincomposer.
    This function guarantees garagevisibility contains onlystock+active IDs.
    """
    if sha(stock_filter)!=expected_stock_filter_sha256:raise ValueError('Pinnedstockfilter drift')
    selected=selected_cids(modules);db,defs,gd=database(stock_filter),database(merged_defs),database(garage)
    owner=record_body(gd,exact_record(gd,GARAGE_KEY,GARAGE_TYPE));needle=struct.pack('<Q',int(FILTER_KEY,16))
    if len(owner)!=3524 or owner[GARAGE_REFERENCE_OFFSET:GARAGE_REFERENCE_OFFSET+8]!=needle:
        raise ValueError('ExactGARAGEfilterowner changed')
    inbound=[r['opaque_key']for r in gd['index']['records']if needle in record_body(gd,r)]
    if inbound!=[GARAGE_KEY] or owner.count(needle)!=1:raise ValueError('Unexpectedfilterowner')
    original=record_body(db,exact_record(db,FILTER_KEY,FILTER_TYPE));stock=filter_members(original)
    if len(stock)!=269:raise ValueError('Exact269stockrequired')
    bykey={};byid={}
    for r in defs['index']['records']:
        if int(r['opaque_last'],16)!=TYPE_DEF:continue
        i=car_def_prefix(record_body(defs,r));cid=i['numeric_car_id'];key=r['opaque_key']
        if key in bykey or cid in byid:raise ValueError('AmbiguousCarDefUIDorCID')
        bykey[key]=cid;byid[cid]=key
    if any(k not in bykey for k in stock):raise ValueError('Stockfilterunresolved')
    stockids=[bykey[k]for k in stock];allmoduleids={c for v in MODULE_CIDS.values()for c in v}
    if allmoduleids&set(stockids):raise ValueError('ModuleCIDunexpectedlyinthestockvector')
    if not {166,243,181}<=set(stockids):raise ValueError('Originalhostsaremissing')
    if any(cid not in byid for cid in selected):raise ValueError('ActiveCIDhasnoexactCarDef')
    wanted=stock+[byid[cid]for cid in selected]
    payload=original[:1]+struct.pack('<I',len(wanted))+b''.join(struct.pack('<Q',int(k,16))for k in wanted)
    output=stock_filter if not selected else _compact_replace(stock_filter,(FILTER_KEY,FILTER_TYPE),payload)
    check=database(output);actual=filter_members(record_body(check,exact_record(check,FILTER_KEY,FILTER_TYPE)))
    if actual!=wanted:raise ValueError('Filterreadbackdiffers')
    return output,dict(schema='C9_MODULES207_GARAGE_FILTER_V1',stock_filter_sha256=sha(stock_filter),
        output_sha256=sha(output),stock_count=269,active_cids=list(selected),visible_count=len(wanted),
        visible_module_cids=[bykey[k]for k in actual if bykey[k]in allmoduleids],
        original_stock_order_flag_and_other_filter_bodies_exact=True,
        GARAGE_and_CarDef_bytes_unchanged=True,disabled_module_garage_entries_absent=True,
        inactive_CarDef_physical_presence_not_claimed=True,native_visibility_tested=False)
