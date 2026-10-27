"""Pure native shared lookup-table check; does not recalculate stock keys.

Retained136 native parser evidence inserts field0 unconditionally and nonzero
field1 into the same key -> resource-index map. Repetition in the SAME entry is
unambiguous. A key naming two DISTINCT entries is rejected, even if their stored
bytes happen to match. Zero field1 is the authenticated absent-alias marker.
"""
def verify_native_aliases(entries):
    if not isinstance(entries,(list,tuple)) or len(entries)>100000:
        raise ValueError('Manifest entry count outside bounded contract')
    lookup={};repeated=0;secondary=0
    for index,entry in enumerate(entries):
        for field in ('field0','field1'):
            value=getattr(entry,field,None)
            if type(value) is not int or not 0<=value<2**64:
                raise ValueError('Manifest key must be uint64: '+field)
            if field=='field1' and value==0:
                continue
            secondary+=field=='field1'
            if value in lookup:
                old=lookup[value]
                if old!=index:
                    raise ValueError('Native lookup key collision: %016x maps entries %d and %d'%(value,old,index))
                repeated+=1
            else:
                lookup[value]=index
    return dict(entries=len(entries),field0_insertions=len(entries),nonzero_field1_insertions=secondary,
                unique_lookup_keys=len(lookup),same_entry_repeated_keys=repeated,
                distinct_entry_collisions=0)
