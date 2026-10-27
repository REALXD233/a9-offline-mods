"""Pure stdlib-only loaderselection/repin helper. NeverloadsDLLorfiles."""
import hashlib
def _hex(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):raise ValueError('CanonicalSHA256required')
    return bytes.fromhex(value)
def effective_mask(*,career,cn):
    if type(career)is not bool or type(cn)is not bool:raise ValueError('Booleanmoduleflagsrequired')
    return int(career)|2*int(cn)
def repin_loader(template,spec,*,mask,main_sha256,gin_sha256):
    """Authenticateonecompiledtemplate thenchangeonlytwo32-byte data constants.

    Specmustcomefromthepinnedmoduleintegrationmanifest. Functionalcode differs
    acrossmasks; thispin-onlytransform appliesonlywithintheselectedtemplate.
    """
    if type(template)is not bytes or type(mask)is not int or mask not in range(4):raise ValueError('Invalidtemplateormask')
    if spec['mask']!=mask or len(template)!=spec['bytes']or hashlib.sha256(template).hexdigest()!=spec['sha256']:raise ValueError('Exactvarianttemplateauthenticationfailed')
    pins=spec['resource_pins'];newvalues={'main':_hex(main_sha256),'gin':_hex(gin_sha256)};out=bytearray(template);ranges=[]
    for name in('main','gin'):
        row=pins[name];at=row['offset'];old=_hex(row['expected'])
        if type(at)is not int or at<0 or at+32>len(template)or template[at:at+32]!=old or template.count(old)!=1:raise ValueError('Templatepinoffset/value/uniquenessdiffers')
        if any(at<z and a<at+32 for a,z in ranges):raise ValueError('Overlappingpins')
        ranges.append((at,at+32));out[at:at+32]=newvalues[name]
    result=bytes(out)
    if any(result.count(v)!=1 for v in newvalues.values()):raise ValueError('Newpinsnotunique')
    allowed={i for a,z in ranges for i in range(a,z)}
    if any(a!=b and i not in allowed for i,(a,b)in enumerate(zip(template,result,strict=True))):raise ValueError('Outofscopebinarymutation')
    return result,dict(schema='C9_MODULES207_SELECTED_TEMPLATE_REPIN_V1',mask=mask,
        template_sha256=spec['sha256'],output_sha256=hashlib.sha256(result).hexdigest(),
        bytes=len(result),only_main_and_GIN_data_constants_changed=True,
        selected_template_machine_code_unchanged=True,cross_variant_machine_code_equivalence_claimed=False)
