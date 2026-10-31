"""Bounded proof codec.

Decoding REQUIRES the expected shape from trusted verifier parameters. The
shape_from_dump helper is for public benchmark fixtures only, not network input.
Native centered fields are restored before the native transcript is evaluated.
"""
import hashlib
import struct

Q=274877906837
D=256
MAGIC=b'QPF6\x00\x00\x00\x00'
MAX_BYTES=1<<20


def require(condition,message):
    if not condition:raise ValueError(message)


def integer(value,low,high):
    require(type(value) is int and low<=value<=high,'integer outside codec bounds')
    return value


def shape_from_dump(proof):
    require(proof['format']=='quil-unverified-native-proof-fixture-v4' and proof['degree']==D and proof['modulus']==Q,'wrong proof domain')
    rounds=[]
    for item in proof['rounds']:
        rounds.append(None if item is None else {'kind':item['kind'],'inner':item['tail_inner_commitments'],'messages':[len(group) for group in item['messages']]})
    shape={'rounds':rounds,'zk_round':proof['zk_round'],'dch':len(proof['dch_commitment']),
           'lnp':[len(group) for group in proof['lnp_messages']],
           'witness':[len(group) for group in proof['final_witness']]}
    require(proof['pack_round_count']==len(rounds),'round count mismatch')
    describe(shape)
    return shape


def describe(shape):
    rounds=shape['rounds']
    require(type(rounds) is list and 1<=len(rounds)<=64,'bad round count')
    zk=integer(shape['zk_round'],0,len(rounds)-1)
    require(rounds[zk] is None and sum(r is None for r in rounds)==1,'bad ZK round')
    descriptor=bytearray(struct.pack('<III',len(rounds),zk,integer(shape['dch'],0,1024)))
    polynomials=shape['dch'];projections=0
    tags={'compressed':1,'uncompressed':2,'tail':3}
    for item in rounds:
        if item is None:descriptor+=bytes(21);continue
        require(item['kind'] in tags and len(item['messages'])==4,'bad round shape')
        counts=[integer(n,0,1024) for n in item['messages']]
        inner=integer(item['inner'],0,counts[0])
        require(item['kind']=='tail' or inner==0,'inner split outside tail')
        require(item['kind']=='compressed' or counts[1]==0,'unexpected second message')
        descriptor+=struct.pack('<B5I',tags[item['kind']],inner,*counts)
        polynomials+=sum(counts)
        projections+=item['kind']!='compressed'
    require(len(shape['lnp'])==5,'bad LNP shape')
    lnp=[integer(n,1,1024) for n in shape['lnp']]
    require(lnp[2]==1 and lnp[0]==lnp[1]==lnp[3]==lnp[4],'bad LNP message ranks')
    descriptor+=struct.pack('<5I',*lnp);polynomials+=sum(lnp)
    require(1<=len(shape['witness'])<=16,'bad final witness count')
    witness=[integer(n,1,2048) for n in shape['witness']]
    descriptor+=struct.pack('<I',len(witness))+struct.pack('<'+'I'*len(witness),*witness)
    size=40+polynomials*1216+projections*1024+sum(witness)*512
    require(size<MAX_BYTES,'proof alone exceeds strict 1 MiB ceiling')
    return bytes(descriptor),size


def header(shape):
    descriptor,size=describe(shape)
    return MAGIC+hashlib.shake_256(b'quil/proof-shape/v1\x00'+descriptor).digest(32),size


def encode(proof,shape):
    require(shape_from_dump(proof)==shape,'proof shape differs from verifier parameters')
    prefix,size=header(shape);output=bytearray(prefix)
    def polys(group,count,center_start=None):
        require(len(group)==count,'polynomial count mismatch')
        for i,poly in enumerate(group):
            require(len(poly)==D,'polynomial degree mismatch')
            centered=center_start is not None and i>=center_start
            value=0
            for j,x in enumerate(poly):
                integer(x,-(Q//2) if centered else 0,Q//2 if centered else Q-1)
                value|=(x%Q)<<(38*j)
            output.extend(value.to_bytes(1216,'little'))
    polys(proof['dch_commitment'],shape['dch'])
    for item,layout in zip(proof['rounds'],shape['rounds']):
        if layout is None:continue
        for j,group in enumerate(item['messages']):
            center=layout['inner'] if layout['kind']=='tail' and j==0 else None
            polys(group,layout['messages'][j],center)
        if layout['kind']=='compressed':require(item['projection'] is None,'unexpected projection')
        else:
            require(len(item['projection'])==D,'projection dimension mismatch')
            output.extend(struct.pack('<256i',*(integer(x,-(1<<31),(1<<31)-1) for x in item['projection'])))
    for j,group in enumerate(proof['lnp_messages']):polys(group,shape['lnp'][j],0 if j==2 else None)
    for group,count in zip(proof['final_witness'],shape['witness']):
        require(len(group)==count,'witness count mismatch')
        for poly in group:
            require(len(poly)==D,'witness degree mismatch')
            output.extend(struct.pack('<256h',*(integer(x,-32768,32767) for x in poly)))
    require(len(output)==size,'encoded size mismatch')
    return bytes(output)


def decode(encoded,shape):
    prefix,size=header(shape)
    require(len(encoded)==size and encoded[:40]==prefix,'length, version or parameter-shape mismatch')
    offset=40
    def polys(count,center_start=None):
        nonlocal offset
        group=[]
        for i in range(count):
            value=int.from_bytes(encoded[offset:offset+1216],'little');offset+=1216
            centered=center_start is not None and i>=center_start
            poly=[]
            for _ in range(D):
                x=value&((1<<38)-1);value>>=38
                require(x<Q,'noncanonical residue')
                poly.append(x-Q if centered and x>Q//2 else x)
            group.append(poly)
        return group
    proof={'format':'quil-unverified-native-proof-fixture-v4','degree':D,'modulus':Q,
           'pack_round_count':len(shape['rounds']),'zk_round':shape['zk_round']}
    proof['dch_commitment']=polys(shape['dch']);rounds=[]
    for layout in shape['rounds']:
        if layout is None:rounds.append(None);continue
        messages=[]
        for j,count in enumerate(layout['messages']):messages.append(polys(count,layout['inner'] if layout['kind']=='tail' and j==0 else None))
        projection=None
        if layout['kind']!='compressed':projection=list(struct.unpack_from('<256i',encoded,offset));offset+=1024
        rounds.append({'kind':layout['kind'],'tail_inner_commitments':layout['inner'],'messages':messages,'projection':projection})
    proof['rounds']=rounds;proof['lnp_messages']=[polys(n,0 if j==2 else None) for j,n in enumerate(shape['lnp'])]
    witness=[]
    for count in shape['witness']:
        group=[]
        for _ in range(count):group.append(list(struct.unpack_from('<256h',encoded,offset)));offset+=512
        witness.append(group)
    proof['final_witness']=witness
    require(offset==len(encoded),'unconsumed proof bytes')
    return proof
