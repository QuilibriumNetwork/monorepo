"""Codec semantics and malformed input tests; mock data is not a valid proof."""
import argparse
import copy
import json
from pathlib import Path
from proof_codec import Q,encode,decode,shape_from_dump,header


def rejected(function):
    try:function()
    except ValueError:return
    raise AssertionError('invalid input accepted')


def canonical_mock(proof):
    proof=copy.deepcopy(proof)
    # Construct a codec-only mock with each message in its declared domain.
    groups=[proof['dch_commitment']]
    for item in proof['rounds']:
        if item is None:continue
        for j,group in enumerate(item['messages']):
            if item['kind']=='tail' and j==0:groups.append(group[:item['tail_inner_commitments']])
            else:groups.append(group)
    groups.extend(proof['lnp_messages'][j] for j in [0,1,3,4])
    for group in groups:
        for poly in group:
            for i,value in enumerate(poly):poly[i]=value%Q
    return proof


def mock_fixture():
    def poly(): return [0]*256
    first=poly();first[0]=13;first[-1]=Q-1
    return {'format':'quil-unverified-native-proof-fixture-v4','degree':256,'modulus':Q,
            'pack_round_count':2,'zk_round':0,'dch_commitment':[first],
            'rounds':[None,{'kind':'tail','tail_inner_commitments':1,
                           'messages':[[poly()],[],[poly()],[poly()]],'projection':[0]*256}],
            'lnp_messages':[[poly()] for _ in range(5)],'final_witness':[[poly()]]}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mock',type=Path,nargs='?')
    args=parser.parse_args();proof=json.loads(args.mock.read_text()) if args.mock else mock_fixture()
    proof=canonical_mock(proof)
    old=copy.deepcopy(proof);old['format']='quil-unverified-native-proof-fixture-v1'
    rejected(lambda:shape_from_dump(old))
    shape=shape_from_dump(proof)
    encoded=encode(proof,shape)
    assert decode(encoded,shape)==proof
    assert encode(decode(encoded,shape),shape)==encoded
    # Independent integer expression for the first coefficient block.
    expected=(13+((Q-1)<<(38*255))).to_bytes(1216,'little')
    assert encoded[40:1256]==expected
    for invalid in [encoded[:-1],encoded+b'\x00',b'BAD!'+encoded[4:],b'QPF1'+encoded[4:],b'QPF2'+encoded[4:],b'QPF3'+encoded[4:]]:
        rejected(lambda:decode(invalid,shape))
    malformed=bytearray(encoded)
    block=int.from_bytes(malformed[40:1256],'little')
    block=(block>>38<<38)|Q
    malformed[40:1256]=block.to_bytes(1216,'little')
    rejected(lambda:decode(malformed,shape))
    wrong_shape=copy.deepcopy(shape);wrong_shape['dch']+=1
    rejected(lambda:decode(encoded,wrong_shape))
    too_large=copy.deepcopy(shape);too_large['witness']=[2048]*16
    rejected(lambda:header(too_large))
    for invalid_value in [-1,Q,True]:
        bad=copy.deepcopy(proof);bad['dch_commitment'][0][0]=invalid_value
        rejected(lambda:encode(bad,shape))
    bad=copy.deepcopy(proof);bad['lnp_messages'][2][0][0]=Q//2+1
    rejected(lambda:encode(bad,shape))
    print(json.dumps({'scope':'mock codec roundtrip and malformed-input checks; no proof verification',
                      'roundtrip':'passed','canonical_residue_checks':'passed','signed_message_restoration':'passed',
                      'length_version_shape_and_size_guards':'passed','mock_encoded_bytes':len(encoded)}))


if __name__=='__main__':main()
