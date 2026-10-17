"""Cross-check the independent native decoder against Python-encoded mock data."""
import argparse
import json
from pathlib import Path
import subprocess
from proof_codec import Q,encode,shape_from_dump
from test_proof_codec import canonical_mock


def check(out):
    original=json.loads((out/'mock-proof.json').read_text())
    expected=canonical_mock(original)
    encoded=encode(expected,shape_from_dump(expected))
    def run(data,name,status):
        path=out/(name+'.qpf');path.write_bytes(data)
        result=subprocess.run([str(out/'probe_proof_dump'),str(out/'mock-proof.json'),str(path),str(out/(name+'-decoded.json'))])
        assert result.returncode==status
    run(encoded,'native-codec-valid',0)
    assert json.loads((out/'native-codec-valid-decoded.json').read_text())==expected
    bad=bytearray(encoded);word=int.from_bytes(bad[40:1256],'little');word=(word>>38<<38)|Q;bad[40:1256]=word.to_bytes(1216,'little')
    for name,data in [('residue',bad),('truncated',encoded[:-1]),('trailing',encoded+b'\x00'),('header',b'X'+encoded[1:]),('retired-version',b'QPF1'+encoded[4:]),('retired-qpf2',b'QPF2'+encoded[4:]),('retired-qpf3',b'QPF3'+encoded[4:])]:run(data,'native-codec-'+name,2)
    return {'scope':'mock cross-language codec; not native proof verification',
            'all_decoded_fields_match_python':True,'noncanonical_truncated_trailing_wrong_header':'rejected','encoded_bytes':len(encoded)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    print(json.dumps(check(parser.parse_args().out.resolve())))
