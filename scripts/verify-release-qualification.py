#!/usr/bin/env python3
"""Check candidate publication or stable promotion against matching evidence."""
import argparse,hashlib,json,os,re,subprocess,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
# User-authorized test-credit ceiling, September 17, 2026. Older $10 records
# retain their lower bound; this does not rewrite an existing qualification.
AUTHORIZED_CANARY_MAX_ATOMS=100_000_000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tree_sha():
    names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    result=hashlib.sha256()
    for name in sorted(set(names)):
        if not name or name=='docs/release/qualification.json' or name.startswith('docs/release/evidence/'):continue
        path=ROOT/name
        if not path.is_file():continue
        result.update(name.encode()+b'\0'+sha(path).encode()+b'\0')
    return result.hexdigest()
def verify(stage):
    record=json.loads((ROOT/'docs/release/qualification.json').read_text())
    assert record['format_version']==1
    allowed={'production-qualified'} if stage=='stable' else {'staging-qualified-production-pending','production-qualified'}
    assert record['status'] in allowed,'qualification stage is incomplete'
    version=tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
    assert record['version']==version,'release version changed after qualification'
    if os.environ.get('GITHUB_REF','').startswith('refs/tags/'):
        assert os.environ['GITHUB_REF']=='refs/tags/v'+version,'release tag and tested package version differ'
    if stage=='candidate':
        assert re.fullmatch(r'3\.\d+\.\d+-rc\.\d+',version),'candidate publication requires an explicit RC version'
        assert record.get('production_pending') is (record['status']!='production-qualified'),'production acceptance state must be explicit'
    else:
        assert record.get('production_pending') is False,'production acceptance is still pending'
    assert record['cli_source_tree_sha256']==tree_sha(),'source changed after qualification'
    assert record['contracts']['published'] is True,'matching immutable contracts must be published before the RC'
    assert record['contracts']['control_plane_sha256']==sha(ROOT/'contracts/platform-draft/control-plane.json')
    assert re.fullmatch('[a-f0-9]{40}',record['backend']['source_commit'])
    assert re.fullmatch('[a-f0-9]{64}',record['backend']['binary_sha256'])
    assert record['backend']['deployed'] is True,'compatible backend support must precede publication'
    qualification=record['qualification']
    assert qualification['staging_passed'] is True
    assert isinstance(qualification['intentionally_unavailable'],list)
    canary=record['canary']
    assert all(type(canary[field]) is int for field in ('maximum_atoms','spent_atoms','reserved_atoms')),'canary accounting requires exact integer atoms'
    assert 0<canary['maximum_atoms']<=AUTHORIZED_CANARY_MAX_ATOMS,'canary ceiling exceeds the authorized test-credit limit'
    assert 0<=canary['spent_atoms']<=canary['maximum_atoms']
    assert 0<=canary['reserved_atoms']<=canary['maximum_atoms']-canary['spent_atoms']
    assert re.fullmatch('[a-f0-9]{64}',record['canary']['ledger_sha256'])
    if stage=='stable':
        assert qualification['real_browser_login'] is True and qualification['cleanup_complete'] is True
        assert qualification['enabled_workflows_passed']
        assert record['canary']['reserved_atoms']==0,'outstanding canary reservations remain'
    assert len(record['evidence'])>=(3 if stage=='stable' else 2),'include qualification and publication evidence'
    for item in record['evidence']:
        path=(ROOT/item['path']).resolve()
        assert path.is_relative_to((ROOT/'docs/release/evidence').resolve())
        assert path.is_file() and sha(path)==item['sha256'],'qualification evidence changed'
    subprocess.run(['python3' if os.name!='nt' else 'python','scripts/cli-coverage.py','--release'],cwd=ROOT,check=True)
    print(json.dumps({'publication_gate':'passed','stage':stage,'production_pending':record['production_pending'],'qualified_tree_sha256':tree_sha()}))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-tree-sha256',action='store_true');p.add_argument('--stage',choices=['candidate','stable'],default='stable');a=p.parse_args()
    if a.source_tree_sha256:print(tree_sha());return
    try:verify(a.stage)
    except (OSError,ValueError,KeyError,AssertionError) as error:raise SystemExit('Release is not qualified: '+str(error))
if __name__=='__main__':main()
