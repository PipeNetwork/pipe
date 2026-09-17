#!/usr/bin/env python3
"""Create deterministic release archives from an already-tested native binary."""
import argparse,gzip,hashlib,io,json,platform,re,subprocess,tarfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TARGETS={'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-apple-darwin','aarch64-apple-darwin','x86_64-pc-windows-msvc'}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',choices=sorted(TARGETS),required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--development-snapshot',action='store_true',help='Label a local uncommitted fixture; never qualifies a release');a=p.parse_args()
    manifest=json.loads(subprocess.check_output(['cargo','metadata','--locked','--no-deps','--format-version','1'],cwd=ROOT))
    version=next(x['version'] for x in manifest['packages'] if x['name']=='pipe')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?',version):raise SystemExit('Invalid release version')
    if not re.fullmatch(r'[a-f0-9]{40}',a.source):raise SystemExit('Full source commit required')
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()!=a.source:raise SystemExit('Source commit differs from the checkout')
    dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True))
    if dirty and not a.development_snapshot:raise SystemExit('Release packaging requires a committed clean source tree')
    a.output.mkdir(parents=True,exist_ok=True)
    name=f'pipe-v{version}-{a.target}';windows=a.target.endswith('windows-msvc');binary='pipe.exe' if windows else 'pipe'
    files={binary:a.binary.read_bytes(),'README.md':(ROOT/'README.md').read_bytes(),'CRYPTO_FORMAT.md':(ROOT/'CRYPTO_FORMAT.md').read_bytes(),'LICENSE':(ROOT/'LICENSE').read_bytes()}
    record={'format_version':1,'version':version,'source_commit':a.source,'source_status':'development-uncommitted' if dirty else 'committed','target':a.target,'binary_sha256':sha(a.binary),'contract_index_sha256':sha(ROOT/'contracts/platform-draft/index.json'),'contract_sha256':sha(ROOT/'contracts/platform-draft/control-plane.json'),'lockfile_sha256':sha(ROOT/'Cargo.lock')}
    record['tested_build_os']=platform.platform()
    record['rustc']=subprocess.check_output(['rustc','--version'],text=True).strip()
    files['release.json']=(json.dumps(record,indent=2,sort_keys=True)+'\n').encode()
    destination=a.output/(name+('.zip' if windows else '.tar.gz'))
    if destination.exists():raise SystemExit('Refusing to replace an immutable archive')
    if windows:
        with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            for path,data in sorted(files.items()):
                info=zipfile.ZipInfo(path,(1980,1,1,0,0,0));info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,data)
    else:
        with destination.open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w') as archive:
            for path,data in sorted(files.items()):
                info=tarfile.TarInfo(path);info.size=len(data);info.mode=0o755 if path==binary else 0o644;info.mtime=0;info.uid=info.gid=0;archive.addfile(info,io.BytesIO(data))
    (a.output/(name+'.sha256')).write_text(f'{sha(destination)}  {destination.name}\n')
    print(json.dumps({**record,'archive':destination.name,'archive_sha256':sha(destination)}))
if __name__=='__main__':main()
