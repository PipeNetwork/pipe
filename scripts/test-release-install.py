#!/usr/bin/env python3
"""Exercise local binary installation, checksum refusal, upgrade and rollback."""
import argparse,gzip,hashlib,io,json,os,platform,subprocess,tarfile,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);a=parser.parse_args();input_binary=a.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='pipe installer with spaces ') as temp:
        temp=Path(temp);prefix=temp/'install';windows=os.name=='nt';name='pipe.exe' if windows else 'pipe';archive=temp/('release.zip' if windows else 'release.tar.gz');binary=temp/('qualified-'+name);binary.write_bytes(input_binary.read_bytes());binary.chmod(0o755);version=subprocess.check_output([str(binary),'--version'],text=True).strip().removeprefix('pipe ')
        if windows:
            with zipfile.ZipFile(archive,'w') as z:z.write(binary,name)
        else:
            with tarfile.open(archive,'w:gz') as tar:tar.add(binary,arcname=name,recursive=False)
        # The predecessor is another working executable whose bytes differ; rollback checks exact bytes.
        predecessor=binary.read_bytes()+b'\nPIPE_INSTALLER_PREDECESSOR_FIXTURE\n';(prefix/'bin').mkdir(parents=True);destination=prefix/'bin'/name;destination.write_bytes(predecessor);destination.chmod(0o755)
        config=temp/'preserved-state';config.mkdir();sentinel=config/'unresolved-payment-journal';sentinel.write_bytes(b'unchanged signed payment recovery record')
        env={**os.environ,'PIPE_CLI_STATE_DIR':str(config)}
        def run(*args,success=True):
            command=['pwsh','-NoProfile','-File',str(ROOT/'install.ps1'),'-Prefix',str(prefix)] if windows else ['bash',str(ROOT/'install.sh'),'--prefix',str(prefix)]
            result=subprocess.run(command+list(args),env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            if (result.returncode==0)!=success:raise AssertionError(result.stdout+result.stderr)
        options=['-Version',version,'-Archive',str(archive),'-Sha256'] if windows else ['--version',version,'--archive',str(archive),'--sha256']
        run(*options,'0'*64,success=False);assert destination.read_bytes()==predecessor
        run(*options,sha(archive));assert sha(destination)==sha(binary)
        run('-Rollback' if windows else '--rollback');assert destination.read_bytes()==predecessor
        run('-Rollback' if windows else '--rollback');assert sha(destination)==sha(binary)
        assert sentinel.read_bytes()==b'unchanged signed payment recovery record'
        # Tampering with the recorded predecessor cannot install altered bytes.
        backup=prefix/('installer' if windows else 'share/pipe-installer')/'backups'/hashlib.sha256(predecessor).hexdigest();backup.write_bytes(b'tampered')
        run('-Rollback' if windows else '--rollback',success=False);assert sha(destination)==sha(binary)
        print(json.dumps({'platform':platform.system(),'checks':['checksum refusal','install over existing binary','exact upgrade/rollback','tampered rollback refusal','paths with spaces','state retained'],'passed':True}))
if __name__=='__main__':main()
