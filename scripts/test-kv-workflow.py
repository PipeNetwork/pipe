#!/usr/bin/env python3
"""Actual CLI against the inert production TLS router/node/executor fixture.
No production endpoints or credit; all resource and key material is disposable.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
BINARY=Path(os.environ.get('PIPE_CLI_TEST_BINARY',ROOT/'target/debug/pipe'))
FIXTURE=Path(os.environ['PIPE_KV_FIXTURE'])

def main():
    binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='pipe-cli-kv-') as directory:
        d=Path(directory)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(d/'key.pem'),'-out',str(d/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        env={**os.environ,'PIPE_DISABLE_KEYRING':'1','PIPE_CLI_SECRET_PASSWORD':'disposable-kv-fixture-password','PIPE_CLI_STATE_DIR':str(d/'state')}
        for name in ['PIPE_CLI_TOKEN','PIPE_CONTROL_API_URL','PIPE_KV_CA_CERT','PIPE_KV_CREDENTIAL']:env.pop(name,None)
        def run(*args,status=0,jsonl=False):
            p=subprocess.run([str(BINARY),'--config',str(d/'config.json'),'--output','jsonl' if jsonl else 'json','--no-input','--yes',*map(str,args)],env=env,capture_output=True,text=True,timeout=30)
            assert p.returncode==status,(args,p.returncode,p.stderr)
            rows=[json.loads(row) for row in p.stdout.splitlines()] if jsonl else [json.loads(p.stdout)]
            assert all(row['schema_version']==1 for row in rows)
            assert info['secret'] not in p.stdout and info['secret'] not in p.stderr
            return [row['result'] for row in rows] if jsonl else rows[0]['result']
        with (d/'router.log').open('w') as log:
            fixture=subprocess.Popen([str(FIXTURE),str(d)],stdout=subprocess.PIPE,stderr=log,text=True)
            try:
                assert select.select([fixture.stdout],[],[],30)[0],'fixture startup timeout'
                info=json.loads(fixture.stdout.readline())
                secret=d/'secret';secret.write_text(info['secret']);secret.chmod(0o600)
                endpoint=f"rediss://localhost:{info['port']}"
                run('kv','credentials','import',info['credential'],'--secret-file',secret,'--endpoint',endpoint)
                assert run('kv','connection',info['credential'])['permissions'] is None
                opts=['--credential',info['credential'],'--ca-cert',d/'cert.pem']
                key=base64.b64encode(b'\x00key\xff\r\n').decode();payload=b'\x00value\xff\r\n'
                value=d/'value';value.write_bytes(payload)
                assert run('kv','set',key,'--base64-keys','--value-file',value,'--nx','--px','60000',*opts)['reply']=={'status':'OK'}
                assert run('kv','set',key,'--base64-keys','--value','wrong','--nx',*opts)['reply'] is None
                assert run('kv','get',key,'--base64-keys',*opts)['reply']['base64']==base64.b64encode(payload).decode()
                dest=d/'download';run('kv','get',key,'--base64-keys','--destination',dest,*opts);assert dest.read_bytes()==payload
                r=run('kv','mget',key,base64.b64encode(b'missing').decode(),key,'--base64-keys',*opts)['reply'];assert r[0]==r[2] and r[1] is None
                assert run('kv','exists',key,key,'--base64-keys',*opts)['reply']['integer']=='2'
                assert int(run('kv','ttl',key,'--base64-keys','--milliseconds',*opts)['reply']['integer'])>0
                assert run('kv','persist',key,'--base64-keys',*opts)['reply']['integer']=='1'
                assert run('kv','ttl',key,'--base64-keys',*opts)['reply']['integer']=='-1'
                run('kv','set','counter','--value','9007199254740992',*opts)
                assert run('kv','incr','counter',*opts)['reply']['integer']=='9007199254740993'
                assert run('kv','decr','counter','--by','2',*opts)['reply']['integer']=='9007199254740991'
                run('kv','set','max','--value','9223372036854775807',*opts)
                assert run('kv','incr','max',*opts,status=1)['error']['code']=='kv_rejected'
                assert base64.b64decode(run('kv','get','max',*opts)['reply']['base64'])==b'9223372036854775807'
                for n in range(4):run('kv','set',f'scan:{n}','--value','v',*opts)
                pages=run('kv','scan','--pattern','scan:*','--count','2','--all',*opts,jsonl=True)
                assert pages[-1]['complete']
                assert {base64.b64decode(k['base64']) for p in pages for k in p['keys']}=={f'scan:{n}'.encode() for n in range(4)}
                run('kv','expire',key,'0','--base64-keys',*opts)
                assert run('kv','get',key,'--base64-keys',*opts)['reply'] is None
                assert run('kv','delete','counter','counter',*opts)['reply']['integer']=='1'
                # No CA and a trusted certificate for the wrong DNS name both fail.
                assert run('kv','get','max','--credential',info['credential'],status=7)['error']['code']=='transport'
                import uuid
                wrong=str(uuid.uuid4());run('kv','credentials','import',wrong,'--secret-file',secret,'--endpoint',f"rediss://127.0.0.1:{info['port']}")
                assert run('kv','get','max','--credential',wrong,'--ca-cert',d/'cert.pem',status=7)['error']['code']=='transport'
                # A real TLS peer consumes the mutation, then closes without a reply.
                listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(10)
                losses=[];errors=[]
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(d/'cert.pem',d/'key.pem')
                def consume():
                    try:
                        sock,_=listener.accept()
                        with ctx.wrap_socket(sock,server_side=True) as stream:
                            stream.settimeout(10);reader=stream.makefile('rb')
                            def frame():
                                line=reader.readline();assert line.startswith(b'*');out=[]
                                for _ in range(int(line[1:])):
                                    line=reader.readline();assert line.startswith(b'$');n=int(line[1:]);out.append(reader.read(n));assert reader.read(2)==b'\r\n'
                                return out
                            assert frame()[0]==b'AUTH';stream.sendall(b'+OK\r\n');losses.append(frame());reader.close()
                        listener.settimeout(1)
                        try:extra,_=listener.accept();extra.close();raise AssertionError('mutation reconnected')
                        except socket.timeout:pass
                    except Exception as e:errors.append(e)
                    finally:listener.close()
                t=threading.Thread(target=consume);t.start()
                lost=str(uuid.uuid4());run('kv','credentials','import',lost,'--secret-file',secret,'--endpoint',f'rediss://localhost:{listener.getsockname()[1]}')
                loss_opts=['--credential',lost,'--ca-cert',d/'cert.pem']
                result=run('kv','incr','uncertain',*loss_opts,status=8);assert result['error']['code']=='unknown_outcome'
                t.join(12);assert not t.is_alive() and not errors and losses==[[b'INCRBY',b'uncertain',b'1']],errors
                records=run('kv','requests');pending=[(i,r) for i,r in records.items() if r['state']=='unknown'];assert len(pending)==1
                assert run('kv','incr','uncertain',*loss_opts,status=1)['error']['code']=='command_failed'
                run('kv','acknowledge',pending[0][0]);assert run('kv','requests')[pending[0][0]]['state']=='acknowledged_unknown'
                # Scope changes take effect after existing signed authority expires.
                urllib.request.urlopen(urllib.request.Request(f"http://{info['control']}/read-only",data=b'',method='POST'),timeout=5).close()
                time.sleep(6)
                assert run('kv','incr','max',*opts,status=4)['error']['code']=='authorization'
                assert run('kv','get','max',*opts)['reply'] is not None
                # Revocation is observed through signed, expiring router authority.
                urllib.request.urlopen(urllib.request.Request(f"http://{info['control']}/revoke",data=b'',method='POST'),timeout=5).close()
                time.sleep(6)
                assert run('kv','get','max',*opts,status=3)['error']['code']=='authentication'
                secret_file=(d/'state'/'secrets.json').read_bytes();assert secret_file.startswith(b'PIPESEC3') and info['secret'].encode() not in secret_file
                print(json.dumps({'passed':True,'binary_sha256':binary_sha256,'fixture':'production TLS router + node executor, disposable authority','binary_values':True,'tls_name_and_trust':True,'scope_and_revocation':True,'unknown_mutation_forwarded_once':len(losses),'production_spent_atoms':0,'production_reserved_atoms':0}))
            finally:
                fixture.terminate()
                try:fixture.wait(timeout=10)
                except subprocess.TimeoutExpired:fixture.kill();fixture.wait()
if __name__=='__main__':main()
