#!/usr/bin/env python3
"""Persistent CLI 3 production qualification budget. This never funds or pays accounts."""
import argparse,fcntl,json,os,pathlib,tempfile
MAX_ATOMS=10_000_000  # USDC atomic units, including unresolved reservations.
STATE=pathlib.Path.home()/'.local/state/pipe/cli3-canary-budget.json'

def update(path,action,operation=None,atoms=None):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 with open(str(path)+'.lock','a') as lock:
  os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX)
  data=json.loads(path.read_text()) if path.exists() else {'version':1,'maximum_atoms':MAX_ATOMS,'operations':{}}
  if data['version']!=1 or data['maximum_atoms']!=MAX_ATOMS:raise ValueError('unsupported or changed budget')
  records=data['operations']
  def exposure():return sum(v['actual_atoms'] if v['state']=='settled' else v['maximum_atoms'] for v in records.values())
  if action=='reserve':
   if type(atoms)!=int or atoms<0:raise ValueError('maximum exposure must be nonnegative integer atoms')
   if not operation or operation in records:raise ValueError('operation already recorded; reconcile it instead of reserving again')
   if exposure()+atoms>MAX_ATOMS:raise ValueError('operation cannot fit within the persistent $10 budget')
   records[operation]={'state':'reserved','maximum_atoms':atoms}
  elif action=='settle':
   if operation not in records or type(atoms)!=int or atoms<0:raise ValueError('known reservation and exact nonnegative settlement required')
   old=records[operation]
   if old['state']=='settled' and old['actual_atoms']!=atoms:raise ValueError('settlement cannot be rewritten')
   records[operation]={**old,'state':'settled','actual_atoms':atoms}
  elif action!='status':raise ValueError('unsupported action')
  data['exposure_atoms']=exposure();data['remaining_atoms']=max(0,MAX_ATOMS-exposure())
  fd,name=tempfile.mkstemp(dir=path.parent,prefix='.canary-')
  try:
   with os.fdopen(fd,'w') as out:json.dump(data,out,indent=2,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
   os.replace(name,path)
   directory=os.open(path.parent,os.O_RDONLY);os.fsync(directory);os.close(directory)
  finally:
   if os.path.exists(name):os.unlink(name)
  return data

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('action',choices=['status','reserve','settle']);parser.add_argument('operation',nargs='?');parser.add_argument('atoms',type=int,nargs='?')
 args=parser.parse_args()
 print(json.dumps(update(STATE,args.action,args.operation,args.atoms),indent=2))
