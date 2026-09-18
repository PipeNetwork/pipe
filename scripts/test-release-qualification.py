#!/usr/bin/env python3
"""RC publication may precede paid acceptance; stable promotion must not."""
import contextlib,hashlib,importlib.util,io,json,os,subprocess,tempfile,unittest
from pathlib import Path
SPEC=importlib.util.spec_from_file_location('qualification',Path(__file__).with_name('verify-release-qualification.py'));Q=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(Q)
class Qualification(unittest.TestCase):
 def setUp(self):
  self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name);self.old_root=Q.ROOT;Q.ROOT=self.root;self.addCleanup(setattr,Q,'ROOT',self.old_root)
  self.prior_ref=os.environ.pop('GITHUB_REF',None)
  self.addCleanup(lambda:os.environ.pop('GITHUB_REF',None) if self.prior_ref is None else os.environ.__setitem__('GITHUB_REF',self.prior_ref))
  subprocess.run(['git','init','-q'],cwd=self.root,check=True)
  (self.root/'Cargo.toml').write_text('[package]\nversion = "3.0.0-rc.1"\n');(self.root/'contracts/platform-draft').mkdir(parents=True);(self.root/'contracts/platform-draft/control-plane.json').write_text('{}');(self.root/'scripts').mkdir();(self.root/'scripts/cli-coverage.py').write_text('print("fixture coverage complete")\n')
  evidence=self.root/'docs/release/evidence';evidence.mkdir(parents=True)
  for name in ['staging.json','contracts.json','production.json']:(evidence/name).write_text('{}')
  self.record={'format_version':1,'version':'3.0.0-rc.1','status':'staging-qualified-production-pending','production_pending':True,'cli_source_tree_sha256':Q.tree_sha(),'contracts':{'published':True,'control_plane_sha256':Q.sha(self.root/'contracts/platform-draft/control-plane.json')},'backend':{'source_commit':'a'*40,'binary_sha256':'b'*64,'deployed':True},'qualification':{'staging_passed':True,'intentionally_unavailable':['kv'],'real_browser_login':False,'cleanup_complete':False,'enabled_workflows_passed':[]},'canary':{'maximum_atoms':10_000_000,'spent_atoms':0,'reserved_atoms':0,'ledger_sha256':'c'*64},'evidence':[{'path':'docs/release/evidence/'+name,'sha256':Q.sha(evidence/name)} for name in ['staging.json','contracts.json','production.json']]}
 def verify(self,stage):
  (self.root/'docs/release/qualification.json').write_text(json.dumps(self.record))
  with contextlib.redirect_stdout(io.StringIO()):Q.verify(stage)
 def test_rc_may_publish_with_explicit_production_pending_but_stable_is_refused(self):
  self.verify('candidate')
  with self.assertRaises(AssertionError):self.verify('stable')
 def test_source_or_evidence_drift_refuses_candidate(self):
  (self.root/'Cargo.toml').write_text('[package]\nversion = "3.0.0-rc.2"\n')
  with self.assertRaises(AssertionError):self.verify('candidate')
 def test_false_production_complete_label_is_refused(self):
  self.record['status']='production-qualified';self.record['production_pending']=False
  with self.assertRaises(AssertionError):self.verify('stable')
 def test_stable_requires_cleanup_and_no_reserved_exposure(self):
  self.record['status']='production-qualified';self.record['production_pending']=False;self.record['qualification'].update(real_browser_login=True,cleanup_complete=True,enabled_workflows_passed=['storage','hosting','durable'])
  self.record['canary']['reserved_atoms']=1
  with self.assertRaises(AssertionError):self.verify('stable')
  self.record['canary']['reserved_atoms']=0;self.verify('stable')
 def test_candidate_rejects_budget_overrun_and_unpublished_contract(self):
  self.record['canary']['reserved_atoms']=10_000_001
  with self.assertRaises(AssertionError):self.verify('candidate')
  self.record['canary']['reserved_atoms']=0;self.record['contracts']['published']=False
  with self.assertRaises(AssertionError):self.verify('candidate')
 def test_authorized_hundred_dollar_record_includes_outstanding_reservations(self):
  self.record['canary'].update(maximum_atoms=100_000_000,spent_atoms=45_000_060,reserved_atoms=54_999_940)
  self.verify('candidate')
  self.record['canary']['reserved_atoms']+=1
  with self.assertRaises(AssertionError):self.verify('candidate')
 def test_qualification_cannot_increase_the_authorized_ceiling_or_use_inexact_atoms(self):
  original=self.record['canary'].copy()
  for field,value in [('maximum_atoms',Q.AUTHORIZED_CANARY_MAX_ATOMS+1),('maximum_atoms',0),('maximum_atoms',True),('spent_atoms',0.5),('reserved_atoms',False),('reserved_atoms',-1)]:
   with self.subTest(field=field,value=value):
    self.record['canary']={**original,field:value}
    with self.assertRaises(AssertionError):self.verify('candidate')
 def test_authorized_thousand_dollar_record_preserves_prior_spending(self):
  self.record['canary'].update(maximum_atoms=1_000_000_000,spent_atoms=45_021_726,reserved_atoms=954_978_274)
  self.verify('candidate')
  self.record['canary']['reserved_atoms']+=1
  with self.assertRaises(AssertionError):self.verify('candidate')
if __name__=='__main__':unittest.main()
