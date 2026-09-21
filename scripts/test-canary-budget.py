import importlib.util,pathlib,tempfile,unittest
spec=importlib.util.spec_from_file_location('budget',pathlib.Path(__file__).with_name('canary-budget.py'));budget=importlib.util.module_from_spec(spec);spec.loader.exec_module(budget)
class Budget(unittest.TestCase):
 def test_outstanding_reservations_survive_reruns_and_settlement_is_exact(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'budget.json'
   budget.update(path,'reserve','vm',800_000_000)
   self.assertEqual(budget.update(path,'status')['remaining_atoms'],200_000_000)
   with self.assertRaises(ValueError):budget.update(path,'reserve','replacement',300_000_000)
   with self.assertRaises(ValueError):budget.update(path,'reserve','vm',1)
   budget.update(path,'settle','vm',10_000_000)
   self.assertEqual(budget.update(path,'reserve','hosting',990_000_000)['remaining_atoms'],0)
   with self.assertRaises(ValueError):budget.update(path,'settle','vm',0)
 def test_unknown_or_non_integer_exposure_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'budget.json'
   for value in [None,1.5,-1,True]:
    with self.assertRaises(ValueError):budget.update(path,'reserve','a',value)
 def test_explicit_increase_preserves_old_spending_reservations_and_backup(self):
  import json
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'budget.json'
   original={'version':1,'maximum_atoms':100_000_000,'operations':{'spent':{'state':'settled','maximum_atoms':40_000_000,'actual_atoms':30_000_000},'unknown':{'state':'reserved','maximum_atoms':60_000_000}},'budget_changes':[{'id':'earlier-approval'}]}
   path.write_text(json.dumps(original))
   self.assertEqual(budget.update(path,'status')['remaining_atoms'],10_000_000)
   with self.assertRaises(ValueError):budget.update(path,'reserve','too-soon',20_000_000)
   raised=budget.update(path,'raise-limit',None,1_000_000_000)
   self.assertEqual(raised['operations'],original['operations'])
   self.assertEqual(raised['remaining_atoms'],910_000_000)
   self.assertEqual(raised['budget_changes'][0],original['budget_changes'][0])
   backup=next(path.parent.glob('budget.json.before-*'))
   self.assertEqual(json.loads(backup.read_text())['operations'],original['operations'])
   self.assertEqual(backup.stat().st_mode & 0o777,0o600)
   with self.assertRaises(ValueError):budget.update(path,'raise-limit',None,2_000_000_000)
if __name__=='__main__':unittest.main()
