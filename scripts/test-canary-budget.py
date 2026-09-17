import importlib.util,pathlib,tempfile,unittest
spec=importlib.util.spec_from_file_location('budget',pathlib.Path(__file__).with_name('canary-budget.py'));budget=importlib.util.module_from_spec(spec);spec.loader.exec_module(budget)
class Budget(unittest.TestCase):
 def test_outstanding_reservations_survive_reruns_and_settlement_is_exact(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'budget.json'
   budget.update(path,'reserve','vm',8_000_000)
   self.assertEqual(budget.update(path,'status')['remaining_atoms'],2_000_000)
   with self.assertRaises(ValueError):budget.update(path,'reserve','replacement',3_000_000)
   with self.assertRaises(ValueError):budget.update(path,'reserve','vm',1)
   budget.update(path,'settle','vm',1_000_000)
   self.assertEqual(budget.update(path,'reserve','hosting',9_000_000)['remaining_atoms'],0)
   with self.assertRaises(ValueError):budget.update(path,'settle','vm',0)
 def test_unknown_or_non_integer_exposure_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'budget.json'
   for value in [None,1.5,-1,True]:
    with self.assertRaises(ValueError):budget.update(path,'reserve','a',value)
if __name__=='__main__':unittest.main()
