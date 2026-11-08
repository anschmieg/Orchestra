import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from acceptance_reconcile import record_launch, receipt_path, lookup, reconcile

class TornTerminatorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / 'home'
        self.entry = dict(t3_thread_id='thread-1', receipt='receipt-1', task_id='task-1', phase='review', commit='a'*40, worktree='/tmp/worktree-1')
        self.assertEqual(record_launch(**self.entry, home=self.home)['status'], 'recorded')

    def test_complete_json_without_newline_blocks_lookup_replay_new_records(self):
        p = receipt_path(self.home)
        torn = p.read_bytes().rstrip(b'\n')
        p.write_bytes(torn)
        self.assertEqual(lookup('thread-1', 'receipt-1', home=self.home)['status'], 'blocked')
        self.assertEqual(reconcile('thread-1','receipt-1',task_id='task-1',phase='review',commit='a'*40,worktree='/tmp/worktree-1',home=self.home)['status'], 'blocked')
        self.assertEqual(record_launch(**{**self.entry, 'receipt':'receipt-2'}, home=self.home)['status'], 'blocked')
        self.assertEqual(p.read_bytes(),torn)

    def test_blank_line_inside_ledger_blocks(self):
        p = receipt_path(self.home)
        torn = p.read_bytes() + b'  \n'
        p.write_bytes(torn)
        self.assertEqual(lookup('thread-1','receipt-1',home=self.home)['status'],'blocked')
        self.assertEqual(record_launch(**{**self.entry,'receipt':'receipt-2'},home=self.home)['status'],'blocked')
        self.assertEqual(p.read_bytes(),torn)

    def test_complete_line_still_idempotent(self):
        self.assertEqual(record_launch(**self.entry,home=self.home)['status'],'duplicate')
        self.assertEqual(record_launch(**{**self.entry,'receipt':'receipt-2'},home=self.home)['status'],'recorded')

if __name__ == '__main__': unittest.main()
