#!/usr/bin/env python3
"""Regression tests for the subtree charge mutation runner (inventory dependencies)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('mutations', Path(__file__).with_name('subtree-charge-mutations.py'))
mutations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mutations)


class ChargeMutations(unittest.TestCase):
    def test_inventory_excludes_tests_comments_and_literals(self):
        source = b'''
fn production(budget: &Budget) -> Result<(), SubtreeError> {
    // budget.charge(100)?;
    let _ = "budget.charge(200)";
    budget.charge(checked(1, 2)?)?;
    self.budget().charge(3)
}
#[cfg(test)] mod tests { fn helper() { budget.charge(4); } }
#[test] fn test_only() { budget.charge(5); }
'''
        sites = mutations.sites_in('example.rs', source)
        self.assertEqual(len(sites), 2)
        self.assertEqual([site['function'] for site in sites], ['production', 'production'])
        changed = mutations.replace(source, sites[0])
        self.assertIn(b'checked(1, 2)?', changed)
        self.assertIn(b'self.budget().charge(3)', changed)
        self.assertNotIn(b'budget.charge(checked', changed)
        self.assertEqual(len(mutations.sites_in('example.rs', changed)), 1)

    def test_generated_projector_charges_are_mutated_in_the_quote(self):
        source = b'fn emit() { quote! { ctx.budget().charge(#key_count)?; } }'
        sites = mutations.sites_in('crates/opc-yanggen/src/content.rs', source)
        self.assertEqual(len(sites), 1)
        changed = mutations.replace(source, sites[0])
        self.assertIn(b'#key_count', changed)
        self.assertIn(b'opc_mgmt_schema::subtree::SubtreeError', changed)
        self.assertNotIn(b'.charge(', changed)

    def test_inventory_discovers_charge_sites_in_new_read_path_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in mutations.ROOTS:
                candidate = root / name
                if candidate.suffix == '.rs':
                    candidate.parent.mkdir(parents=True, exist_ok=True)
                    candidate.write_text('')
                else:
                    candidate.mkdir(parents=True, exist_ok=True)
            path = root / 'crates/opc-netconf-server/src/discovery/new_content.rs'
            path.parent.mkdir(parents=True)
            path.write_text('fn project() { budget.charge(7); }')
            sources, sites = mutations.inventory(root)
            self.assertEqual(len(sites), 1)
            self.assertEqual(sites[0]['path'], str(path.relative_to(root)))
            self.assertEqual(sources[sites[0]['path']], path.read_bytes())

    def test_failed_compilation_and_timeouts_are_not_killed_mutations(self):
        failed = 'test real_test ... FAILED\ntest result: FAILED. 4 passed; 1 failed; 0 ignored;'
        self.assertEqual(mutations.outcome(101, failed), 'killed')
        self.assertEqual(mutations.outcome(0, 'test result: ok. 5 passed; 0 failed; 0 ignored;'), 'survived')
        for code, log in [(101, 'error: could not compile'), (124, failed),
                          (101, 'could not compile\n' + failed), (0, '')]:
            self.assertEqual(mutations.outcome(code, log), 'invalid')

    def test_source_restored_after_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.rs'
            path.write_bytes(b'original')
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                with mutations.overlay(path, b'original', b'mutated'):
                    self.assertEqual(path.read_bytes(), b'mutated')
                    raise RuntimeError('interrupted')
            self.assertEqual(path.read_bytes(), b'original')

    def test_concurrent_edit_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.rs'
            path.write_bytes(b'original')
            with self.assertRaisesRegex(RuntimeError, 'changed during mutation'):
                with mutations.overlay(path, b'original', b'mutated'):
                    path.write_bytes(b'another edit')
            self.assertEqual(path.read_bytes(), b'another edit')


if __name__ == '__main__':
    unittest.main()
