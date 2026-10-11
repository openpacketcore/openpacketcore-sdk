#!/usr/bin/env python3
"""Regression fixtures for test inventories, declarations and required CI."""

from copy import deepcopy
from pathlib import Path
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from test_inventory.cli import comparison_revisions, event_revisions, github_issue_exists, main
from test_inventory.guard import analyze_files, inventory
from test_inventory.model import GuardError
from test_inventory.source import read_revision
from test_inventory.workflows import documents


MANIFEST = '[package]\nname = "fixture"\nversion = "0.1.0"\n'
TEST = 'rust:.::lib=lib::checks::works'
JOB = 'ci:.github/workflows/ci.yml::tests'


def rust(body='assert_eq!(value(), 1);', attributes='#[test]', extra=''):
    return {'Cargo.toml': MANIFEST, 'src/lib.rs': f'#[cfg(test)] mod checks {{ {extra} {attributes} fn works() {{ {body} }} }}'}


def declare(files, subject=TEST, kind='removed', **options):
    entry = dict(test=subject, kind=kind, reason='The replacement covers the supported contract.', issue=42)
    entry.update(options)
    return {**files, 'ci/test-changes.json': json.dumps(dict(version=1, changes=[entry]))}


def report(base, head):
    return analyze_files(base, head, lambda number: number == 42)


def workflow(body='run: cargo test --workspace', needs='[tests]', matrix=''):
    return {'.github/workflows/ci.yml': f'''name: CI
on: [pull_request, push]
jobs:
  rust:
    name: Rust workspace
    needs: {needs}
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
  tests:
    runs-on: ubuntu-latest
{matrix}    steps:
      - {body}
'''}


class RustInventoryTests(unittest.TestCase):
    def test_removal_is_rejected_with_name_and_location(self):
        result = report(rust(), rust().copy() | {'src/lib.rs': ''})
        self.assertFalse(result.success)
        self.assertEqual([(f.subject, f.kind, f.file, f.line) for f in result.findings], [(TEST, 'removed', 'src/lib.rs', 1)])

    def test_assertion_decrease_is_rejected(self):
        result = report(rust('assert!(ok()); assert_eq!(value(), 1);'), rust('assert!(ok());'))
        self.assertFalse(result.success)
        self.assertEqual(result.findings[0].kind, 'assertions-decreased')
        self.assertIn('2 -> 1', result.findings[0].detail)

    def test_debug_and_result_assertions_are_counted(self):
        body = 'debug_assert!(ready()); debug_assert_eq!(a(), b()); assert_matches!(v(), Some(_)); result().expect("result"); result().unwrap();'
        result = report(rust(body), rust(body.replace('result().unwrap();', '')))
        self.assertIn('5 -> 4', result.findings[0].detail)

    def test_comments_and_strings_cannot_replace_assertions(self):
        head = rust('let _ = r###"assert!(true); result().unwrap();"###; /* assert!(true); */ // assert_eq!(1, 1);\n')
        result = report(rust(), head)
        self.assertFalse(result.success)
        self.assertIn('1 -> 0', result.findings[0].detail)

    def test_constant_false_branch_assertions_do_not_count(self):
        for body in ('if false { assert!(ready()); }',
                     'if !true { result().unwrap(); }',
                     'if true {} else { assert!(ready()); }',
                     'while false { assert!(ready()); }', 'if 1 > 2 { assert!(ready()); }',
                     'false && checked();', 'true || checked();'):
            with self.subTest(body=body):
                head = rust(body, extra='fn checked() { assert!(ready()); }')
                self.assertEqual(inventory(head).coverage()[TEST]['assertions'], 0)
                self.assertFalse(report(rust(), head).success)

    def test_trivially_true_assertions_do_not_count(self):
        for body in ('assert!(true);', 'debug_assert!(!false);',
                     'assert_eq!(value, value);', 'assert_eq!(object.field, object.field);',
                     'assert!(value == value);', 'debug_assert_ne!(true, false);',
                     'assert!(1 < 2);', 'assert_ne!(1, 2);', 'assert!({ true });',
                     'assert!(true, "unused diagnostic {:?}", result().unwrap());'):
            with self.subTest(body=body):
                self.assertEqual(inventory(rust(body)).coverage()[TEST]['assertions'], 0)
                self.assertFalse(report(rust(), rust(body)).success)

    def test_uninvoked_closure_assertions_do_not_count(self):
        for body in ('let _skip = || assert!(ready());',
                     'let skip = || { assert!(ready()); result().unwrap(); };',
                     'let skip = || checked();',
                     'let skip = || assert!(ready()); if false { skip(); }',
                     'let skip = || assert!(ready()); let outer = || skip();',
                     'let skip = || assert!(ready()); drop(skip);',
                     'let skip = Box::new(|| assert!(ready()));',
                     'let skip = vec![|| assert!(ready())];'):
            with self.subTest(body=body):
                head = rust(body, extra='fn checked() { assert!(ready()); }')
                self.assertEqual(inventory(head).coverage()[TEST]['assertions'], 0)
                self.assertFalse(report(rust(), head).success)

    def test_called_closures_and_live_branches_retain_assertions(self):
        for body in ('let check = || assert!(ready()); check();',
                     'let check = || assert!(ready()); let alias = check; alias();',
                     '(|| assert!(ready()))();', 'run(|| assert!(ready()));',
                     'let check = Box::new(|| assert!(ready())); check();',
                     'if false {} else { assert!(ready()); }',
                     'if condition() { assert!(ready()); }',
                     'assert_eq!(value(), value());'):
            with self.subTest(body=body):
                self.assertEqual(inventory(rust(body)).coverage()[TEST]['assertions'], 1)
                self.assertTrue(report(rust(), rust(body)).success)

    def test_legitimate_assertion_edits_do_not_compare_text(self):
        self.assertTrue(report(rust('assert_eq!(actual(), 5, "old wording");'),
                               rust('assert_eq!(updated(), 6, "new wording");')).success)

    def test_assertions_inside_macro_token_trees_count(self):
        old = rust('tokio::select! { _ = ready() => { assert!(ok()); result().expect("checked"); }, }')
        new = rust('tokio::select! { _ = ready() => { assert!(ok()); }, }')
        self.assertFalse(report(old, new).success)

    def test_macro_branch_blocks_discount_unreachable_assertions(self):
        for body in ('if false { assert!(ready()); result().unwrap(); }',
                     'let unused = || assert!(ready());', 'assert!(true);'):
            with self.subTest(body=body):
                head = rust('tokio::select! { _ = ready() => { ' + body + ' }, }')
                self.assertEqual(inventory(head).coverage()[TEST]['assertions'], 0)
                self.assertFalse(report(rust(), head).success)
        head = rust('tokio::select! { _ = ready() => { let check = || assert!(ready()); check(); }, }')
        self.assertEqual(inventory(head).coverage()[TEST]['assertions'], 1)

    def test_same_named_tests_have_full_module_paths(self):
        base = {'Cargo.toml': MANIFEST, 'src/lib.rs': 'mod a; mod b;', 'src/a.rs': '#[test] fn same() {assert!(true);}', 'src/b.rs': '#[test] fn same() {assert!(true);}'}
        result = report(base, {**base, 'src/lib.rs': 'mod a;'})
        self.assertEqual([f.subject for f in result.findings], ['rust:.::lib=lib::b::same'])

    def test_path_attribute_and_nested_external_module(self):
        base = {'Cargo.toml': MANIFEST, 'src/lib.rs': '#[cfg(test)] #[path="other.rs"] mod named;', 'src/other.rs': 'mod inner;', 'src/other/inner.rs': '#[rstest::rstest] fn works() {assert!(true);}'}
        self.assertEqual(set(inventory(base).tests), {'rust:.::lib=lib::named::inner::works'})

    def test_path_inside_inline_module_follows_rust_directory_rules(self):
        base = {'Cargo.toml': MANIFEST, 'src/lib.rs': 'mod outer;', 'src/outer.rs': '#[cfg(test)] mod checks { #[path="case.rs"] mod named; }', 'src/outer/checks/case.rs': '#[test] fn works() {assert!(true);}'}
        self.assertEqual(set(inventory(base).tests), {'rust:.::lib=lib::outer::checks::named::works'})

    def test_shared_helper_assertion_removal_reaches_each_test(self):
        old = rust('check();', extra='fn check() {assert!(ready()); assert_eq!(state(), old());}')
        new = rust('check();', extra='fn check() {assert!(ready());}')
        result = report(old, new)
        self.assertFalse(result.success)
        self.assertIn('2 -> 1', result.findings[0].detail)

    def test_moving_assertions_into_helper_is_preserved(self):
        old = rust('assert!(ready()); assert_eq!(state(), old());')
        new = rust('check();', extra='fn check() {assert!(ready()); assert_eq!(state(), old());}')
        self.assertTrue(report(old, new).success)

    def test_checked_result_callback_preserves_propagated_error_checks(self):
        old = rust('check(|| { read().unwrap(); assert_eq!(message(), expected()); Ok(()) }).unwrap();')
        new = rust('check(|| { read()?; if message() != expected() { return Err(invalid()); } Ok(()) }).unwrap();')
        self.assertEqual(inventory(old).coverage()[TEST]['assertions'], 3)
        self.assertEqual(inventory(new).coverage()[TEST]['assertions'], 3)
        self.assertTrue(report(old, new).success)

    def test_discarded_callback_result_does_not_preserve_assertions(self):
        old = rust('check(|| { read().unwrap(); assert_eq!(message(), expected()); Ok(()) }).unwrap();')
        new = rust('let _ = check(|| { read()?; if message() != expected() { return Err(invalid()); } Ok(()) });')
        self.assertFalse(report(old, new).success)

    def test_dropping_a_checked_callback_predicate_is_rejected(self):
        old = rust('check(|| { read()?; if message() != expected() { return Err(invalid()); } Ok(()) }).unwrap();')
        new = rust('check(|| { read()?; Ok(()) }).unwrap();')
        self.assertFalse(report(old, new).success)

    def test_awaited_callback_result_must_check_success(self):
        callback = 'check(|| { read()?; if invalid() { return Err(error()); } Ok(()) })'
        checked = inventory(rust(callback + '.await.expect("checked");')).coverage()[TEST]['assertions']
        expected_error = inventory(rust(callback + '.await.unwrap_err();')).coverage()[TEST]['assertions']
        recovered = inventory(rust(callback + '.unwrap_or_else(|_| default());')).coverage()[TEST]['assertions']
        self.assertEqual(checked, 3)
        self.assertEqual(expected_error, 1)
        self.assertEqual(recovered, 0)

    def test_nested_unused_callback_cannot_supply_propagated_checks(self):
        source = rust('check(|| { let unused = || { read()?; if invalid() { return Err(error()); } Ok(()) }; Ok(()) }).unwrap();')
        self.assertEqual(inventory(source).coverage()[TEST]['assertions'], 1)

    def test_replacing_checked_scenario_is_visible_despite_added_checks(self):
        old = rust('passive();', extra='fn passive() {probe().expect("survivor");}')
        new = rust('forced();', extra='fn forced() {trigger_for_test(); probe().unwrap(); assert!(ready());}')
        result = report(old, new)
        self.assertFalse(result.success)
        self.assertTrue(any('helper removed' in f.detail for f in result.findings))

    def test_method_call_does_not_resolve_to_unrelated_free_function(self):
        base = rust('local.scope(); assert!(ready());', extra='fn scope() { assert!(unrelated()); }')
        head = rust('local.scope(); assert!(ready());', extra='#[cfg(unix)] fn scope() {}')
        self.assertTrue(report(base, head).success)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)

    def test_result_expect_does_not_resolve_to_unrelated_fixture_method(self):
        extra = 'struct Peer; impl Peer { fn expect(&self) {assert!(unrelated());} }'
        base = rust('result().expect("checked");', extra=extra)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)

    def test_qualified_constructor_does_not_resolve_to_other_type(self):
        base = rust('Arc::new(value()); assert!(ready());', extra='struct Peer; impl Peer { fn new() {assert!(unrelated());} }')
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)

    def test_method_assertions_and_qualified_helpers_are_followed(self):
        extra = 'struct Peer; impl Peer { fn checked(&self) {assert!(ready());} } mod detail {pub fn checked() {assert!(ready());}}'
        base = rust('peer.checked(); detail::checked();', extra=extra)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 2)
        self.assertFalse(report(base, rust('peer.checked(); detail::checked();', extra=extra.replace('assert!(ready());', ''))).success)

    def test_self_calls_retain_their_type_when_another_method_is_added(self):
        extra = 'struct Peer; impl Peer { fn checked(&self) {self.wait_for();} fn wait_for(&self) {assert!(ready());} }'
        base = rust('peer.checked();', extra=extra)
        head = rust('peer.checked();', extra=extra + 'struct Other; impl Other {fn wait_for(&self) {assert!(unrelated());}}')
        self.assertTrue(report(base, head).success)
        self.assertEqual(inventory(head).coverage()[TEST]['assertions'], 1)

    def test_constructor_receiver_finds_helper_in_another_module(self):
        extra = 'mod support {pub struct Peer; impl Peer {pub fn new() -> Self {Peer} pub fn checked(&self) {assert!(ready());}}}'
        base = rust('let peer = Arc::new(support::Peer::new()); peer.checked();', extra=extra)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)
        self.assertFalse(report(base, rust('let peer = Arc::new(support::Peer::new()); peer.checked();', extra=extra.replace('assert!(ready());', ''))).success)

    def test_unknown_receiver_does_not_find_method_in_unrelated_module(self):
        extra = 'mod support {struct Peer; impl Peer {fn available_permits(&self) {assert!(unrelated());}}}'
        base = rust('semaphore.available_permits(); assert!(ready());', extra=extra)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)

    def test_factory_return_type_identifies_relocated_method(self):
        extra = 'mod support {pub struct Peer; impl Peer {pub fn checked(&self) {assert!(ready());}}} fn peer() -> Arc<support::Peer> {unimplemented!()}'
        base = rust('let fixture = peer(); fixture.checked();', extra=extra)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)

    def test_qualified_optional_factory_preserves_method_receiver(self):
        extra = 'pub mod support {pub struct Peer; impl Peer {pub fn checked(&self) {assert!(ready());}} pub fn peer() -> Option<Arc<Peer>> {None}}'
        base = rust('let fixture = crate::checks::support::peer().unwrap_or_default(); fixture.checked();', extra=extra)
        self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)

    def test_qualified_type_distinguishes_same_named_helpers(self):
        extra = '''mod a {pub struct Peer; impl Peer {pub fn new() -> Self {Peer} pub fn checked(&self) {assert!(ready());}}}
mod b {pub struct Peer; impl Peer {pub fn new() -> Self {Peer} pub fn checked(&self) {assert!(unrelated());}}}
fn peer() -> Arc<a::Peer> {unimplemented!()}'''
        for body in ('let fixture = a::Peer::new(); fixture.checked();', 'let fixture = peer(); fixture.checked();'):
            with self.subTest(body=body):
                base = rust(body, extra=extra)
                self.assertEqual(inventory(base).coverage()[TEST]['assertions'], 1)
                self.assertFalse(report(base, rust(body, extra=extra.replace('assert!(ready());', ''))).success)

    def test_atomic_store_cannot_call_fixture_accessor(self):
        extra = 'struct Peer; impl Peer {fn store(&self, index: usize) {assert!(unrelated());}}'
        for body in ('atomic.store(true, Ordering::Release);', 'assert!({atomic.store(true, Ordering::Release); true});'):
            with self.subTest(body=body):
                count = inventory(rust(body, extra=extra)).coverage()[TEST]['assertions']
                self.assertEqual(count, 0)

    def test_helper_moved_into_method_preserves_checks(self):
        base = rust('wait_ready();', extra='fn wait_ready() { result().expect("ready"); }')
        head = rust('peer.wait_ready();', extra='struct Peer; impl Peer { fn wait_ready(&self) { result().expect("ready"); } }')
        self.assertTrue(report(base, head).success)

    def test_renamed_helper_preserves_named_assertion(self):
        base = rust('wait_count();', extra='fn wait_count() { result().expect("count published"); }')
        head = rust('wait_retired();', extra='fn wait_retired() { other_result().expect("count published"); assert!(ready()); }')
        self.assertTrue(report(base, head).success)

    def test_platform_helper_does_not_gate_calling_test(self):
        base = rust('check();', extra='fn check() { assert!(ready()); }')
        head = rust('check();', extra='#[cfg(unix)] fn check() { assert!(ready()); }')
        self.assertTrue(report(base, head).success)
        head = rust('check();', extra='fn check() { if std::env::var("SKIP").is_ok() { return; } assert!(ready()); }')
        self.assertFalse(report(base, head).success)

    def test_cfg_selected_return_is_not_unconditional(self):
        base = rust('check();', extra='fn check() { assert!(ready()); }')
        head = rust('check();', extra='fn check() { #[cfg(not(unix))] return fallback(); #[cfg(unix)] {assert!(ready());} }')
        self.assertTrue(report(base, head).success)

    def test_checked_same_test_child_reexecution_preserves_coverage(self):
        body = '''const CHILD: &str = "CHILD_MARKER";
const TEST: &str = "checks::works";
if std::env::var_os(CHILD).is_none() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"]).env(CHILD, "1").output().unwrap();
    assert!(output.status.success());
    return;
}
assert!(ready());'''
        self.assertTrue(report(rust('assert!(ready());'), rust(body)).success)
        for changed in (body.replace('checks::works', 'other::works'), body.replace('assert!(output.status.success());', ''), body.replace('.env(CHILD, "1")', '.env("OTHER", "1")')):
            with self.subTest(changed=changed):
                self.assertTrue(any(f.kind == 'disabled' for f in report(rust('assert!(ready());'), rust(changed)).findings))

    def test_diagnostic_panic_preserves_result_assertion(self):
        old = rust('probe().expect("ready");')
        new = rust('probe().unwrap_or_else(|error| panic!("ready: {error}"));')
        self.assertTrue(report(old, new).success)

    def test_ignore_and_new_ignored_test_are_rejected(self):
        for old in (rust(), {'Cargo.toml': MANIFEST, 'src/lib.rs': ''}):
            with self.subTest(old=old):
                result = report(old, rust(attributes='#[test] #[ignore="tracked elsewhere"]'))
                self.assertTrue(any(f.kind == 'disabled' for f in result.findings))

    def test_module_feature_cfg_and_conditional_ignore_are_rejected(self):
        for attribute in ('#[cfg(feature="optional")]', '#[cfg_attr(target_os="linux", ignore)]'):
            with self.subTest(attribute=attribute):
                old = rust()
                new = {**old, 'src/lib.rs': attribute + old['src/lib.rs']}
                self.assertFalse(report(old, new).success)

    def test_test_case_and_tokio_attributes_are_inventory_members(self):
        for attribute in ('#[test_case(1)]', '#[tokio::test(flavor="multi_thread")]', '#[rstest]'):
            with self.subTest(attribute=attribute):
                self.assertEqual(set(inventory(rust(attributes=attribute)).tests), {TEST})

    def test_environment_and_unconditional_early_returns_are_rejected(self):
        for prefix in ('if std::env::var("RUN_IT").is_err() {return;}', 'return;'):
            with self.subTest(prefix=prefix):
                self.assertFalse(report(rust(), rust(prefix + 'assert_eq!(value(), 1);')).success)

    def test_required_features_and_autotests_are_not_silent(self):
        base = {'Cargo.toml': MANIFEST, 'tests/contract.rs': '#[test] fn works(){assert!(true);}'}
        new = {**base, 'Cargo.toml': MANIFEST + 'autotests=false\n'}
        self.assertTrue(any(f.kind == 'disabled' for f in report(base, new).findings))
        new = {**base, 'Cargo.toml': MANIFEST + '\n[[test]]\nname="contract"\nrequired-features=["optional"]\n'}
        self.assertTrue(any(f.kind == 'disabled' for f in report(base, new).findings))

    def test_invalid_rust_is_not_an_empty_inventory(self):
        with self.assertRaisesRegex(GuardError, 'parse error'):
            inventory(rust('assert!('))

    def test_cfg_on_destructured_field_preserves_assertions_and_lines(self):
        for fields in ('#[cfg(test)] value', 'first, #[cfg(any(test, feature="control"))] value, ..'):
            with self.subTest(fields=fields):
                base = rust('let Record {' + fields + '} = record;\nassert_eq!(value, "α");')
                self.assertTrue(report(base, base).success)
                new = {**base, 'src/lib.rs': base['src/lib.rs'].replace('assert_eq!(value, "α");', '')}
                result = report(base, new)
                self.assertEqual(result.findings[0].kind, 'assertions-decreased')


class OtherLanguagesTests(unittest.TestCase):
    def test_python_constant_false_branch_assertions_do_not_count(self):
        old = {'test_contract.py': 'def test_works():\n assert ready()\n'}
        for body in (' if False:\n  assert ready()\n',
                     ' if True:\n  pass\n else:\n  self.assertTrue(ready())\n',
                     ' while False:\n  assert ready()\n'):
            with self.subTest(body=body):
                head = {'test_contract.py': 'def test_works():\n' + body}
                self.assertFalse(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 0)

    def test_python_trivially_true_assertions_do_not_count(self):
        old = {'test_contract.py': 'def test_works():\n assert ready()\n'}
        for body in ('assert True', 'assert value == value',
                     'self.assertEqual(value, value)', 'self.assertTrue(True)',
                     'self.assertFalse(False)'):
            with self.subTest(body=body):
                head = {'test_contract.py': 'def test_works():\n ' + body + '\n'}
                self.assertFalse(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 0)

    def test_python_uninvoked_closure_assertions_do_not_count(self):
        old = {'test_contract.py': 'def test_works():\n assert ready()\n'}
        for body in (' unused = lambda: self.assertTrue(ready())\n',
                     ' def unused():\n  assert ready()\n',
                     ' def unused():\n  assert ready()\n if False:\n  unused()\n',
                     ' def unused():\n  assert ready()\n def outer():\n  unused()\n'):
            with self.subTest(body=body):
                head = {'test_contract.py': 'def test_works():\n' + body}
                self.assertFalse(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 0)

    def test_python_called_closures_and_live_checks_count(self):
        old = {'test_contract.py': 'def test_works():\n assert ready()\n'}
        for body in (' check = lambda: self.assertTrue(ready())\n check()\n',
                     ' def check():\n  assert ready()\n check()\n',
                     ' (lambda: self.assertTrue(ready()))()\n',
                     ' run(lambda: self.assertTrue(ready()))\n',
                     ' if False:\n  pass\n else:\n  assert ready()\n',
                     ' self.assertEqual(value(), value())\n'):
            with self.subTest(body=body):
                head = {'test_contract.py': 'def test_works():\n' + body}
                self.assertTrue(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 1)

    def test_go_constant_false_branch_assertions_do_not_count(self):
        old = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { require.True(t, ready()) }'}
        for body in ('if false { t.Fatal("bad") }',
                     'if true {} else { require.True(t, ready()) }',
                     'for false { t.Fatal("bad") }', 'if value != value { t.Fatal("bad") }'):
            with self.subTest(body=body):
                head = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { ' + body + ' }'}
                self.assertFalse(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 0)

    def test_go_trivially_true_assertions_do_not_count(self):
        old = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { require.True(t, ready()) }'}
        for body in ('require.True(t, true)', 'assert.False(t, false)',
                     'require.Equal(t, value, value)', 'require.NoError(t, nil)'):
            with self.subTest(body=body):
                head = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { ' + body + ' }'}
                self.assertFalse(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 0)

    def test_go_uninvoked_closure_assertions_do_not_count(self):
        old = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { require.True(t, ready()) }'}
        for body in ('unused := func() { t.Fatal("bad") }',
                     'unused := func() { t.Fatal("bad") }; if false { unused() }',
                     'unused := func() { t.Fatal("bad") }; outer := func() { unused() }'):
            with self.subTest(body=body):
                head = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { ' + body + ' }'}
                self.assertFalse(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 0)

    def test_go_called_closures_and_live_checks_count(self):
        old = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { require.True(t, ready()) }'}
        for body in ('check := func() { require.True(t, ready()) }; check()',
                     'func() { require.True(t, ready()) }()',
                     't.Run("child", func(t *testing.T) { require.True(t, ready()) })',
                     'if false {} else { require.True(t, ready()) }',
                     'require.Equal(t, value(), value())'):
            with self.subTest(body=body):
                head = {'contract_test.go': 'package demo\nfunc TestWorks(t *testing.T) { ' + body + ' }'}
                self.assertTrue(report(old, head).success)
                self.assertEqual(next(iter(inventory(head).coverage().values()))['assertions'], 1)

    def test_python_removal_and_assertion_decrease(self):
        old = {'tests/test_contract.py': 'class Contract:\n def test_works(self):\n  assert ready()\n  self.assertEqual(a(), b())\n'}
        self.assertFalse(report(old, {}).success)
        result = report(old, {'tests/test_contract.py': old['tests/test_contract.py'].replace('  assert ready()\n', '')})
        self.assertEqual(result.findings[0].subject, 'python:tests/test_contract.py::Contract.test_works')
        self.assertEqual(result.findings[0].kind, 'assertions-decreased')

    def test_python_decorator_and_environment_gate(self):
        old = {'test_contract.py': 'def test_works():\n assert ready()\n'}
        for source in ('@pytest.mark.skipif(os.getenv("SKIP"), reason="optional")\n' + old['test_contract.py'], 'def test_works():\n if os.getenv("SKIP"):\n  return\n assert ready()\n'):
            with self.subTest(source=source):
                self.assertFalse(report(old, {'test_contract.py': source}).success)

    def test_python_class_bare_skip_marker_disables_its_tests(self):
        source = 'class TestContract:\n def test_works(self):\n  assert ready()\n'
        self.assertFalse(report({'test_api.py': source}, {'test_api.py': '@pytest.mark.skip\n' + source}).success)

    def test_python_raises_and_context_assertions(self):
        old = {'test_contract.py': 'def test_works():\n with pytest.raises(ValueError):\n  call()\n'}
        self.assertFalse(report(old, {'test_contract.py': 'def test_works():\n call()\n'}).success)

    def test_go_removal_error_assertions_skip_and_build_tag(self):
        source = 'package demo\nfunc TestWorks(t *testing.T) { if value()!=1 {t.Fatalf("bad")}; require.Equal(t,a(),b()) }'
        old = {'contract_test.go': source}
        self.assertFalse(report(old, {}).success)
        for new in (source.replace('require.Equal(t,a(),b())', ''), source.replace('if value()', 't.Skip("optional"); if value()'), '//go:build optional\n' + source):
            with self.subTest(new=new):
                self.assertFalse(report(old, {'contract_test.go': new}).success)


class RequiredCITests(unittest.TestCase):
    def test_removing_required_job_is_rejected(self):
        old = workflow()
        new = {'.github/workflows/ci.yml': 'on: pull_request\njobs:\n  rust:\n    name: Rust workspace\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n'}
        result = report(old, new)
        self.assertTrue(any(f.subject == JOB and f.kind == 'required-ci-removed' for f in result.findings))

    def test_moving_tests_outside_aggregate_is_rejected(self):
        self.assertFalse(report(workflow(), workflow(needs='[]')).success)

    def test_required_matrix_lane_removed(self):
        old = workflow(matrix='    strategy:\n      matrix:\n        shard: [unit, integration]\n')
        new = workflow(matrix='    strategy:\n      matrix:\n        shard: [unit]\n')
        self.assertTrue(any(f.subject == JOB + '[shard=integration]' for f in report(old, new).findings))

    def test_test_command_removed_but_job_retained(self):
        result = report(workflow(), workflow(body='run: cargo clippy --workspace'))
        self.assertFalse(result.success)
        self.assertTrue(any('test command' in f.detail for f in result.findings))

    def test_quoted_python_command_removal_is_rejected(self):
        for executable in ('"python3"', '"${RUNNER_TEMP}/venv/bin/python"', "'/tmp/test environment/bin/python3'"):
            with self.subTest(executable=executable):
                old = workflow(body='run: |\n          ' + executable + ' ci/test-guard.py')
                self.assertFalse(report(old, workflow(body='run: echo removed')).success)

    def test_duplicate_command_on_another_platform_cannot_hide_a_removed_run(self):
        old = workflow(needs='[tests, other]')
        path = '.github/workflows/ci.yml'
        old[path] += '  other:\n    runs-on: macos-latest\n    steps:\n      - run: cargo test --workspace\n'
        head = {path: old[path].replace('run: cargo test --workspace', 'run: echo removed', 1)}
        self.assertTrue(any(f.subject == JOB and 'test command' in f.detail for f in report(old, head).findings))

    def test_duplicate_commands_in_the_same_environment_retain_multiplicity(self):
        old = workflow(needs='[tests, other]')
        path = '.github/workflows/ci.yml'
        old[path] += '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test --workspace\n'
        head = {path: old[path].replace('run: cargo test --workspace', 'run: echo removed', 1)}
        self.assertFalse(report(old, head).success)

    def test_relocating_a_command_between_identical_required_environments_passes(self):
        old = workflow(needs='[tests, other]')
        path = '.github/workflows/ci.yml'
        old[path] += '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo setup\n'
        head = {path: old[path].replace('run: cargo test --workspace', 'run: echo moved', 1).replace('run: echo setup', 'run: cargo test --workspace')}
        self.assertTrue(report(old, head).success)

    def test_one_new_execution_cannot_replace_two_removed_executions(self):
        old = workflow(needs='[tests, other, destination]')
        path = '.github/workflows/ci.yml'
        old[path] += '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test --workspace\n  destination:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo setup\n'
        head = {path: old[path].replace('run: cargo test --workspace', 'run: echo moved').replace('run: echo setup', 'run: cargo test --workspace')}
        findings = [f for f in report(old, head).findings if 'test command' in f.detail]
        self.assertEqual(len(findings), 1)

    def test_relocation_to_a_conditional_required_step_is_rejected(self):
        old = workflow(needs='[tests, destination]')
        path = '.github/workflows/ci.yml'
        old[path] += '  destination:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo setup\n'
        head = {path: old[path].replace('run: cargo test --workspace', 'run: echo moved').replace('run: echo setup', 'if: false\n        run: cargo test --workspace')}
        self.assertFalse(report(old, head).success)

    def test_renaming_a_step_cannot_hide_a_new_execution_condition(self):
        old = workflow(body='name: Test\n        run: cargo test --workspace')
        for condition in ('if: false', 'continue-on-error: true'):
            with self.subTest(condition=condition):
                head = {path: source.replace('name: Test', 'name: Renamed\n        ' + condition) for path, source in old.items()}
                self.assertFalse(report(old, head).success)

    def test_renaming_a_step_without_changing_execution_passes(self):
        old = workflow(body='name: Test\n        run: cargo test --workspace')
        head = {path: source.replace('name: Test', 'name: Renamed') for path, source in old.items()}
        self.assertTrue(report(old, head).success)

    def test_renamed_duplicate_steps_cannot_hide_a_new_condition(self):
        old = workflow(body='name: First\n        run: cargo test\n      - name: Second\n        run: cargo test')
        head = {path: source.replace('name: First', 'name: Renamed\n        if: false') for path, source in old.items()}
        self.assertFalse(report(old, head).success)

    def test_adding_a_conditional_duplicate_preserves_existing_execution(self):
        old = workflow(body='name: First\n        run: cargo test')
        head = {path: source + '      - name: Extra\n        if: vars.EXTRA_TESTS\n        run: cargo test\n' for path, source in old.items()}
        self.assertTrue(report(old, head).success)

    def test_broadening_and_renaming_an_existing_conditional_step_passes(self):
        old = workflow(body='name: First\n        if: vars.RUN_TESTS\n        run: cargo test')
        head = {path: source.replace('name: First', 'name: Renamed').replace('        if: vars.RUN_TESTS\n', '') for path, source in old.items()}
        self.assertTrue(report(old, head).success)

    def test_changing_a_required_platform_is_visible(self):
        old = workflow()
        head = {path: source.replace('runs-on: ubuntu-latest', 'runs-on: macos-latest') for path, source in old.items()}
        self.assertTrue(any('runs-on changed' in f.detail for f in report(old, head).findings))

    def test_new_job_condition_or_continue_on_error_is_rejected(self):
        for condition in ('    if: vars.RUN_TESTS\n', '    continue-on-error: true\n'):
            old = workflow()
            new = {key: value.replace('  tests:\n', '  tests:\n' + condition) for key, value in old.items()}
            self.assertFalse(report(old, new).success)

    def test_qualification_manifest_addition_disables_exact_test(self):
        old = rust()
        new = {**old, 'ci/realtime-qualification.json': json.dumps({'tests': [{'name': 'checks::works', 'issue': 42, 'reason': 'qualification'}]})}
        result = report(old, new)
        self.assertTrue(any(f.subject == TEST and f.kind == 'disabled' for f in result.findings))

    def test_python_skip_list_addition(self):
        old = {**rust(), 'ci/plan.py': 'SKIP_TESTS = []\n'}
        new = {**old, 'ci/plan.py': 'SKIP_TESTS = ["checks::works"]\n'}
        self.assertFalse(report(old, new).success)

    def test_duplicate_yaml_keys_fail_closed(self):
        with self.assertRaisesRegex(GuardError, 'duplicate YAML key'):
            report({}, {'.github/workflows/ci.yml': 'jobs:\n  rust: {}\n  rust: {}\n'})

    def test_reusable_required_workflow_is_followed(self):
        old = {'.github/workflows/ci.yml': 'on: pull_request\njobs:\n  rust:\n    name: Rust workspace\n    needs: [tests]\n    steps: []\n  tests:\n    uses: ./.github/workflows/tests.yml\n', '.github/workflows/tests.yml': 'on: workflow_call\njobs:\n  unit:\n    steps:\n      - run: cargo test\n'}
        new = deepcopy(old)
        new['.github/workflows/tests.yml'] = new['.github/workflows/tests.yml'].replace('cargo test', 'cargo clippy')
        self.assertFalse(report(old, new).success)


class RepositoryWorkflowTests(unittest.TestCase):
    def setUp(self):
        path = '.github/workflows/ci.yml'
        source = (Path(__file__).resolve().parents[1] / path).read_text()
        self.jobs = documents({path: source})[path]['jobs']
        self.aggregate = self.jobs['rust']

    def test_required_aggregate_keeps_guard_and_every_rust_lane(self):
        needs = self.aggregate['needs']
        required = {name for name in self.jobs if name.startswith('rust-')}
        required.update({'session-net-i686', 'test-inventory'})
        self.assertEqual(self.aggregate['name'], 'Rust workspace')
        self.assertEqual(self.aggregate['if'], 'always()')
        self.assertNotIn('continue-on-error', self.aggregate)
        self.assertIsInstance(needs, list)
        self.assertEqual(len(needs), len(set(needs)))
        self.assertTrue(required <= set(needs), required - set(needs))
        self.assertTrue(set(needs) <= set(self.jobs))
        self.assertEqual(self.jobs['test-inventory']['uses'], './.github/workflows/test-inventory.yml')

    def test_required_aggregate_rejects_each_non_success_lane(self):
        step = next(step for step in self.aggregate['steps'] if 'LANE_RESULTS' in step.get('env', {}))
        self.assertEqual(step['env']['LANE_RESULTS'], '${{ toJSON(needs) }}')
        self.assertNotIn('if', step)
        self.assertNotIn('continue-on-error', step)
        self.assertNotIn('shell', step)
        lanes = {name: {'result': 'success'} for name in self.aggregate['needs']}

        def run(results):
            return subprocess.run(['bash', '-e', '-c', step['run']],
                                  env={**os.environ, 'LANE_RESULTS': json.dumps(results)},
                                  capture_output=True, text=True, check=False)

        success = run(lanes)
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        self.assertIn(f'all {len(lanes)} Rust lanes succeeded', success.stdout)
        for name in lanes:
            for status in ('failure', 'cancelled', 'skipped', 'unknown', '', None):
                with self.subTest(lane=name, status=status):
                    result = run({**lanes, name: {'result': status}})
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f'::error::Rust lanes did not succeed: {name}', result.stdout)

    def test_nested_i686_aggregate_rejects_each_non_success_result(self):
        job = self.jobs['session-net-i686']
        self.assertEqual(job['if'], 'always()')
        self.assertEqual(job['needs'], ['session-net-i686-tests'])
        self.assertNotIn('continue-on-error', job)
        self.assertEqual(job['env'], {'I686_TESTS_RESULT': '${{ needs.session-net-i686-tests.result }}'})
        (step,) = job['steps']
        self.assertEqual(set(step), {'name', 'run'})

        def run(status):
            return subprocess.run(['bash', '-e', '-c', step['run']], env={**os.environ, 'I686_TESTS_RESULT': status},
                                  capture_output=True, text=True, check=False)

        self.assertEqual(run('success').returncode, 0)
        for status in ('failure', 'cancelled', 'skipped', 'unknown', ''):
            with self.subTest(status=status):
                self.assertNotEqual(run(status).returncode, 0)


class DeclarationTests(unittest.TestCase):
    def test_declared_removal_is_still_printable(self):
        result = report(rust(), declare({'Cargo.toml': MANIFEST, 'src/lib.rs': ''},
                        behavior_deleted=True, deleting_change='This PR removes the legacy behavior.',
                        reason='The legacy behavior is no longer supported.'))
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.findings[0].allowed)
        self.assertEqual(result.findings[0].issue, 42)

    def test_rename_requires_existing_head_target(self):
        old = rust()
        new = {**old, 'src/lib.rs': old['src/lib.rs'].replace('fn works', 'fn renamed')}
        renamed = TEST.rsplit('::', 1)[0] + '::renamed'
        self.assertFalse(report(old, new).success)
        self.assertTrue(report(old, declare(new, renamed_to=renamed, reason='Renamed to ' + renamed)).success)
        self.assertFalse(report(old, declare(new, renamed_to=renamed + '_missing')).success)

    def test_rename_does_not_waive_weaker_assertions(self):
        old = rust()
        new = {**old, 'src/lib.rs': old['src/lib.rs'].replace('fn works', 'fn renamed').replace('assert_eq!(value(), 1);', '')}
        result = report(old, declare(new, renamed_to=TEST.rsplit('::', 1)[0] + '::renamed'))
        self.assertFalse(result.success)
        self.assertTrue(any(f.kind == 'assertions-decreased' and not f.allowed for f in result.findings))

    def test_code_and_test_removal_requires_replacing_tests(self):
        old = rust() | {'src/lib.rs': 'pub fn value() -> u8 {1}\n' + rust()['src/lib.rs']}
        new = rust().copy()
        new['src/lib.rs'] = new['src/lib.rs'].replace('fn works', 'fn replacement')
        self.assertFalse(report(old, declare(new)).success)
        replacement = TEST.rsplit('::', 1)[0] + '::replacement'
        self.assertTrue(report(old, declare(new, replacements=[replacement])).success)

    def test_python_and_go_code_removal_requires_replacements(self):
        cases = [
            ({'app.py': 'def value(): return 1\n', 'tests/test_app.py': 'def test_works(): assert value() == 1\n'}, 'python:tests/test_app.py::test_works'),
            ({'api.go': 'package api\nfunc Value() int { return 1 }', 'api_test.go': 'package api\nfunc TestWorks(t *testing.T) {if Value()!=1 {t.Fatal("bad")}}'}, 'go:.::package=api::TestWorks'),
        ]
        for old, identity in cases:
            with self.subTest(identity=identity):
                result = report(old, declare({}, subject=identity))
                self.assertFalse(result.success)
                self.assertTrue(any('replacing head tests' in error for error in result.errors))

    def test_test_only_removal_also_requires_replacement_or_deleted_behavior(self):
        old = rust() | {'src/lib.rs': 'pub fn value() -> u8 { 1 }\n' + rust()['src/lib.rs']}
        new = {'Cargo.toml': MANIFEST, 'src/lib.rs': 'pub fn value() -> u8 { 1 }'}
        result = report(old, declare(new))
        self.assertFalse(result.success)
        self.assertIn('replacing head tests', result.errors[0])

    def test_deleted_behavior_needs_no_unrelated_replacement(self):
        cases = [
            (rust() | {'src/lib.rs': 'pub fn value() -> u8 { 1 }\n' + rust()['src/lib.rs']}, TEST),
            ({'app.py': 'def value(): return 1\n', 'tests/test_app.py': 'def test_works(): assert value() == 1\n'}, 'python:tests/test_app.py::test_works'),
            ({'api.go': 'package api\nfunc Value() int { return 1 }', 'api_test.go': 'package api\nfunc TestWorks(t *testing.T) {if Value()!=1 {t.Fatal("bad")}}'}, 'go:.::package=api::TestWorks'),
        ]
        for old, identity in cases:
            with self.subTest(identity=identity):
                head = declare({}, subject=identity, behavior_deleted=True,
                               reason='The legacy behavior has been removed from the product.',
                               deleting_change='This PR deletes the value implementation and its tests.')
                result = report(old, head)
                self.assertTrue(result.success)
                self.assertEqual(len(result.findings), 1)
                self.assertTrue(result.findings[0].allowed)

    def test_deleted_behavior_requires_explicit_state_citation_and_no_replacements(self):
        cases = [
            {'behavior_deleted': True},
            {'deleting_change': 'This PR removes the legacy implementation.'},
            {'behavior_deleted': False, 'deleting_change': 'This PR.'},
            {'behavior_deleted': 'true', 'deleting_change': 'This PR.'},
            {'behavior_deleted': 1, 'deleting_change': 'This PR.'},
            {'behavior_deleted': True, 'deleting_change': ' '},
            {'behavior_deleted': True, 'deleting_change': 123},
            {'behavior_deleted': True, 'deleting_change': 'This PR.', 'replacements': [TEST]},
            {'behavior_deleted': True, 'deleting_change': 'This PR.', 'renamed_to': TEST},
            {'behavior_deleted': True, 'deleting_change': 'This PR.', 'kind': 'disabled'},
            {'behavior_deleted': True, 'deleting_change': 'This PR.', 'test': None, 'job': JOB},
        ]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(GuardError):
                report(rust(), declare({}, **options))

    def test_deleted_behavior_still_requires_reason_and_issue(self):
        for options in ({'reason': ''}, {'reason': ' '}, {'issue': 0}, {'issue': True}):
            with self.subTest(options=options), self.assertRaises(GuardError):
                report(rust(), declare({}, behavior_deleted=True,
                                      deleting_change='This PR deletes the legacy behavior.', **options))

    def test_duplicate_json_keys_and_boolean_version_are_rejected(self):
        for source in ('{"version":1,"changes":[],"changes":[]}', '{"version":true,"changes":[]}'):
            with self.subTest(source=source), self.assertRaises(GuardError):
                report(rust(), {**rust(), 'ci/test-changes.json': source})

    def test_nonexistent_issue_does_not_allow_removal(self):
        result = report(rust(), declare({'Cargo.toml': MANIFEST, 'src/lib.rs': ''}, issue=987,
                        behavior_deleted=True, deleting_change='This PR removes the legacy behavior.'))
        self.assertFalse(result.success)
        self.assertIn('not an existing issue', result.errors[0])

    def test_issue_api_outage_keeps_findings_visible(self):
        def unavailable(_):
            raise GuardError('Cannot verify issue: GitHub HTTP 403')

        result = analyze_files(rust(), declare({'Cargo.toml': MANIFEST, 'src/lib.rs': ''},
                               behavior_deleted=True, deleting_change='This PR removes the legacy behavior.'), unavailable)
        self.assertFalse(result.success)
        self.assertEqual(len(result.findings), 1)
        self.assertFalse(result.findings[0].allowed)
        self.assertIn('GitHub HTTP 403', result.errors[0])

    def test_stale_and_inherited_entries_are_rejected(self):
        self.assertFalse(report(rust(), declare(rust())).success)
        old = declare(rust())
        new = {**old, 'src/lib.rs': ''}
        result = report(old, new)
        self.assertFalse(result.success)
        self.assertEqual(result.errors, [])
        self.assertFalse(result.findings[0].allowed)

    def test_unrelated_later_pr_preserves_history_without_validation_or_warnings(self):
        old = declare(rust(), subject='rust:old::test=removed::old_test',
                      renamed_to='rust:old::test=removed::replacement', issue=987)
        new = {**old, 'CONTRIBUTING.md': 'Unrelated documentation update.\n'}
        # No issue callback: history must not trigger a network request, target
        # lookup, stale-entry error, or finding, even after targets disappear.
        result = analyze_files(old, new)
        self.assertTrue(result.success)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.findings, [])

    def test_record_edits_deletions_and_reordering_fail(self):
        old = declare(rust())
        record = json.loads(old['ci/test-changes.json'])
        record['changes'].append({**record['changes'][0], 'test': TEST + '_old'})
        old['ci/test-changes.json'] = json.dumps(record)
        changed_reason = deepcopy(record)
        changed_reason['changes'][0]['reason'] = 'Rewritten history.'
        changed_type = deepcopy(record)
        changed_type['changes'][0]['issue'] = 42.0
        for changes in (changed_reason['changes'], record['changes'][1:],
                        list(reversed(record['changes'])), changed_type['changes'], []):
            with self.subTest(changes=changes):
                new = {**old, 'ci/test-changes.json': json.dumps(dict(version=1, changes=changes))}
                result = report(old, new)
                self.assertFalse(result.success)
                self.assertEqual(result.findings, [])
                self.assertIn('historical entries', result.errors[0])
        self.assertFalse(report(old, rust()).success)

    def test_record_formatting_and_key_order_are_not_edits(self):
        old = declare(rust())
        record = json.loads(old['ci/test-changes.json'])
        new = {**old, 'ci/test-changes.json': json.dumps(record, sort_keys=True, indent=2)}
        self.assertTrue(analyze_files(old, new).success)

    def test_appending_same_subject_and_kind_declares_only_the_new_change(self):
        old = declare(rust(), behavior_deleted=True,
                      deleting_change='This PR removes the reinstated legacy behavior.')
        record = json.loads(old['ci/test-changes.json'])
        # A repeated subject/kind (even an identical record) may be appended
        # for a later PR; history itself can never authorize that reduction.
        record['changes'].append(deepcopy(record['changes'][0]))
        new = {**old, 'src/lib.rs': '', 'ci/test-changes.json': json.dumps(record)}
        result = report(old, new)
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.findings[0].allowed)
        self.assertTrue(analyze_files(new, {**new, 'README.md': 'Later PR.\n'}).success)

    def test_duplicate_new_declarations_remain_rejected(self):
        old = declare(rust())
        record = json.loads(old['ci/test-changes.json'])
        record['changes'] *= 3
        new = {**old, 'src/lib.rs': '', 'ci/test-changes.json': json.dumps(record)}
        with self.assertRaisesRegex(GuardError, 'duplicate declaration'):
            report(old, new)

    def test_schema_rejects_wildcards_empty_reason_and_unknown_fields(self):
        for options in ({'reason': ''}, {'test': '*'}, {'issue': True}, {'extra': 'typo'}):
            with self.subTest(options=options), self.assertRaises(GuardError):
                report(rust(), declare({'Cargo.toml': MANIFEST, 'src/lib.rs': ''}, **options))

    def test_github_issue_api_rejects_pull_requests_and_api_errors(self):
        value = {'number': 42, 'repository_url': 'https://api.github.com/repos/example/repository'}
        with patch('urllib.request.urlopen', return_value=io.BytesIO(json.dumps(value).encode())):
            self.assertTrue(github_issue_exists('example/repository', 42))
        with patch('urllib.request.urlopen', return_value=io.BytesIO(json.dumps({**value, 'pull_request': {}}).encode())):
            self.assertFalse(github_issue_exists('example/repository', 42))
        with patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError('', 403, '', {}, None)):
            with self.assertRaisesRegex(GuardError, 'HTTP 403'):
                github_issue_exists('example/repository', 42)


class GitFixtureTests(unittest.TestCase):
    def test_cli_compares_committed_trees_not_working_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()

            git('init', '-q')
            git('config', 'user.name', 'Inventory fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            for name, source in rust().items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            git('add', '.')
            git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', base)
            (root / 'src/lib.rs').write_text('')
            git('add', '.')
            git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'remove test')
            head = git('rev-parse', 'HEAD')
            (root / 'src/lib.rs').write_text(rust()['src/lib.rs'])
            self.assertEqual(read_revision(root, head)[1]['src/lib.rs'], '')
            with patch('sys.stdout', new=io.StringIO()) as output:
                self.assertEqual(main(['--repo', str(root), '--base', base, '--head', head]), 1)
                self.assertIn('UNDECLARED removed', output.getvalue())
            event = {'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}
            self.assertEqual(event_revisions(root, 'pull_request', event), (base, head))


class LocalRevisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = patch.dict(os.environ, {'GITHUB_ACTIONS': 'false', 'GITHUB_EVENT_PATH': ''})
        environment.start()
        self.addCleanup(environment.stop)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Inventory fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        for name, source in rust().items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'common ancestor')
        self.base = self.git('rev-parse', 'HEAD')
        (self.root / 'src/lib.rs').write_text('')
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'branch removes test')
        self.head = self.git('rev-parse', 'HEAD')
        tree = self.git('rev-parse', self.base + '^{tree}')
        self.main = self.git('-c', 'commit.gpgsign=false', 'commit-tree', tree, '-p', self.base, '-m', 'main diverges')
        self.unrelated = self.git('-c', 'commit.gpgsign=false', 'commit-tree', tree, '-m', 'unrelated history')
        self.git('update-ref', 'refs/remotes/origin/main', self.main)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def test_default_uses_merge_base_and_reports_the_branch_removal(self):
        self.assertEqual(comparison_revisions(self.root), (self.base, self.head, 'merge-base(HEAD, origin/main)'))
        with patch('sys.stdout', new=io.StringIO()) as output:
            self.assertEqual(main(['--repo', str(self.root)]), 1)
            self.assertIn('base = merge-base(HEAD, origin/main): ' + self.base, output.getvalue())
            self.assertIn('UNDECLARED removed', output.getvalue())

    def test_branch_only_base_cannot_pass_an_empty_comparison(self):
        for arguments in (['--base', 'HEAD'], ['--base', self.head, '--head', self.head]):
            with self.subTest(arguments=arguments), patch('sys.stderr', new=io.StringIO()) as error:
                self.assertEqual(main(['--repo', str(self.root), *arguments]), 2)
                self.assertIn('ancestor of both HEAD', error.getvalue())
                self.assertIn('origin/main', error.getvalue())

    def test_base_on_main_but_not_head_is_rejected(self):
        with self.assertRaisesRegex(GuardError, 'ancestor of both HEAD'):
            comparison_revisions(self.root, self.main)

    def test_unrelated_base_is_rejected(self):
        with self.assertRaisesRegex(GuardError, 'ancestor of both HEAD'):
            comparison_revisions(self.root, self.unrelated)

    def test_explicit_common_ancestor_and_historical_head_are_supported(self):
        self.assertEqual(comparison_revisions(self.root, self.base), (self.base, self.head, 'explicit common ancestor'))
        self.assertEqual(comparison_revisions(self.root, self.base, self.head), (self.base, self.head, 'explicit common ancestor'))

    def test_identical_comparison_revisions_are_rejected_after_ref_resolution(self):
        for base, head in ((self.base, self.base), ('HEAD^', self.base), (self.base, 'HEAD^')):
            with self.subTest(base=base, head=head), patch('sys.stdout', new=io.StringIO()) as output, patch('sys.stderr', new=io.StringIO()) as error:
                self.assertEqual(main(['--repo', str(self.root), '--base', base, '--head', head]), 2)
                self.assertIn('same commit (' + self.base + ')', error.getvalue())
                self.assertIn('refusing an empty comparison', error.getvalue())
                self.assertNotIn('PASS', output.getvalue())

    def test_default_and_base_only_empty_comparisons_pass(self):
        self.git('checkout', '--detach', self.base)
        for arguments in ([], ['--base', 'HEAD'], ['--base', self.base]):
            with self.subTest(arguments=arguments), patch('sys.stdout', new=io.StringIO()) as output:
                self.assertEqual(main(['--repo', str(self.root), *arguments]), 0)
                self.assertIn('nothing to compare', output.getvalue().lower())

    def test_empty_default_run_on_main_reports_nothing_to_compare(self):
        self.git('checkout', '-B', 'main', self.main)
        report_path = self.root / 'report.json'
        with patch('sys.stdout', new=io.StringIO()) as output:
            self.assertEqual(main(['--repo', str(self.root), '--json', str(report_path)]), 0)
            self.assertIn('nothing to compare', output.getvalue().lower())
        self.assertEqual(json.loads(report_path.read_text()),
                         dict(base=self.main, head=self.main, success=True, nothing_to_compare=True,
                              base_tests=None, head_tests=None, findings=[], errors=[]))

    def test_event_selected_empty_comparisons_pass(self):
        event_path = self.root / 'event.json'
        cases = [
            ('pull_request', {'pull_request': {'base': {'sha': self.main}, 'head': {'sha': self.base}}}),
            ('merge_group', {'merge_group': {'base_sha': self.base, 'head_sha': self.base}}),
            ('push', {'ref': 'refs/heads/main', 'before': self.base, 'after': self.base}),
        ]
        for name, event in cases:
            event_path.write_text(json.dumps(event))
            with self.subTest(event_name=name), patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': name, 'GITHUB_EVENT_PATH': str(event_path)}):
                with patch('sys.stdout', new=io.StringIO()) as output:
                    self.assertEqual(main(['--repo', str(self.root)]), 0)
                    self.assertIn('nothing to compare', output.getvalue().lower())

    def test_train_push_at_main_tip_reports_nothing_to_compare(self):
        self.git('checkout', '-B', 'train/fixture', self.main)
        event_path = self.root / 'event.json'
        event_path.write_text(json.dumps({'ref': 'refs/heads/train/fixture', 'before': '0' * 40,
                                         'after': self.main, 'repository': {'default_branch': 'main'}}))
        report_path = self.root / 'report.json'
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(event_path)}):
            with patch('sys.stdout', new=io.StringIO()) as output:
                self.assertEqual(main(['--repo', str(self.root), '--json', str(report_path)]), 0)
                self.assertIn('nothing to compare', output.getvalue().lower())
        self.assertEqual(json.loads(report_path.read_text()),
                         dict(base=self.main, head=self.main, success=True, nothing_to_compare=True,
                              base_tests=None, head_tests=None, findings=[], errors=[]))

    def test_manual_dispatch_uses_default_branch_merge_base_and_dispatched_head(self):
        self.git('update-ref', 'refs/remotes/origin/trunk', self.main)
        self.git('update-ref', '-d', 'refs/remotes/origin/main')
        (self.root / 'src/lib.rs').write_text(rust()['src/lib.rs'])
        self.git('add', '.')
        self.git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'later checkout restores test')
        restored = self.git('rev-parse', 'HEAD')
        event_path = self.root / 'event.json'
        event_path.write_text(json.dumps({'ref': 'fixture', 'repository': {'default_branch': 'trunk'}}))
        report_path = self.root / 'report.json'
        for head, expected_exit in ((self.head, 1), (restored, 0)):
            with self.subTest(head=head), patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                                                                 'GITHUB_EVENT_PATH': str(event_path), 'GITHUB_SHA': head}):
                self.assertEqual(comparison_revisions(self.root), (self.base, head, 'GitHub event'))
                with patch('sys.stdout', new=io.StringIO()) as output:
                    self.assertEqual(main(['--repo', str(self.root), '--json', str(report_path)]), expected_exit)
                    if expected_exit:
                        self.assertIn('UNDECLARED removed', output.getvalue())
                report = json.loads(report_path.read_text())
                self.assertEqual((report['base'], report['head']), (self.base, head))
                self.assertEqual(report['success'], expected_exit == 0)
                self.assertEqual(len(report['findings']), expected_exit)

    def test_manual_dispatch_on_default_branch_reports_nothing_to_compare(self):
        self.git('checkout', '-B', 'main', self.main)
        event_path = self.root / 'event.json'
        event_path.write_text(json.dumps({'ref': 'main', 'repository': {'default_branch': 'main'}}))
        report_path = self.root / 'report.json'
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                                     'GITHUB_EVENT_PATH': str(event_path), 'GITHUB_SHA': self.main}):
            with patch('sys.stdout', new=io.StringIO()) as output:
                self.assertEqual(main(['--repo', str(self.root), '--json', str(report_path)]), 0)
                self.assertIn('nothing to compare', output.getvalue().lower())
        self.assertEqual(json.loads(report_path.read_text()),
                         dict(base=self.main, head=self.main, success=True, nothing_to_compare=True,
                              base_tests=None, head_tests=None, findings=[], errors=[]))

    def test_explicit_base_must_also_precede_comparison_head(self):
        with self.assertRaisesRegex(GuardError, 'ancestor of the comparison head'):
            comparison_revisions(self.root, self.base, self.unrelated)

    def test_explicit_head_requires_a_base(self):
        with self.assertRaisesRegex(GuardError, 'requires --base'):
            comparison_revisions(self.root, head=self.head)

    def test_missing_origin_main_fails_with_fetch_guidance(self):
        self.git('update-ref', '-d', 'refs/remotes/origin/main')
        for base in (None, self.base):
            with self.subTest(base=base), self.assertRaisesRegex(GuardError, 'requires origin/main; fetch'):
                comparison_revisions(self.root, base)

    def test_local_run_ignores_event_file_without_actions_context(self):
        with patch.dict(os.environ, {'GITHUB_EVENT_PATH': str(self.root / 'missing-event.json')}):
            self.assertEqual(comparison_revisions(self.root)[:2], (self.base, self.head))

    def test_actions_requires_event_and_validates_checkout_ancestry(self):
        event_path = self.root / 'event.json'
        event = {'pull_request': {'base': {'sha': self.main}, 'head': {'sha': self.head}}}
        event_path.write_text(json.dumps(event))
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_EVENT_PATH': str(event_path)}):
            self.assertEqual(comparison_revisions(self.root), (self.base, self.head, 'GitHub event'))
            event['pull_request']['head']['sha'] = self.main
            event_path.write_text(json.dumps(event))
            with self.assertRaisesRegex(GuardError, 'event head must be in the checked-out HEAD'):
                comparison_revisions(self.root)
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_PATH': ''}):
            with self.assertRaisesRegex(GuardError, 'requires its event file'):
                comparison_revisions(self.root)

    def test_actions_rejects_event_base_outside_head_history(self):
        event_path = self.root / 'event.json'
        event_path.write_text(json.dumps({'merge_group': {'base_sha': self.main, 'head_sha': self.head}}))
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'merge_group', 'GITHUB_EVENT_PATH': str(event_path)}):
            with self.assertRaisesRegex(GuardError, 'event base must be an ancestor'):
                comparison_revisions(self.root)


def review_workflow(extra='', body='cargo test --workspace', matrix=''):
    source = 'on: pull_request\njobs:\n  rust:\n    name: Rust workspace\n    needs: [tests]\n    steps: []\n  tests:\n'
    source += extra + matrix + '    steps:\n      - name: Run tests\n        run: |\n'
    source += '\n'.join('          ' + line for line in body.splitlines()) + '\n'
    return {'.github/workflows/ci.yml': source}


class InventoryEdgeTests(unittest.TestCase):
    def test_include_only_lane_removal(self):
        before = review_workflow(matrix='    strategy:\n      matrix:\n        include:\n          - shard: first\n          - shard: second\n')
        after = review_workflow(matrix='    strategy:\n      matrix:\n        include:\n          - shard: first\n')
        result = analyze_files(before, after)
        self.assertTrue(any('second' in item.subject for item in result.findings))

    def test_job_and_step_false_conditions_disable_tests(self):
        before = review_workflow()
        for after in [review_workflow(extra='    if: false\n'), {path: source.replace('- name: Run tests', '- name: Run tests\n        if: false') for path, source in before.items()}]:
            with self.subTest(after=after):
                self.assertFalse(analyze_files(before, after).success)

    def test_test_profile_moved_between_literal_shell_arrays(self):
        before = review_workflow(body='ordinary=(contract)\noptimized=(snapshot)\nfor name in "${ordinary[@]}"; do\n  cargo test --exact "module::$name"\ndone\nfor name in "${optimized[@]}"; do\n  env CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --exact "module::$name"\ndone')
        after = {path: source.replace('ordinary=(contract)', 'ordinary=()').replace('optimized=(snapshot)', 'optimized=(snapshot contract)') for path, source in before.items()}
        result = analyze_files(before, after)
        self.assertFalse(result.success)
        self.assertTrue(all(finding.line > 1 for finding in result.findings))

    def test_new_platform_specific_test_is_added_coverage(self):
        before = {'Cargo.toml': MANIFEST, 'src/lib.rs': ''}
        after = {**before, 'src/lib.rs': '#[cfg(target_os="linux")] #[test] fn works(){ assert!(ready()); }'}
        self.assertTrue(analyze_files(before, after).success)

    def test_binary_autodiscovery_and_disabled_autobins(self):
        before = {'Cargo.toml': MANIFEST, 'src/bin/worker.rs': 'fn main() {} #[test] fn works(){assert!(ready());}'}
        self.assertEqual(len(inventory(before).tests), 1)
        self.assertFalse(analyze_files(before, {**before, 'Cargo.toml': before['Cargo.toml'] + 'autobins=false\n'}).success)

    def test_bare_python_skip_marker(self):
        before = {'tests/test_api.py': 'def test_works():\n assert ready()\n'}
        after = {'tests/test_api.py': '@pytest.mark.skip\n' + before['tests/test_api.py']}
        self.assertFalse(analyze_files(before, after).success)

    def test_go_unconditional_return(self):
        before = {'api_test.go': 'package api\nfunc TestWorks(t *testing.T){if !ready(){t.Fatal("bad")}}'}
        after = {'api_test.go': before['api_test.go'].replace('{if', '{return; if')}
        self.assertFalse(analyze_files(before, after).success)

    def test_internal_and_external_go_tests_have_distinct_identities(self):
        before = {'inside_test.go': 'package api\nfunc TestWorks(t *testing.T){t.Fatal("bad")}', 'outside_test.go': 'package api_test\nfunc TestWorks(t *testing.T){t.Fatal("bad")}'}
        self.assertEqual(len(inventory(before).tests), 2)

if __name__ == '__main__':
    unittest.main()
