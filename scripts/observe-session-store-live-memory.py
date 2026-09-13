#!/usr/bin/env python3
"""Measure live voters separately from the original workload driver on Linux.

Run inside the authorized build allocation with an existing fs-verity root.
The command after -- is the only process tree this program observes. It creates
no mounts and changes no host settings. Use a fresh evidence directory and a
short existing temporary workspace root, also supplied to the test as TMPDIR.
Samples, exact process/configuration identities, output and result hashes are
retained even when the workload fails. Process exit is never a zero-RSS sample.
A full run requires coverage from workload start through each final live sample.
This measures process memory; it does not establish a deployment RAM budget or
attribute anonymous memory to Rust, SQLite or allocator retention.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time



def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def scale_binding(config):
    scale = config.get('isolated_scale')
    if not isinstance(scale, dict) or set(scale) != {'persistence', 'workload'}:
        raise ValueError('missing or noncanonical explicit scale mode')
    mode, workload = scale['persistence'], scale['workload']
    if mode not in ('async', 'durable'):
        raise ValueError('unknown persistence mode')
    if workload == 'original':
        workload_descriptor = 'sessions=50000;preload=50000;steady=500x1800;burst=1000x60;epochs=8'
    elif workload == 'boundary_control':
        workload_descriptor = 'boundary-control'
    else:
        raise ValueError('unknown scale workload')
    descriptor = f'opc-session-isolated-scale/v1;voters=3;mode={mode};clock=1900000000;{workload_descriptor}'
    schedule = 'sha256:' + hashlib.sha256(descriptor.encode()).hexdigest()
    if config['workload_schedule_sha256'] != schedule or len(config['members']) != 3:
        raise ValueError('mode, clock, workload or three-voter schedule differs')
    return dict(persistence=mode, declared_workload=workload, schedule_sha256=schedule)


def fresh_descendants(latest, process_identity):
    """Follow only the explicitly owned controller's current /proc descendants."""
    stale = {p['pid']: p for p in latest['owned']}
    seeds = [p for p in stale.values() if p['ppid'] not in stale]
    pending = []
    for seed in seeds:
        try:
            if process_identity(seed['pid']) == seed['start_ticks']:
                pending.append(seed['pid'])
        except (FileNotFoundError, ProcessLookupError):
            pass
    owned = {}
    while pending:
        pid = pending.pop()
        if pid in owned:
            continue
        try:
            proc = Path(f'/proc/{pid}')
            raw = (proc / 'stat').read_text()
            tail = raw.rpartition(') ')[2].split()
            parent, start = int(tail[1]), int(tail[19])
            seed = stale.get(pid)
            is_seed = seed and seed in seeds and seed['start_ticks'] == start
            if not is_seed and parent not in owned:
                continue
            owned[pid] = dict(pid=pid, ppid=parent, start_ticks=start,
                              name=raw.partition('(')[2].rpartition(')')[0])
            # libtest can spawn children from a test thread, not the main thread.
            for task in (proc / 'task').iterdir():
                try:
                    pending.extend(int(child) for child in (task / 'children').read_text().split())
                except (FileNotFoundError, ProcessLookupError):
                    pass
        except (FileNotFoundError, ProcessLookupError):
            pass
    return owned


def boundary_coverage(check, records):
    expected = {}
    for line in (check / 'output.log').read_text(errors='replace').splitlines():
        _, marker, payload = line.partition('sdk_isolated_scale_boundary=')
        if not marker:
            continue
        event = json.loads(payload)
        if event['full_cardinality'] or event['performance_acceptance']:
            raise ValueError('boundary event declared qualification')
        for phase, key in [('live', 'voter_pids'), ('cold', 'cold_voter_pids')]:
            if len(set(event[key])) != 3:
                raise ValueError('boundary voter cardinality differs')
            for pid in event[key]:
                expected[pid] = dict(role='voter', phase=phase, configuration=event['configuration'],
                                     workspace=event['workspace'], driver_pid=event['driver_pid'])
    observed = {r['pid']: r for r in records if r['role'] == 'voter' and r['sample_count']}
    missing = []
    for pid, declaration in expected.items():
        record = observed.get(pid)
        if not record:
            missing.append(pid)
            continue
        if not any(binding['workspace'] == declaration['workspace']
                   and binding['persistence'] == declaration['configuration']['persistence']
                   and binding['declared_workload'] == declaration['configuration']['workload']
                   and binding['driver_pid'] == declaration['driver_pid']
                   for binding in record['configurations'].values()):
            raise ValueError('sampled mode/workspace differs from completed boundary event')
        record['boundary_phase'] = declaration['phase']
    return dict(expected_voter_incarnations=len(expected), missing_pids=missing,
                all_declared_voters_observed=bool(expected) and not missing)


def events(check, marker):
    # Qualification voters send their verbose stderr to owned files; these
    # markers contain only bounded driver summaries. Keep historical output.
    path = check / 'output.log'
    if not path.exists():
        return []
    result = []
    for line in path.read_text(errors='replace').splitlines(keepends=True):
        # The output relay may still be writing its final line. Only parse
        # complete records; an incomplete completion never counts as proof.
        if not line.endswith('\n'):
            continue
        _, found, payload = line.partition(marker)
        if found:
            result.append(json.loads(payload))
    return result


def matching_original_records(event, records):
    workspace = str(Path(event['workspace']))
    scale = event['configuration']
    if scale.get('workload') != 'original' or len(set(event['voter_pids'])) != 3:
        raise ValueError('full measurement must bind three distinct Original voters')
    if event['driver_pid'] in event['voter_pids']:
        raise ValueError('driver cannot be a voter')
    expected = [(pid, 'voter') for pid in event['voter_pids']] + [(event['driver_pid'], 'driver')]
    matched = []
    for pid, role in expected:
        candidates = [r for r in records if r['pid'] == pid and r['role'] == role and r['sample_count']]
        candidates = [r for r in candidates if any(
            c['workspace'] == workspace and c['driver_pid'] == event['driver_pid']
            and c['persistence'] == scale['persistence'] and c['declared_workload'] == 'original'
            and c['schedule_sha256'] == event['schedule_sha256']
            for c in r['configurations'].values())]
        if len(candidates) != 1:
            return None
        matched.append(candidates[0])
    voters = [r for r in matched if r['role'] == 'voter']
    if {c['node_index'] for r in voters for c in r['configurations'].values()} != {0, 1, 2}:
        raise ValueError('full voter node indexes differ')
    return matched


def acknowledge_final_sample(check, records, workspace_root):
    for event in events(check, 'sdk_isolated_scale_final_sample_required='):
        matched = matching_original_records(event, records)
        if not matched or any(r.get('last_sample_unix_ns', 0) < event['sample_request_unix_ns'] for r in matched):
            continue
        workspace = Path(event['workspace']).resolve(strict=True)
        if not workspace.is_relative_to(workspace_root):
            raise ValueError('acknowledgement outside owned measurement workspace')
        path = workspace / 'isolated-memory-final.json'
        if path.exists():
            continue
        samples = [dict(pid=r['pid'], start_ticks=r['start_ticks'], sampled_unix_ns=r['last_sample_unix_ns']) for r in matched]
        payload = dict(request=event, samples=samples)
        encoded = json.dumps(payload, sort_keys=True).encode()
        if len(encoded) > 4096:
            raise ValueError('final memory acknowledgement exceeds its bound')
        temporary = workspace / '.isolated-memory-final.tmp'
        with temporary.open('xb') as stream:
            stream.write(encoded)
        temporary.rename(path)


def original_coverage(check, records):
    started = events(check, 'sdk_isolated_scale_started=')
    completed = events(check, 'sdk_isolated_scale_completed=')
    campaigns = []
    for event in started:
        matched = matching_original_records(event, records)
        finals = [end for end in completed if end['workspace'] == event['workspace']
                  and end['driver_pid'] == event['driver_pid'] and end['voter_pids'] == event['voter_pids']
                  and end['configuration'] == event['configuration'] and end['schedule_sha256'] == event['schedule_sha256']]
        failures = []
        if not matched:
            failures.append('one or more declared process incarnations missing')
        elif any(r.get('first_sample_unix_ns', 2**64) > event['started_unix_ns'] for r in matched):
            failures.append('sampling began after workload start')
        if len(finals) != 1:
            failures.append('exact completion event absent or duplicated')
        else:
            end = finals[0]
            if end['exact_workload_outcomes'] != 1010000 or end['successor_rotations'] != 7 or end['retained_epoch_representatives'] != 8:
                failures.append('original cardinality differs')
            if not end['joined_shutdown'] or not end['full_cardinality'] or end['performance_acceptance'] or end['quiet_host_claim']:
                failures.append('completion scope differs')
            if [p['completed_operations'] for p in end['phases']] != [900000, 60000]:
                failures.append('phase cardinalities differ')
            ack = end.get('final_memory_sample', {})
            request = ack.get('request', {})
            if any(request.get(k) != event[k] for k in ('workspace', 'driver_pid', 'voter_pids', 'configuration', 'schedule_sha256')):
                failures.append('final acknowledgement identity differs')
            if matched:
                observed = {(r['pid'], r['start_ticks']) for r in matched}
                samples = ack.get('samples', [])
                if len(samples) != 4 or {(r['pid'], r['start_ticks']) for r in samples} != observed:
                    failures.append('final acknowledgement process incarnation differs')
                if any(r['sampled_unix_ns'] < request.get('sample_request_unix_ns', 2**64) for r in samples):
                    failures.append('final acknowledgement reused a prior sample')
                if any(r['last_sample_unix_ns'] < request.get('sample_request_unix_ns', 2**64) for r in matched):
                    failures.append('sample ledger does not cover the final capture')
        campaigns.append(dict(workspace=event['workspace'], configuration=event['configuration'], failures=failures,
                              exact_process_coverage=not failures))
    return dict(started_campaigns=len(started), completed_campaigns=len(completed), campaigns=campaigns,
                all_declared_processes_observed=bool(started) and len(started) == len(completed)
                  and all(not item['failures'] for item in campaigns))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-directory', required=True, type=Path)
    parser.add_argument('--workspace-root', required=True, type=Path)
    parser.add_argument('--worktree', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('an owned qualification command is required after --')
    W = args.worktree.resolve(strict=True)
    workspace_root = args.workspace_root.resolve(strict=True)
    evidence = args.evidence_directory.resolve()
    evidence.mkdir(mode=0o700)
    check = evidence
    module_path = W / 'scripts/observe-session-store-isolated-memory.py'
    spec = importlib.util.spec_from_file_location('session_memory_parser', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = dict(command=command, worktree=str(W), workspace_root=str(workspace_root),
                    observer_sha256=digest_file(__file__),
                    memory_parser_sha256=digest_file(module_path),
                    scope='separate live voter processes and external workload driver',
                    interval_seconds=0.1,
                    discovery='fresh descendants of the command started by this observer, including test threads',
                    read_only_sampling=True,
                    final_capture_acknowledgement='one atomic JSON file in the verified owned fixture workspace',
                    quiet_host_claim=False, deployment_memory_qualified=False,
                    performance_acceptance=False, declared_workload_is_not_completion_evidence=True,
                    affinity=sorted(os.sched_getaffinity(0)),
                    cargo_build_jobs=os.environ.get('CARGO_BUILD_JOBS'),
                    host_load_average=os.getloadavg())
    (evidence / 'command.json').write_text(json.dumps(manifest, indent=2) + '\n')
    command_process = subprocess.Popen(command, cwd=W, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    reader_errors = []

    def relay_output():
        try:
            with (evidence / 'output.log').open('xb') as log:
                for line in command_process.stdout:
                    log.write(line)
                    log.flush()
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
        except Exception as error:
            reader_errors.append(str(error))

    reader = threading.Thread(target=relay_output)
    reader.start()
    seed = dict(pid=command_process.pid, ppid=os.getpid(), start_ticks=module.process_identity(command_process.pid))
    latest = dict(owned=[seed])
    identities, errors, executable_hashes = {}, [], {}
    latest_utc = None
    transient_exits = {}
    legacy_voter_incarnations = set()
    try:
        with (evidence / 'samples.jsonl').open('x') as output:
            while command_process.poll() is None:
                try:
                    if latest:
                        latest_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        owned = fresh_descendants(latest, module.process_identity)
                        for process in owned.values():
                            if process['name'] != 'opc-session-quo':
                                continue
                            pid, start = process['pid'], process['start_ticks']
                            stage = 'process_identity'
                            try:
                                if module.process_identity(pid) != start:
                                    continue
                                stage = 'executable'
                                executable = Path(f'/proc/{pid}/exe').resolve(strict=True)
                                if not executable.is_relative_to(W / 'target') or executable.name != 'opc-session-quorum-node':
                                    raise ValueError('voter executable outside owned SDK target')
                                stage = 'configuration'
                                args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                                config_path = Path(os.fsdecode(args[args.index(b'--config') + 1]))
                                config_bytes = config_path.read_bytes()
                                config = json.loads(config_bytes)
                                workspace = Path(config['workspace_directory']).resolve(strict=True)
                                if not workspace.is_relative_to(workspace_root) or not config_path.resolve(strict=True).is_relative_to(workspace):
                                    raise ValueError('scale configuration outside owned short-path workspace')
                                if config.get('isolated_scale') is None:
                                    legacy_voter_incarnations.add((pid, start))
                                    continue
                                binding = scale_binding(config)
                                stage = 'driver_identity'
                                driver = owned[process['ppid']]
                                driver_exe = Path(f'/proc/{driver["pid"]}/exe').resolve(strict=True)
                                if not driver_exe.is_relative_to(W / 'target') or not driver_exe.name.startswith('qualification_mtls_multiprocess-'):
                                    raise ValueError('external driver executable differs')
                                config_hash = hashlib.sha256(config_bytes).hexdigest()
                                for target, path, role in [(process, executable, 'voter'), (driver, driver_exe, 'driver')]:
                                    identity = (target['pid'], target['start_ticks'])
                                    if path not in executable_hashes:
                                        stage = 'executable_hash'
                                        executable_hashes[path] = digest_file(path)
                                    if identity not in identities:
                                        identities[identity] = dict(pid=identity[0], start_ticks=identity[1], role=role,
                                            executable=str(path), executable_sha256=executable_hashes[path],
                                            sample_count=0, maximum_sample_gap_ns=None, last_sample_monotonic_ns=None,
                                            configurations={})
                                    record = identities[identity]
                                    if role == 'voter' and record['configurations'] and config_hash not in record['configurations']:
                                        raise ValueError('live voter configuration changed')
                                    record['configurations'][config_hash] = dict(**binding, config_path=str(config_path),
                                        node_index=config['node_index'], workspace=str(workspace),
                                        driver_pid=driver['pid'], driver_start_ticks=driver['start_ticks'])
                            except (FileNotFoundError, ProcessLookupError):
                                key = f'{pid}:{start}:{stage}'
                                transient_exits[key] = transient_exits.get(key, 0) + 1
                                continue
                            except Exception as error:
                                errors.append(dict(pid=pid, start_ticks=start, stage=stage, error=str(error)))
                        for identity, record in identities.items():
                            try:
                                if identity[0] not in owned or owned[identity[0]]['start_ticks'] != identity[1]:
                                    continue
                                sample = module.memory_sample(*identity)
                                sample.update(sampled_unix_ns=time.time_ns(), role=record['role'], utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), ownership_sampler_utc=latest_utc)
                                previous = record['last_sample_monotonic_ns']
                                if previous is not None:
                                    gap = sample['monotonic_ns'] - previous
                                    record['maximum_sample_gap_ns'] = max(record['maximum_sample_gap_ns'] or 0, gap)
                                record.setdefault('first_sample_unix_ns', sample['sampled_unix_ns'])
                                record['last_sample_unix_ns'] = sample['sampled_unix_ns']
                                record['last_sample_monotonic_ns'] = sample['monotonic_ns']
                                record['sample_count'] += 1
                                for field in ('smaps_rss_kib', 'smaps_pss_kib', 'vmhwm_estimate_kib'):
                                    key = 'maximum_observed_' + field
                                    record[key] = max(record.get(key, 0), sample[field])
                                output.write(json.dumps(sample) + '\n');output.flush()
                            except (FileNotFoundError, ProcessLookupError):
                                # An exit is never a zero-memory observation.
                                pass
                            except Exception as error:
                                errors.append(dict(pid=identity[0], start_ticks=identity[1], stage='sample', error=str(error)))
                except FileNotFoundError:
                    pass
                try:
                    acknowledge_final_sample(check, list(identities.values()), workspace_root)
                except Exception as error:
                    errors.append(dict(stage='final_capture', error=str(error)))
                time.sleep(0.1)
    except Exception as error:
        errors.append(dict(stage='observer_loop', error=str(error)))
    exit_code = command_process.wait()
    reader.join()
    command_process.stdout.close()
    errors.extend(dict(stage='output', error=error) for error in reader_errors)
    coverage = boundary_coverage(check, list(identities.values()))
    full = original_coverage(check, list(identities.values()))
    result = dict(**manifest, boundary_coverage=coverage, original_coverage=full, transient_exits=transient_exits, legacy_voter_incarnations_skipped=sorted(legacy_voter_incarnations), finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  processes=list(identities.values()), errors=errors, transient_peaks_may_be_missed=True,
                  measurement_observed=bool(identities) and all(r['sample_count'] for r in identities.values()) and not errors and (coverage['all_declared_voters_observed'] or full['all_declared_processes_observed']),
                  full_cardinality_observed=full['all_declared_processes_observed'],
                  cardinality_qualification=False,
                  exit_code=exit_code, output_sha256=digest_file(evidence / 'output.log'),
                  samples_sha256=digest_file(evidence / 'samples.jsonl'),
                  command_sha256=digest_file(evidence / 'command.json'))
    (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(evidence=str(evidence), processes=len(identities), errors=len(errors),
                         deployment_memory_qualified=False)), flush=True)
    return exit_code or (0 if result['measurement_observed'] else 1)


if __name__ == '__main__':
    raise SystemExit(main())
