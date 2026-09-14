#!/usr/bin/env python3
"""Independent acceptance and rejection controls for live memory evidence."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import tempfile

p = Path(__file__).with_name('observe-session-store-live-memory.py')
spec = importlib.util.spec_from_file_location('observer', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
checks=[]
def check(name,condition):
 assert condition,name
 checks.append(name)
for mode in ['async','durable']:
 for workload,descriptor in [('original','sessions=50000;preload=50000;steady=500x1800;burst=1000x60;epochs=8'),('boundary_control','boundary-control')]:
  text=f'opc-session-isolated-scale/v1;voters=3;mode={mode};clock=1900000000;{descriptor}'
  config={'isolated_scale':{'persistence':mode,'workload':workload},'members':[{}, {}, {}],'workload_schedule_sha256':'sha256:'+hashlib.sha256(text.encode()).hexdigest()}
  check(mode+workload+'canonical',m.scale_binding(config)['schedule_sha256']==config['workload_schedule_sha256'])
  for name,edit in [('extra-scale-key',lambda c:c['isolated_scale'].update(extra=True)),('wrong-mode',lambda c:c['isolated_scale'].update(persistence='fake')),('wrong-workload',lambda c:c['isolated_scale'].update(workload='fake')),('wrong-binding',lambda c:c.update(workload_schedule_sha256='sha256:'+'0'*64)),('wrong-voters',lambda c:c.update(members=[{},{}]))]:
   wrong=copy.deepcopy(config);edit(wrong)
   try:m.scale_binding(wrong)
   except (ValueError,KeyError):checks.append(mode+workload+name)
   else:raise AssertionError(name)
scale={'persistence':'async','workload':'original'}
schedule='sha256:'+hashlib.sha256(b'opc-session-isolated-scale/v1;voters=3;mode=async;clock=1900000000;sessions=50000;preload=50000;steady=500x1800;burst=1000x60;epochs=8').hexdigest()
start={'configuration':scale,'schedule_sha256':schedule,'driver_pid':14,'voter_pids':[11,12,13],'workspace':'/original-memory-parser-unit-control','started_unix_ns':100}
request={k:v for k,v in start.items() if k!='started_unix_ns'};request['sample_request_unix_ns']=200
records=[]
for index,pid in enumerate([11,12,13,14]):
 binding={'workspace':start['workspace'],'driver_pid':14,'persistence':'async','declared_workload':'original','schedule_sha256':schedule,'node_index':index if index<3 else 0}
 records.append({'pid':pid,'start_ticks':pid*10,'role':'voter' if index<3 else 'driver','sample_count':10,'configurations':{'hash':binding},'first_sample_unix_ns':90,'last_sample_unix_ns':210})
end={k:v for k,v in start.items() if k!='started_unix_ns'}
end.update(exact_workload_outcomes=1010000,successor_rotations=7,retained_epoch_representatives=8,joined_shutdown=True,full_cardinality=True,performance_acceptance=False,quiet_host_claim=False,phases=[{'completed_operations':900000},{'completed_operations':60000}],final_memory_sample={'request':request,'samples':[{'pid':r['pid'],'start_ticks':r['start_ticks'],'sampled_unix_ns':210} for r in records]})
with tempfile.TemporaryDirectory() as root:
 root=Path(root)
 def cover(events,observed):
  (root/'output.log').write_text('\n'.join(marker+json.dumps(event) for marker,event in events) + ('\n' if events else ''))
  return m.original_coverage(root,observed)['all_declared_processes_observed']
 markers=[('sdk_isolated_scale_started=',start),('sdk_isolated_scale_completed=',end)]
 check('full-positive-all-four-processes',cover(markers,records))
 check('no-events-not-coverage',not cover([],records))
 check('start-without-completion-not-coverage',not cover(markers[:1],records))
 check('completion-without-start-not-coverage',not cover(markers[1:],records))
 for index in range(4):
  check('missing-process-'+str(index),not cover(markers,[r for i,r in enumerate(records) if i!=index]))
 for name,edit in [('late-start-sample',lambda rs:rs[0].update(first_sample_unix_ns=101)),('missing-final-sample',lambda rs:rs[1].update(last_sample_unix_ns=199)),('wrong-role',lambda rs:rs[0].update(role='driver')),('wrong-incarnation',lambda rs:rs[0].update(start_ticks=999)),('wrong-mode',lambda rs:rs[0]['configurations']['hash'].update(persistence='durable'))]:
  wrong=copy.deepcopy(records);edit(wrong);check(name,not cover(markers,wrong))
 for name,edit in [('wrong-total',lambda e:e.update(exact_workload_outcomes=1009999)),('not-joined',lambda e:e.update(joined_shutdown=False)),('performance-claim',lambda e:e.update(performance_acceptance=True)),('wrong-phase-denominator',lambda e:e['phases'][0].update(completed_operations=500)),('stale-final-ack',lambda e:e['final_memory_sample']['samples'][0].update(sampled_unix_ns=199)),('wrong-ack-workspace',lambda e:e['final_memory_sample']['request'].update(workspace='elsewhere'))]:
  wrong=copy.deepcopy(end);edit(wrong);check(name,not cover([markers[0],('sdk_isolated_scale_completed=',wrong)],records))
# Final capture cannot acknowledge missing, stale or foreign-workspace evidence.
with tempfile.TemporaryDirectory() as temporary:
    check_root = Path(temporary)
    workspace = check_root / 'workspace'
    workspace.mkdir()
    local_request = copy.deepcopy(request)
    local_request['workspace'] = str(workspace)
    local_records = copy.deepcopy(records)
    for row in local_records:
        row['configurations']['hash']['workspace'] = str(workspace)
    (check_root / 'output.log').write_text(
        'sdk_isolated_scale_final_sample_required=' + json.dumps(local_request) + '\n')
    ack_path = workspace / 'isolated-memory-final.json'
    complete_line = (check_root / 'output.log').read_text()
    (check_root / 'output.log').write_text(complete_line[:-3])
    m.acknowledge_final_sample(check_root, local_records, check_root)
    check('partial-output-cannot-acknowledge', not ack_path.exists())
    (check_root / 'output.log').write_text(complete_line)
    m.acknowledge_final_sample(check_root, local_records[:-1], check_root)
    check('missing-driver-cannot-acknowledge', not ack_path.exists())
    stale_records = copy.deepcopy(local_records)
    stale_records[0]['last_sample_unix_ns'] = 199
    m.acknowledge_final_sample(check_root, stale_records, check_root)
    check('stale-voter-cannot-acknowledge', not ack_path.exists())
    try:
        m.acknowledge_final_sample(check_root, local_records, check_root / 'foreign')
    except ValueError:
        checks.append('foreign-workspace-cannot-acknowledge')
    else:
        raise AssertionError('foreign workspace acknowledged')
    m.acknowledge_final_sample(check_root, local_records, check_root)
    ack = json.loads(ack_path.read_text())
    check('exact-final-request-echoed', ack['request'] == local_request)
    check('four-exact-final-incarnations',
          {(r['pid'], r['start_ticks']) for r in ack['samples']} ==
          {(r['pid'], r['start_ticks']) for r in local_records})
    before = ack_path.read_bytes()
    m.acknowledge_final_sample(check_root, local_records, check_root)
    check('completed-acknowledgement-not-overwritten', ack_path.read_bytes() == before)

# Initial discovery must acknowledge all four live owners before the driver
# emits its workload-start marker; the strict late-start rejection above stays.
with tempfile.TemporaryDirectory() as temporary:
    check_root = Path(temporary)
    workspace = check_root / 'workspace'
    workspace.mkdir()
    initial_request = copy.deepcopy(request)
    initial_request['workspace'] = str(workspace)
    initial_records = copy.deepcopy(records)
    for row in initial_records:
        row['configurations']['hash']['workspace'] = str(workspace)
    line = 'sdk_isolated_scale_initial_sample_required=' + json.dumps(initial_request) + '\n'
    log = check_root / 'output.log'
    initial_path = workspace / 'isolated-memory-initial.json'
    log.write_text(line[:-2])
    m.acknowledge_initial_sample(check_root, initial_records, check_root)
    check('partial-initial-request-cannot-acknowledge', not initial_path.exists())
    log.write_text(line)
    m.acknowledge_final_sample(check_root, initial_records, check_root)
    check('initial-request-cannot-produce-final-ack',
          not (workspace / 'isolated-memory-final.json').exists())
    for index in range(4):
        m.acknowledge_initial_sample(check_root, initial_records[:index] + initial_records[index+1:], check_root)
        check('initial-missing-owner-' + str(index), not initial_path.exists())
        stale = copy.deepcopy(initial_records)
        stale[index]['last_sample_unix_ns'] = initial_request['sample_request_unix_ns'] - 1
        m.acknowledge_initial_sample(check_root, stale, check_root)
        check('initial-stale-owner-' + str(index), not initial_path.exists())
    try:
        m.acknowledge_initial_sample(check_root, initial_records, check_root / 'foreign')
    except ValueError:
        checks.append('foreign-initial-workspace-cannot-acknowledge')
    else:
        raise AssertionError('foreign initial workspace acknowledged')
    m.acknowledge_initial_sample(check_root, initial_records, check_root)
    initial_ack = json.loads(initial_path.read_text())
    check('initial-request-echoed-exactly', initial_ack['request'] == initial_request)
    check('initial-capture-all-four-incarnations',
          {(r['pid'], r['start_ticks']) for r in initial_ack['samples']} ==
          {(r['pid'], r['start_ticks']) for r in initial_records})
    check('initial-capture-follows-request',
          all(r['sampled_unix_ns'] >= initial_request['sample_request_unix_ns']
              for r in initial_ack['samples']))
    before = initial_path.read_bytes()
    m.acknowledge_initial_sample(check_root, initial_records, check_root)
    check('initial-acknowledgement-not-overwritten', initial_path.read_bytes() == before)
    check('initial-acknowledgement-does-not-complete-workload',
          not m.original_coverage(check_root, initial_records)['all_declared_processes_observed'])

print(json.dumps(dict(passed=len(checks), failed=0, scope='parser controls only')))
