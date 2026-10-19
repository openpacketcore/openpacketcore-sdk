#!/usr/bin/env python3
"""Linux integration contracts for the private fs-verity filesystem owner.

These tests mount real images and require the same passwordless mount, chown,
umount and losetup privileges as the harness. Fixtures always clean their own
resources, including the leftovers from a deliberately interrupted old helper.
"""

import fcntl
import importlib.util
import json
import os
from pathlib import Path
import resource
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "ci/setup-fsverity-tmp.sh"
SPEC = importlib.util.spec_from_file_location("fsverity_runtime", HARNESS.with_name("fsverity-runtime.py"))
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


def privileged(*args):
    return subprocess.run(
        ["/usr/bin/sudo", "-n", *map(str, args)], check=True,
        capture_output=True, text=True, timeout=10,
    ).stdout


def parent_death_guard():
    parent = os.getpid()
    libc = RUNTIME.ctypes.CDLL(None, use_errno=True)

    def arm():
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            raise OSError(RUNTIME.ctypes.get_errno(), "cannot bind fixture launcher to test runner")
        if os.getppid() != parent:
            os.kill(os.getpid(), signal.SIGKILL)

    return arm


def start_owner(*arguments, **options):
    return subprocess.Popen(*arguments, preexec_fn=parent_death_guard(), **options)


class SafetyTests(unittest.TestCase):
    """Controlled races use ordinary fixture files, never shared devices."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fsverity-safety-")
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner"
        self.runner.mkdir(mode=0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def candidate(self, name, parent=None):
        path = (parent or self.runner) / (RUNTIME.PREFIX + name)
        path.mkdir(mode=0o700)
        (path / "ext4.img").write_bytes(b"fixture-owned image")
        (path / "tmp").mkdir(mode=0o700)
        if hasattr(RUNTIME, "mark_owned"):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                RUNTIME.mark_owned(descriptor)
            finally:
                os.close(descriptor)
        return path

    def guardian(self):
        guardian = RUNTIME.Guardian(-1)
        guardian.inventory = lambda **_kwargs: ([], [])
        return guardian

    def interrupted_root_helper(self, phase, corruption=None):
        directory = self.runner / (RUNTIME.PREFIX + "root-helper-stop-" + phase)
        if not phase.startswith("create"):
            self.candidate("root-helper-stop-" + phase)
        report = self.root / "stopped-helper.json"
        report.write_text("{}")
        program = '''
import importlib.util,json,os,sys
path,report,phase,corruption,*arguments=sys.argv[1:]
spec=importlib.util.spec_from_file_location('runtime',path)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
original_chown,original_rename,original_unlink=runtime.os.fchown,runtime.rename_new,runtime.os.unlink
original_mkdir,original_rmdir=runtime.os.mkdir,runtime.os.rmdir
original_xattr=runtime.os.setxattr
original_protected=runtime.protected_directory
state={}
@runtime.contextmanager
def protected(*args,**kwargs):
    with original_protected(*args,**kwargs) as fd:
        state['stage']=os.readlink('/proc/self/fd/'+str(fd));state['stage_identity']=runtime.identity(fd)
        yield fd
def stop():
    if corruption:
        fd=os.open(state['stage'],os.O_RDONLY|os.O_DIRECTORY)
        record=json.loads(os.getxattr(fd,runtime.STAGING_ATTRIBUTE))
        if corruption=='owner': record['owner']='another checkout'
        elif corruption=='uid': record['uid']+=1
        elif corruption in ('directory','image','parent'): record[corruption][1]+=1
        elif corruption=='live':
            record['pid']=int(arguments[-2])
            record['start']=runtime.process_stat(record['pid'])[1]
        os.setxattr(fd,runtime.STAGING_ATTRIBUTE,json.dumps(record).encode());os.close(fd)
    with open(report,'w') as stream: json.dump(state,stream)
    os._exit(77)
def chown(fd,uid,gid):
    result=original_chown(fd,uid,gid)
    if uid==0 and runtime.stat.S_ISDIR(os.fstat(fd).st_mode):
        state['directory']=os.readlink('/proc/self/fd/'+str(fd))
        state['directory_identity']=runtime.identity(fd)
        if phase=='freeze': stop()
    return result
def rename(source,name,destination,new_name):
    result=original_rename(source,name,destination,new_name)
    if new_name=='runtime':
        state['directory']=os.readlink('/proc/self/fd/'+str(destination))+'/runtime'
        state['directory_identity']=runtime.Guardian.entry_identity(destination,'runtime')
        if phase=='moved': stop()
    if name=='runtime' and phase=='create-published':
        state['directory']=os.readlink('/proc/self/fd/'+str(destination))+'/'+new_name
        state['directory_identity']=runtime.Guardian.entry_identity(destination,new_name)
        stop()
    return result
def unlink(name,*args,**kwargs):
    result=original_unlink(name,*args,**kwargs)
    if name=='ext4.img' and phase=='partial': stop()
    return result
def mkdir(name,*args,**kwargs):
    result=original_mkdir(name,*args,**kwargs)
    if name=='runtime' and phase=='create-mkdir':
        fd=kwargs['dir_fd'];state['directory']=os.readlink('/proc/self/fd/'+str(fd))+'/runtime'
        info=os.stat('runtime',dir_fd=fd,follow_symlinks=False)
        state['directory_identity']=[info.st_dev,info.st_ino]
        assert runtime.stat.S_IMODE(info.st_mode)==0 and info.st_uid==0
        stop()
    if name=='tmp' and phase=='create-partial':
        fd=kwargs['dir_fd'];state['directory']=os.readlink('/proc/self/fd/'+str(fd))
        state['directory_identity']=runtime.identity(fd);stop()
    return result
def rmdir(name,*args,**kwargs):
    result=original_rmdir(name,*args,**kwargs)
    if name=='tmp' and phase=='empty': stop()
    return result
def xattr(fd,name,value):
    if phase=='unmarked' and name==getattr(runtime,'STAGING_ATTRIBUTE','') and 'action' in json.loads(value):
        state['stage']=os.readlink('/proc/self/fd/'+str(fd));state['stage_identity']=runtime.identity(fd)
        state['directory']=state['stage']+'/runtime';stop()
    return original_xattr(fd,name,value)
runtime.protected_directory=protected;runtime.os.fchown=chown
runtime.rename_new=rename;runtime.os.unlink=unlink
runtime.os.mkdir=mkdir;runtime.os.rmdir=rmdir
runtime.os.setxattr=xattr
if phase=='create-mkdir': os.umask(0o777)
if phase=='observe':
    state=json.load(open(report))
    if corruption=='mounted':
        runtime.Guardian.inventory=lambda *a,**k:([],[{'target':state['directory']+'/tmp'}])
    else:
        image=os.stat(state['directory']+'/ext4.img')
        runtime.Guardian.inventory=lambda *a,**k:([{'name':'/dev/loop-test',
            'back-maj:min':str(os.major(image.st_dev))+':'+str(os.minor(image.st_dev)),
            'back-ino':image.st_ino}],[])
sys.argv=[path,*arguments];runtime.main()
'''
        original_popen = subprocess.Popen
        observing = False
        held = []
        if corruption == "locked":
            held.append(os.open(directory, os.O_RDONLY | os.O_DIRECTORY))
        elif corruption == "leased":
            held.append(os.open(directory / "ext4.img", os.O_PATH))

        def interrupted(command, *args, **kwargs):
            if "--privileged" in command:
                command = ["sudo", "-n", "python3", "-I", "-c", program,
                           str(HARNESS.with_name("fsverity-runtime.py")), str(report),
                           "observe" if observing else phase, corruption or "",
                           *command[command.index("--privileged"):]]
            return original_popen(command, *args, **kwargs)

        # An isolated ordinary-file runtime: there are no mounts or loop
        # devices to mutate. The helper really exits between its syscalls.
        try:
            with patch.object(RUNTIME.subprocess, "Popen", side_effect=interrupted):
                with self.assertRaises((RuntimeError, ValueError)):
                    if phase.startswith("create"):
                        parent = os.open(self.runner, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            RUNTIME.privileged_request("create", [parent], name=directory.name)
                        finally:
                            os.close(parent)
                    else:
                        self.guardian().sweep(self.runner)
            state = json.loads(report.read_text())
            self.assertIn("stage", state, "did not reach the helper interruption")
            if corruption == "locked":
                fcntl.flock(held[0], fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif corruption == "leased":
                held.append(os.open(f"/proc/self/fd/{held[0]}", os.O_RDONLY))
            if corruption in ("attached", "mounted"):
                observing = True
                with patch.object(RUNTIME.subprocess, "Popen", side_effect=interrupted):
                    self.guardian().sweep(self.runner)
            else:
                self.guardian().sweep(self.runner)
            remaining = privileged("python3", "-c", """
import json,os,sys
state=json.load(open(sys.argv[1]))
print(json.dumps([p for p in (state['stage'],state['directory']) if os.path.exists(p)]))
""", report)
            if corruption:
                self.assertTrue(json.loads(remaining), "recovery accepted an invalid or live transaction")
                if corruption in ("locked", "leased", "attached", "mounted"):
                    for descriptor in held:
                        os.close(descriptor)
                    held.clear()
                    self.guardian().sweep(self.runner)
                    self.assertFalse(directory.exists(), "recovery lost its record while the resource was busy")
            else:
                self.assertEqual(json.loads(remaining), [], "next sweep did not reclaim a stopped root helper")
                self.assertFalse(directory.exists())
        finally:
            for descriptor in held:
                os.close(descriptor)
            # The RED must not strand its deliberately stopped root fixture.
            # Only the exact descriptors/identities recorded by this fixture
            # are eligible; no glob or recursive root cleanup is permitted.
            privileged("python3", "-c", '''
import json,os,stat,sys
state=json.load(open(sys.argv[1]))
if 'stage' not in state: sys.exit(0)
handles=[]
try:
    for key in ('directory','stage'):
        try: fd=os.open(state[key],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        except FileNotFoundError: continue
        handles.append(fd)
        info=os.fstat(fd)
        assert [info.st_dev,info.st_ino]==state[key+'_identity']
        entries=set(os.listdir(fd))
        if key=='directory':
            assert entries<={'ext4.img','tmp'}
            if 'ext4.img' in entries: os.unlink('ext4.img',dir_fd=fd)
            if 'tmp' in entries: os.rmdir('tmp',dir_fd=fd)
        else: assert not entries
        os.rmdir(state[key])
finally:
    for fd in handles: os.close(fd)
''', report)

    def test_next_sweep_reclaims_helper_stopped_before_the_staging_move(self):
        self.interrupted_root_helper("freeze")

    def test_next_sweep_reclaims_helper_stopped_after_the_staging_move(self):
        self.interrupted_root_helper("moved")

    def test_next_sweep_finishes_a_partially_removed_root_runtime(self):
        self.interrupted_root_helper("partial")

    def test_next_sweep_finishes_an_empty_frozen_runtime(self):
        self.interrupted_root_helper("empty")

    def test_next_sweep_reclaims_an_interrupted_partial_creation(self):
        self.interrupted_root_helper("create-partial")

    def test_next_sweep_reclaims_creation_stopped_after_mkdir_under_restrictive_umask(self):
        self.interrupted_root_helper("create-mkdir")

    def test_next_sweep_reclaims_creation_interrupted_after_publication(self):
        self.interrupted_root_helper("create-published")

    def test_next_sweep_reclaims_empty_transaction_interrupted_before_marking(self):
        self.interrupted_root_helper("unmarked")

    def test_recovery_preserves_busy_resources_and_retries_them_later(self):
        for corruption in ("locked", "leased", "attached", "mounted"):
            with self.subTest(busy=corruption):
                self.interrupted_root_helper("freeze", corruption=corruption)

    def test_recovery_requires_checkout_uid_parent_and_object_identities(self):
        for corruption in ("owner", "uid", "parent", "directory", "image", "live"):
            with self.subTest(corruption=corruption):
                self.interrupted_root_helper("freeze", corruption=corruption)

    def test_concurrent_recovery_skips_a_completed_transaction_from_another_parent(self):
        other = self.root / "other-parent"
        other.mkdir(mode=0o700)
        program = '''
import importlib.util,os,sys,threading,time
spec=importlib.util.spec_from_file_location('runtime',sys.argv[1])
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
parents=[os.open(path,os.O_RDONLY|os.O_DIRECTORY) for path in sys.argv[2:]]
uid=int(os.environ['SUDO_UID']);deadline=time.monotonic()+5
ready,finish=threading.Event(),threading.Event()
active={};errors=[];visited=[]
def first_transaction():
    try:
        with runtime.protected_directory(parents[0],deadline,uid=uid,
                transaction={'action':'create','name':runtime.PREFIX+'first'}) as fd:
            active['path']=os.readlink('/proc/self/fd/'+str(fd))
            active['name']=os.path.basename(active['path'])
            ready.set()
            assert finish.wait(3),'first transaction did not complete'
    except BaseException as error:
        errors.append(error)
    finally:
        ready.set()
worker=threading.Thread(target=first_transaction)
original_open,original_listdir=runtime.os.open,runtime.os.listdir
worker.start()
try:
    assert ready.wait(3),'first transaction did not start'
    if errors: raise errors[0]
    with runtime.protected_directory(parents[1],deadline,uid=uid,
            transaction={'action':'create','name':runtime.PREFIX+'second'}) as second:
        second_path=os.readlink('/proc/self/fd/'+str(second))
        second_name=os.path.basename(second_path)
        assert os.path.dirname(second_path)==os.path.dirname(active['path'])
        anchor=os.open('..',os.O_RDONLY|os.O_DIRECTORY,dir_fd=second)
        try:
            anchor_identity=runtime.identity(anchor)
            def listed(fd):
                names=original_listdir(fd)
                if isinstance(fd,int) and runtime.identity(fd)==anchor_identity:
                    assert active['name'] in names and second_name in names
                    return [active['name'],second_name]
                return names
            def opened(name,*args,**kwargs):
                parent=kwargs.get('dir_fd')
                if parent is not None and runtime.identity(parent)==anchor_identity:
                    visited.append(name)
                    if name==active['name']:
                        finish.set();worker.join(3)
                        assert not worker.is_alive(),'first transaction did not finish'
                        if errors: raise errors[0]
                        assert not os.path.exists(active['path'])
                return original_open(name,*args,**kwargs)
            runtime.os.open=opened;runtime.os.listdir=listed
            runtime.recover_staging(parents[1],uid,deadline)
            assert visited==[active['name'],second_name],visited
            assert os.path.isdir(second_path),'recovery removed a live transaction'
        finally:
            runtime.os.open, runtime.os.listdir=original_open,original_listdir
            os.close(anchor)
    assert not os.path.exists(second_path)
finally:
    runtime.os.open, runtime.os.listdir=original_open,original_listdir
    finish.set();worker.join(3)
    for fd in parents: os.close(fd)
assert not worker.is_alive()
if errors: raise errors[0]
'''
        try:
            privileged("python3", "-I", "-c", program,
                       HARNESS.with_name("fsverity-runtime.py"), self.runner, other)
        except subprocess.CalledProcessError as error:
            self.fail(error.stderr)

    def test_remove_rejects_an_unowned_parent_and_a_different_parent_inode(self):
        directory = self.candidate("wrong-parent")
        descriptors = [os.open(directory, os.O_RDONLY | os.O_DIRECTORY),
                       os.open(directory / "ext4.img", os.O_RDWR),
                       os.open(directory / "tmp", os.O_RDONLY | os.O_DIRECTORY)]
        try:
            fcntl.fcntl(descriptors[1], fcntl.F_SETLEASE, fcntl.F_WRLCK)
            for path in (Path("/tmp"), self.root):
                with self.subTest(parent=str(path)):
                    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with self.assertRaisesRegex(RuntimeError, "runtime parent"):
                            RUNTIME.privileged_request("remove", [parent, *descriptors], name=directory.name)
                        self.assertEqual(directory.stat().st_uid, os.getuid())
                    finally:
                        os.close(parent)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_removal_round_trip_has_a_budget_separate_from_its_inventories(self):
        directory = self.candidate("round-trip")
        parent = os.open(self.runner, os.O_RDONLY | os.O_DIRECTORY)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        calls = []
        now = time.monotonic()

        def request(operation, _descriptors, *, deadline, result, **_kwargs):
            calls.append((operation, deadline - now))
            result['removed'] = True
            return []

        try:
            with patch.object(RUNTIME, "privileged_request", side_effect=request):
                self.assertTrue(self.guardian().remove_runtime(directory, descriptor, parent, deadline=now + .2))
            self.assertEqual(calls[0][0], "remove")
            self.assertGreaterEqual(calls[0][1], 29, "sudo received only the almost-spent inventory budget")
        finally:
            os.close(descriptor)
            os.close(parent)

    def test_creation_round_trip_allows_the_cleanup_class_budget(self):
        guardian = self.guardian()
        guardian.sweep = lambda _root: None
        guardian.stopping = lambda: False
        calls = []
        now = time.monotonic()

        def request(operation, _descriptors, **kwargs):
            calls.append((operation, kwargs.get('deadline', now + 5) - now))
            raise RuntimeError("creation boundary reached")

        with patch.dict(os.environ, RUNNER_TEMP=str(self.runner)), \
                patch.object(RUNTIME.ctypes, "CDLL") as libc, \
                patch.object(RUNTIME, "privileged_request", side_effect=request):
            libc.return_value.prctl.return_value = 0
            with self.assertRaisesRegex(RuntimeError, "creation boundary reached"):
                guardian.execute(["true"])
        self.assertEqual(calls[0][0], "create")
        self.assertGreaterEqual(calls[0][1], 29, "creation must also allow the sudo round trip and fsyncs")

    def test_autoclear_keeps_its_bound_and_does_not_spend_the_removal_inventory_budget(self):
        directory = self.candidate("autoclear-budget")
        guardian = self.guardian()
        guardian.reap_descendants = unittest.mock.Mock()
        clock = [time.monotonic()]
        started = clock[0]
        inventories = []

        def attachments(*_args, **kwargs):
            if 'deadline' in kwargs:
                inventories.append(kwargs['deadline'] - started)
                clock[0] += 4.8  # Slow final autoclear inventory, within its five seconds.
            return [], []

        def remove(*_args, deadline):
            self.assertGreaterEqual(deadline - clock[0], 4.99)
            return True

        guardian.attachments = attachments
        guardian.remove_runtime = remove
        with patch.object(RUNTIME.time, "monotonic", side_effect=lambda: clock[0]):
            guardian.release(directory)
        self.assertEqual(inventories, [5])

    def deletion_boundary_race(self, kind):
        directory = self.candidate("boundary")
        foreign = self.candidate("foreign", self.root)
        if kind in ("directory", "staging"):
            (foreign / "ext4.img").unlink()
            (foreign / "tmp").rmdir()
        event = "fsverity-test-" + RUNTIME.secrets.token_hex(16)
        parked = (self.runner if kind == "staging" else self.root) / "parked"
        # A separate, finite same-UID actor holds the foreign object throughout
        # the actual deletion. In particular, an image lease on our inode does
        # not protect the foreign image that this actor can substitute.
        program = '''
import fcntl,json,os,signal,socket,sys
signal.alarm(10)
kind,event,directory,foreign,parked,directory_fd=sys.argv[1:]
directory_fd=int(directory_fd)
fd=os.open(foreign + ('/ext4.img' if kind == 'image' else ''), os.O_RDONLY)
if kind != 'image': fcntl.flock(fd, fcntl.LOCK_EX)
with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
    server.bind('\\0'+event); server.listen(1)
    print('ready',flush=True)
    connection,_=server.accept()
    with connection:
        connection.recv(1024)
        try:
            if kind == 'image':
                os.rename('ext4.img',parked,src_dir_fd=directory_fd)
                os.rename(foreign+'/ext4.img','ext4.img',dst_dir_fd=directory_fd)
            else:
                try: os.rename(directory,parked)
                except FileNotFoundError: pass
                os.rename(foreign,directory)
            outcome='replaced'
        except PermissionError: outcome='protected'
        connection.send(outcome.encode())
    sys.stdin.readline()
    print(json.dumps({'links':os.fstat(fd).st_nlink,'outcome':outcome}),flush=True)
os.close(fd)
'''
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        actor = subprocess.Popen(["python3", "-c", program, kind, event, str(directory),
                                  str(foreign), str(parked), str(directory_fd)],
                                 pass_fds=(directory_fd,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        original_unlink, original_rmdir, original_popen = os.unlink, os.rmdir, subprocess.Popen
        injected = False

        def notify():
            nonlocal injected
            if not injected:
                injected = True
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
                    connection.settimeout(5)
                    connection.connect("\0" + event)
                    connection.send(b"delete")
                    connection.recv(1024)

        def unlink(path, *args, **kwargs):
            if kind == "image" and path == "ext4.img":
                notify()
            return original_unlink(path, *args, **kwargs)

        def rmdir(path, *args, **kwargs):
            if kind == "directory" and path == directory.name:
                notify()
            return original_rmdir(path, *args, **kwargs)

        # New production performs deletion in the privileged helper's protected
        # directory. Inject at that helper's real syscall boundary too; the
        # actor above still runs as the caller, never as root.
        instrumentation = '''
import importlib.util,socket,sys
path,event,kind,*arguments=sys.argv[1:]
spec=importlib.util.spec_from_file_location('runtime',path)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
unlink,rmdir=runtime.os.unlink,runtime.os.rmdir
rename=runtime.rename_new
injected=False
def notify():
    global injected
    if not injected:
        injected=True
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(5);connection.connect('\\0'+event)
            connection.send(b'delete');connection.recv(1024)
def remove_image(name,*args,**kwargs):
    if kind=='image' and name=='ext4.img': notify()
    return unlink(name,*args,**kwargs)
def remove_directory(name,*args,**kwargs):
    if kind=='directory' and name=='runtime': notify()
    return rmdir(name,*args,**kwargs)
def move_directory(source,name,destination,new_name):
    if kind=='staging' and new_name=='runtime': notify()
    return rename(source,name,destination,new_name)
runtime.os.unlink=remove_image;runtime.os.rmdir=remove_directory
runtime.rename_new=move_directory
sys.argv=[path,*arguments]
runtime.main()
'''

        def popen(command, *args, **kwargs):
            if "--privileged" in command:
                index = command.index("--privileged")
                command = ["sudo", "-n", "python3", "-I", "-c", instrumentation,
                           str(HARNESS.with_name("fsverity-runtime.py")), event, kind,
                           *command[index:]]
            return original_popen(command, *args, **kwargs)

        try:
            self.assertEqual(actor.stdout.readline().strip(), "ready")
            with patch.object(RUNTIME.os, "unlink", side_effect=unlink), \
                    patch.object(RUNTIME.os, "rmdir", side_effect=rmdir), \
                    patch.object(RUNTIME.subprocess, "Popen", side_effect=popen):
                if kind == "staging":
                    with self.assertRaisesRegex(RuntimeError, "binding changed"):
                        self.guardian().sweep(self.runner)
                else:
                    self.guardian().sweep(self.runner)
            output, _ = actor.communicate(input="finish\n", timeout=5)
            self.assertEqual(actor.returncode, 0, output)
            state = json.loads(output)
            # A response from the actor proves the actual boundary was reached,
            # including when the helper executes the syscall in another process.
            self.assertIn(state["outcome"], ("replaced", "protected"))
            self.assertGreater(state["links"], 0, "deleted a substituted live object")
            if kind == "staging":
                self.assertEqual((parked / "ext4.img").read_bytes(), b"fixture-owned image")
                self.assertEqual(parked.stat().st_uid, os.getuid())
        finally:
            if actor.poll() is None:
                actor.communicate(input="finish\n", timeout=5)
            actor.stdout.close()
            os.close(directory_fd)

    def test_image_substitution_at_unlink_preserves_the_live_foreign_inode(self):
        self.deletion_boundary_race("image")

    def test_directory_substitution_at_rmdir_preserves_the_locked_foreign_inode(self):
        self.deletion_boundary_race("directory")

    def test_directory_substitution_before_staging_is_restored_without_deletion(self):
        self.deletion_boundary_race("staging")

    def test_active_runtime_case_detects_disabled_sweep_locks(self):
        fixture = RuntimeTests("test_startup_sweeps_only_unattached_owned_unlocked_directories")
        fixture.setUp()

        def mutated_gate(*_args, **_kwargs):
            # Mutation: turn off both parent and runtime flock operations.
            with patch.object(RUNTIME.fcntl, "flock", return_value=None):
                self.guardian().sweep(fixture.runner)

        fixture.run_command = mutated_gate
        try:
            with self.assertRaises(AssertionError, msg="active-runtime case accepted disabled locks"):
                fixture.test_startup_sweeps_only_unattached_owned_unlocked_directories()
            self.assertFalse((fixture.runner / (RUNTIME.PREFIX + "active")).exists(),
                             "mutation did not remove the otherwise eligible active runtime")
            self.assertFalse((fixture.runner / (RUNTIME.PREFIX + "stale")).exists())
            self.assertTrue((fixture.runner / (RUNTIME.PREFIX + "public")).exists())
        finally:
            fixture.temporary.cleanup()  # The mutation runs no command/mount.

    def mount_with_partition_minors(self, mismatch=None):
        reader, writer = os.pipe()
        guardian = self.guardian()
        guardian.owner = reader
        guardian.sweep = lambda _root: None
        guardian.release = lambda _directory: None
        run = unittest.mock.Mock()
        guardian.run = run
        real_request, real_fstat, real_stat = RUNTIME.privileged_request, os.fstat, os.stat
        pinned = os.open(os.devnull, os.O_RDONLY)
        device = os.makedev(7, 16)  # loop1 with max_part=15, not loop16.

        def request(operation, *args, result=None, **kwargs):
            if operation == "attach":
                if result is not None:
                    result["loop_index"] = 1
                return [pinned]
            return real_request(operation, *args, **kwargs)

        def fstat(descriptor):
            info = real_fstat(descriptor)
            if descriptor == pinned:
                values = list(info)
                values[0] = stat.S_IFBLK | 0o600
                return type("LoopStat", (), {"st_mode": values[0], "st_rdev": device})()
            return info

        def inspect(path, *args, **kwargs):
            if str(path).startswith("/dev/loop"):
                return type("LoopStat", (), {"st_mode": stat.S_IFBLK,
                           "st_rdev": os.makedev(7, 256) if mismatch == "node" else device})()
            info = real_stat(path, *args, **kwargs)
            if isinstance(path, Path) and path.name == "tmp":
                values = list(info)
                values[2] = os.makedev(7, 256) if mismatch == "mount" else device
                return os.stat_result(values)
            return info

        try:
            with patch.dict(os.environ, {"RUNNER_TEMP": str(self.runner)}), \
                    patch.object(RUNTIME, "privileged_request", side_effect=request), \
                    patch.object(RUNTIME.os, "fstat", side_effect=fstat), \
                    patch.object(RUNTIME.os, "stat", side_effect=inspect):
                if mismatch:
                    with self.assertRaisesRegex(RuntimeError, "device.*mismatch"):
                        guardian.execute(["true"])
                else:
                    self.assertEqual(guardian.execute(["true"]), 0)
            mounts = [call.args[0] for call in run.call_args_list if "mount" in call.args[0]]
            chowns = [call for call in run.call_args_list if "chown" in call.args[0]]
            if mismatch == "node":
                self.assertEqual(mounts, [])
            else:
                self.assertEqual(mounts[0][-2], "/dev/loop1")
            self.assertEqual(len(chowns), 0 if mismatch else 1)
        finally:
            os.close(reader)
            os.close(writer)

    def test_loop_index_is_independent_of_partition_minor_numbers(self):
        self.mount_with_partition_minors()

    def test_device_node_mismatch_is_refused_before_mount(self):
        self.mount_with_partition_minors("node")

    def test_mounted_device_mismatch_is_refused_before_chown(self):
        self.mount_with_partition_minors("mount")

    def test_reaper_helper_timeout_still_attempts_unmount(self):
        directory = self.candidate("timeout")
        guardian = self.guardian()
        guardian.reap_descendants = unittest.mock.Mock(side_effect=subprocess.TimeoutExpired("helper", .1))
        guardian.attachments = unittest.mock.Mock(side_effect=[
            ([], [{"target": str(directory / "tmp")}]), ([], []), ([], []),
        ])
        guardian.run = unittest.mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "descendant cleanup failed"):
            guardian.release(directory)
        guardian.run.assert_called_once_with(
            ["sudo", "-n", "umount", "--", str(directory / "tmp")], cleanup=True)
        self.assertTrue(directory.exists())

    def test_cleanup_lock_wait_does_not_stop_with_the_command_owner(self):
        guardian = self.guardian()
        guardian.stopping = unittest.mock.Mock(return_value=True)
        with patch.object(RUNTIME.fcntl, "flock", side_effect=[BlockingIOError(), None, None]):
            with guardian.startup_lock(-1, cleanup=True):
                pass
        guardian.stopping.assert_not_called()

    def test_slow_unmount_does_not_hold_the_shared_startup_lock(self):
        directory = self.candidate("unmount-lock")
        guardian = self.guardian()
        guardian.reap_descendants = unittest.mock.Mock()
        guardian.attachments = unittest.mock.Mock(side_effect=[
            ([], [{"target": str(directory / "tmp")}]), ([], []), ([], []),
        ])
        guardian.remove_runtime = unittest.mock.Mock(return_value=True)
        parent = os.open(self.runner, os.O_RDONLY | os.O_DIRECTORY)

        def unmount(*_args, **_kwargs):
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(parent, fcntl.LOCK_UN)

        guardian.run = unmount
        try:
            guardian.release(directory)
        finally:
            os.close(parent)

    def test_reused_inventory_loop_is_gone_but_explicit_detach_still_refuses_it(self):
        image = self.candidate("reused-loop") / "ext4.img"
        descriptor = os.open(image, os.O_RDONLY)
        other = type("LoopStat", (), {"st_mode": stat.S_IFBLK, "st_rdev": os.makedev(7, 1)})()
        real_fstat = os.fstat
        try:
            with patch.object(RUNTIME.os, "fstat", side_effect=lambda fd: other if fd == -1 else real_fstat(fd)), \
                    patch.object(RUNTIME.fcntl, "ioctl", return_value=bytes(232)):
                self.assertFalse(RUNTIME.verify_loop(descriptor, -1, missing_ok=True))
                with self.assertRaisesRegex(RuntimeError, "refusing to detach"):
                    RUNTIME.verify_loop(descriptor, -1)
        finally:
            os.close(descriptor)

    def test_attachment_inventory_uses_the_pinned_image_after_name_substitution(self):
        directory = self.candidate("inventory-image")
        image = directory / "ext4.img"
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        image_fd = os.open(image, os.O_RDWR)
        guardian = self.guardian()
        guardian.image_identity = RUNTIME.identity(image_fd)
        image.rename(self.root / "original-image")
        image.write_bytes(b"foreign replacement")

        def loop(name, info):
            return {"name": name, "back-maj:min": f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}",
                    "back-ino": info.st_ino}

        original, foreign = loop("owned", os.fstat(image_fd)), loop("foreign", image.stat())
        guardian.inventory = lambda **_kwargs: ([original, foreign], [])
        try:
            self.assertEqual(guardian.attachments(directory, descriptor), ([original], []))
            self.assertEqual(image.read_bytes(), b"foreign replacement")
        finally:
            os.close(image_fd)
            os.close(descriptor)

    def test_mount_inventory_precedes_incomplete_owned_layout_checks(self):
        directory = self.candidate("mounted")
        (directory / "ext4.img").unlink()
        guardian = self.guardian()
        guardian.inventory = unittest.mock.Mock(return_value=([], [{"target": str(directory / "tmp")}]))
        real_listdir = os.listdir
        expected = directory.stat()

        def listdir(descriptor):
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                self.fail("mounted runtime reached layout/deletion checks")
            return real_listdir(descriptor)

        with patch.object(RUNTIME.os, "listdir", side_effect=listdir):
            guardian.sweep(self.runner)
        guardian.inventory.assert_called_once()
        self.assertTrue(directory.exists())

    def test_pin_checks_the_node_without_opening_a_fifo_for_io(self):
        image = self.candidate("pin") / "ext4.img"
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        real_open = os.open

        def checked_open(path, flags, *args, **kwargs):
            if path == str(fifo) and not flags & os.O_PATH:
                self.fail("pin attempted I/O before verifying a loop device")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(RUNTIME.os, "geteuid", return_value=0), \
                patch.object(RUNTIME.os, "open", side_effect=checked_open):
            with self.assertRaisesRegex(RuntimeError, "non-loop device"):
                RUNTIME.detach_verified_loop(image, str(fifo))

    def test_live_legacy_and_foreign_prefixes_are_preserved(self):
        # Both are legitimate pre-attachment layouts of other tools. Neither
        # participates in this owner's locks, even when its image is unopened.
        legacy = self.runner / "opc-fsverity.live"
        foreign = self.runner / "fs-verity-runtime.other-tool"
        for directory in (legacy, foreign):
            directory.mkdir(mode=0o700)
            (directory / "ext4.img").write_bytes(b"live pre-mount image")
            (directory / "tmp").mkdir(mode=0o700)
        (foreign / "mutable").mkdir()
        sentinel = foreign / "mutable" / "database"
        sentinel.write_bytes(b"other tool's mutable state")
        legacy_process = subprocess.Popen(["python3", "-c", """
import os, sys
with open(sys.argv[1], 'rb') as stream:
    print('live before attachment', flush=True)
    sys.stdin.readline()
    assert os.fstat(stream.fileno()).st_nlink > 0, 'live legacy image was removed'
""", str(legacy / "ext4.img")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(legacy_process.stdout.readline().strip(), "live before attachment")
            self.guardian().sweep(self.runner)
            self.assertEqual((legacy / "ext4.img").read_bytes(), b"live pre-mount image")
            self.assertEqual(sentinel.read_bytes(), b"other tool's mutable state")
        finally:
            legacy_process.communicate(input="finish\n", timeout=5)
        self.assertEqual(legacy_process.returncode, 0)

    def renamed_during_inventory(self, release):
        stale = self.candidate("stale")
        active = self.candidate("active", self.root)
        sentinel = active / "must-survive"
        sentinel.write_text("locked active inode")
        descriptor = os.open(active, os.O_RDONLY | os.O_DIRECTORY)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guardian = self.guardian()
        parked = self.root / "parked-stale-inode"

        def inventory(**_kwargs):
            if not parked.exists():
                stale.rename(parked)
                active.rename(stale)
            return [], []

        guardian.inventory = inventory
        try:
            try:
                if release:
                    guardian.release(stale)
                else:
                    guardian.sweep(self.runner)
            except RuntimeError:
                pass  # Rejecting a changed name is the safe outcome.
            self.assertEqual((stale / "must-survive").read_text(), "locked active inode")
            self.assertGreater(os.fstat(descriptor).st_nlink, 0)
        finally:
            os.close(descriptor)

    def test_sweep_never_deletes_a_replacement_locked_inode(self):
        self.renamed_during_inventory(release=False)

    def test_release_never_deletes_a_replacement_locked_inode(self):
        self.renamed_during_inventory(release=True)

    def test_attachment_open_cannot_cross_inventory_and_delete(self):
        directory = self.candidate("attach-race")
        guardian = self.guardian()
        opened = []
        previous = signal.signal(signal.SIGIO, lambda *_args: None)
        inventories = 0

        def inventory(**_kwargs):
            nonlocal inventories
            inventories += 1
            if inventories == 1:
                return [], []  # Mount preflight; inject at the leased inventory.
            # A distinct process models the backing-file open preceding
            # LOOP_CONFIGURE. It holds that FD across the deletion boundary.
            child = subprocess.Popen(["python3", "-c", """
import os, sys
try:
    descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NONBLOCK)
except BlockingIOError:
    print('blocked', flush=True)
else:
    print('opened', flush=True)
    sys.stdin.readline()
    print(os.fstat(descriptor).st_nlink, flush=True)
    os.close(descriptor)
""", str(directory / "ext4.img")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            opened.append((child, child.stdout.readline().strip()))
            return [], []

        guardian.inventory = inventory
        try:
            guardian.sweep(self.runner)
            self.assertGreaterEqual(inventories, 2)
            self.assertTrue(opened, "did not reach the attachment/deletion boundary")
            for child, state in opened:
                output, _ = child.communicate(input="finish\n", timeout=5)
                self.assertEqual(child.returncode, 0)
                if state == "opened":
                    self.assertGreater(int(output), 0, "deleted an image opened for concurrent attachment")
                else:
                    self.assertEqual(state, "blocked")
        finally:
            for child, _state in opened:
                if child.poll() is None:
                    child.communicate(input="finish\n", timeout=5)
            signal.signal(signal.SIGIO, previous)

    def test_fallback_cleanup_never_detaches_an_inventory_name(self):
        fixture = RuntimeTests()
        fixture.root = self.root
        fixture.runner = self.runner
        fixture.process = None
        fixture.guardians = {}
        fixture.extra_mounts = []
        fixture.extra_images = []
        fixture.temporary = unittest.mock.Mock()
        image = self.candidate("reuse") / "ext4.img"
        calls = []
        released = False

        def fake_privileged(*arguments):
            calls.append(arguments)
            if arguments[:2] == ("losetup", "--associated"):
                return "" if released else "/dev/loop123456\n"
            return ""

        def verified_detach(*_arguments):
            nonlocal released
            released = True

        with patch(__name__ + ".privileged", side_effect=fake_privileged), \
                patch.object(RUNTIME, "detach_verified_loop", create=True, side_effect=verified_detach) as detach, \
                patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="")), \
                patch.object(fixture, "wait_for_guardians", create=True):
            fixture.tearDown()
        self.assertNotIn(("losetup", "--detach", "/dev/loop123456"), calls)
        detach.assert_called_once_with(image, "/dev/loop123456")

    def test_captured_orphan_pipe_obeys_helper_deadline(self):
        # Keep subreaper state and finite descendants out of the test runner.
        program = '''
import ctypes, importlib.util, sys, time
spec = importlib.util.spec_from_file_location('runtime', sys.argv[1])
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
guardian = runtime.Guardian(-1)
expired = False
started = time.monotonic()
try:
    guardian.run([sys.executable, '-c', 'import os,time; child=os.fork(); os._exit(0) if child else time.sleep(.6)'],
                 capture=True, cleanup=True, timeout=.15)
except TimeoutError:
    expired = True
finally:
    guardian.reap_descendants()
assert expired, 'orphan-held output bypassed the helper deadline'
assert time.monotonic() - started < .5, 'helper disposal exceeded its bounded budget'
'''
        result = subprocess.run(["python3", "-c", program, str(HARNESS.with_name("fsverity-runtime.py"))],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sweep_requires_the_marker_and_exact_empty_layout(self):
        stale = self.candidate("valid")
        unmarked = self.candidate("unmarked")
        descriptor = os.open(unmarked, os.O_RDONLY | os.O_DIRECTORY)
        os.removexattr(descriptor, RUNTIME.OWNER_ATTRIBUTE)
        os.close(descriptor)
        other_owner = self.candidate("another-checkout")
        os.setxattr(other_owner, RUNTIME.OWNER_ATTRIBUTE, b"another-checkout")
        extra = self.candidate("extra")
        (extra / "mutable").mkdir()
        nonempty = self.candidate("nonempty")
        (nonempty / "tmp" / "sentinel").write_text("preserve")
        self.guardian().sweep(self.runner)
        self.assertFalse(stale.exists())
        self.assertEqual(set(self.runner.iterdir()), {unmarked, other_owner, extra, nonempty})
        self.assertEqual((nonempty / "tmp" / "sentinel").read_text(), "preserve")

    def test_sweep_preserves_an_image_already_open_for_attachment(self):
        directory = self.candidate("preopened")
        descriptor = os.open(directory / "ext4.img", os.O_RDONLY)
        try:
            self.guardian().sweep(self.runner)
            self.assertTrue(directory.exists())
            self.assertGreater(os.fstat(descriptor).st_nlink, 0)
        finally:
            os.close(descriptor)

    def test_initialization_error_rolls_back_only_its_new_runtime(self):
        reader, writer = os.pipe()
        try:
            with patch.dict(os.environ, {"RUNNER_TEMP": str(self.runner)}), \
                    patch.object(RUNTIME, "mark_owned", side_effect=OSError("marker failure")), \
                    patch.object(RUNTIME.ctypes, "CDLL") as libc:
                libc.return_value.prctl.return_value = 0
                with self.assertRaisesRegex(OSError, "marker failure"):
                    RUNTIME.Guardian(reader).execute(["true"])
            self.assertEqual(list(self.runner.iterdir()), [])
        finally:
            os.close(reader)
            os.close(writer)

    def test_expired_helper_budget_never_starts_a_process(self):
        with patch("subprocess.Popen") as launch:
            with self.assertRaises(TimeoutError):
                self.guardian().run(["true"], cleanup=True, deadline=time.monotonic() - 1)
            launch.assert_not_called()

    def test_runtime_open_error_removes_its_new_empty_directory(self):
        reader, writer = os.pipe()
        original_popen = subprocess.Popen
        program = '''
import importlib.util,sys
path,*arguments=sys.argv[1:]
spec=importlib.util.spec_from_file_location('runtime',path)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
original_open=runtime.os.open
def failed_open(path,*args,**kwargs):
    if path=='runtime': raise OSError('runtime open failed')
    return original_open(path,*args,**kwargs)
runtime.os.open=failed_open
sys.argv=[path,*arguments]
runtime.main()
'''

        def failed_open(command, *args, **kwargs):
            if "--privileged" in command:
                command = ["sudo", "-n", "python3", "-I", "-c", program,
                           str(HARNESS.with_name("fsverity-runtime.py")),
                           *command[command.index("--privileged"):]]
            return original_popen(command, *args, **kwargs)

        try:
            with patch.dict(os.environ, {"RUNNER_TEMP": str(self.runner)}), \
                    patch.object(RUNTIME.subprocess, "Popen", side_effect=failed_open), \
                    patch.object(RUNTIME.ctypes, "CDLL") as libc:
                libc.return_value.prctl.return_value = 0
                with self.assertRaisesRegex(OSError, "runtime open failed"):
                    RUNTIME.Guardian(reader).execute(["true"])
            self.assertEqual(list(self.runner.iterdir()), [])
        finally:
            os.close(reader)
            os.close(writer)

    def test_every_workflow_owner_shell_resolves_bash_first(self):
        shells = [line.strip().removeprefix("shell: ")
                  for path in (ROOT / ".github/workflows").glob("*.yml")
                  for line in path.read_text().splitlines()
                  if "shell:" in line and "ci/setup-fsverity-tmp.sh" in line]
        self.assertEqual(len(shells), 11)
        for shell in shells:
            arguments = shlex.split(shell)
            self.assertEqual(arguments[:3], ["bash", "ci/setup-fsverity-tmp.sh", "--"])
            self.assertIsNotNone(shutil.which(arguments[0]))


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fsverity test-")
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.environment = os.environ | {
            "RUNNER_TEMP": str(self.runner),
            "GITHUB_ENV": str(self.root / "github-env"),
        }
        self.process = None
        self.guardians = {}
        self.extra_mounts = []
        self.extra_images = []

    def owned_directory(self, suffix):
        directory = self.runner / (RUNTIME.PREFIX + suffix)
        directory.mkdir(mode=0o700)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            RUNTIME.mark_owned(descriptor)
        finally:
            os.close(descriptor)
        (directory / "tmp").mkdir(mode=0o700)
        return directory

    def images(self):
        return list(self.runner.glob("*/ext4.img")) + self.extra_images

    def attached(self):
        resources = []
        for image in self.images():
            loops = privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME")
            mounts = subprocess.run(
                ["findmnt", "--mountpoint", str(image.parent / "tmp"), "--noheadings"],
                capture_output=True, text=True, timeout=5,
            )
            if loops.strip() or mounts.returncode == 0:
                resources.append({"image": str(image), "loops": loops.strip(), "mounts": mounts.stdout.strip()})
        return resources

    def tearDown(self):
        # Do not let TemporaryDirectory's finalizer delete an attached image
        # if a failing guardian has not finished within the existing bound.
        self.temporary._finalizer.detach()
        self.guardian_locks = []
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        self.wait_for_guardians()
        # Even the RED must not strand a loop mount on the shared host.
        for mountpoint in reversed(self.extra_mounts):
            mounted = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, timeout=5,
            )
            if mounted.returncode == 0:
                privileged("umount", mountpoint)
        for image in self.images():
            mountpoint = image.parent / "tmp"
            mounted = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, timeout=5,
            )
            if mounted.returncode == 0:
                privileged("umount", mountpoint)
            for loop in privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").split():
                RUNTIME.detach_verified_loop(image, loop)
        self.assertEqual(self.attached(), [], "refusing to delete an attached fixture")
        self.temporary.cleanup()
        for descriptor in self.guardian_locks:
            os.close(descriptor)
        for descriptor in self.guardians.values():
            os.close(descriptor)

    def observe_guardians(self):
        for directory in self.runner.glob(RUNTIME.PREFIX + "*"):
            descriptor = None
            try:
                value = os.getxattr(directory, RUNTIME.GUARDIAN_ATTRIBUTE)
                pid, start = map(int, value.decode().split(":"))
                if (pid, start) in self.guardians or RUNTIME.process_stat(pid)[1] != start:
                    continue
                descriptor = os.pidfd_open(pid)
                if RUNTIME.process_stat(pid)[1] == start:
                    self.guardians[pid, start] = descriptor
                    descriptor = None
            except (OSError, ValueError):
                continue
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    def wait_for_guardians(self):
        deadline = time.monotonic() + 10
        self.observe_guardians()
        for descriptor in self.guardians.values():
            ready, _, _ = select.select([descriptor], [], [], max(0, deadline - time.monotonic()))
            self.assertTrue(ready, "guardian did not exit; retaining fixture")
        for directory in self.runner.glob(RUNTIME.PREFIX + "*"):
            try:
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except (FileNotFoundError, NotADirectoryError):
                continue
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.guardian_locks.append(descriptor)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        os.close(descriptor)
                        self.fail("guardian still owns fixture; retaining its files")
                    time.sleep(.02)

    def wait_for(self, predicate, description, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.observe_guardians()
            if predicate():
                return
            time.sleep(0.02)
        self.fail(f"timed out waiting for {description}")

    def interrupted_setup(self, signum):
        ready = self.root / "mounted"
        shim = self.root / "bin"
        shim.mkdir()
        sudo = shim / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys
arguments = sys.argv[1:]
if arguments[:1] == ['-n']:
    arguments = arguments[1:]
subprocess.run(['/usr/bin/sudo', '-n', *arguments], check=True)
if arguments[0] == 'mount':
    Path(os.environ['MOUNT_READY']).write_text(str(os.getpid()))
    while True:
        signal.pause()
""")
        sudo.chmod(0o755)
        self.process = start_owner(
            [str(HARNESS), "--", "true"],
            env=self.environment | {"PATH": str(shim) + ":" + os.environ["PATH"], "MOUNT_READY": str(ready)},
            start_new_session=True,
        )
        self.wait_for(ready.exists, "the real loop mount")
        self.assertTrue(self.attached(), "fixture did not mount a real image")
        os.killpg(self.process.pid, signum)
        self.process.wait(timeout=10)
        # Give an independent cleanup guardian time to finish after interruption.
        deadline = time.monotonic() + 10
        while list(self.runner.iterdir()) and time.monotonic() < deadline:
            time.sleep(0.02)
        leftovers = {"directories": [str(p) for p in self.runner.iterdir()], "attached": self.attached()}
        print("interruption leftovers: " + json.dumps(leftovers), flush=True)
        self.assertEqual(leftovers, {"directories": [], "attached": []})

    def test_interrupted_setup_releases_mount_loop_and_image(self):
        """Interrupt after mount succeeds but before setup can export its root."""
        self.interrupted_setup(signal.SIGTERM)

    def test_killed_launcher_during_setup_releases_mount_loop_and_image(self):
        self.interrupted_setup(signal.SIGKILL)

    def run_command(self, *command, environment=None, expected=0):
        result = subprocess.run(
            [str(HARNESS), "--", *map(str, command)],
            env=self.environment | (environment or {}), preexec_fn=parent_death_guard(),
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_normal_exit_scopes_environment_and_removes_runtime(self):
        report = self.root / "report.json"
        ordinary = self.root / "mutable"
        ordinary.mkdir()
        original = "PRESERVED=1\n"
        Path(self.environment["GITHUB_ENV"]).write_text(original)
        self.run_command("python3", "-c", """
import json, os, pathlib, stat, sys
root = pathlib.Path(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT'])
info = root.stat()
def loop_is_pinned():
    for descriptor in pathlib.Path(f'/proc/{os.getppid()}/fd').iterdir():
        try:
            pinned = descriptor.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISBLK(pinned.st_mode) and pinned.st_rdev == info.st_dev:
            return True
    return False
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    'required': os.environ['OPC_FS_VERITY_QUALIFICATION'],
    'owner': info.st_uid, 'mode': stat.S_IMODE(info.st_mode),
    'snapshot_device': info.st_dev,
    'mutable_device': pathlib.Path(os.environ['TMPDIR']).stat().st_dev,
    'tmpdir': os.environ['TMPDIR'], 'root': str(root),
    'loop_is_pinned': loop_is_pinned(),
}))
""", report, environment={"TMPDIR": str(ordinary)})
        data = json.loads(report.read_text())
        self.assertEqual(data["required"], "required")
        self.assertEqual((data["owner"], data["mode"]), (os.getuid(), 0o700))
        self.assertNotEqual(data["snapshot_device"], data["mutable_device"])
        self.assertEqual(data["tmpdir"], str(ordinary))
        self.assertTrue(data["loop_is_pinned"], "owner must retain the device it configured")
        self.assertFalse(Path(data["root"]).exists())
        self.assertEqual(Path(self.environment["GITHUB_ENV"]).read_text(), original)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_failing_command_keeps_exit_status_and_removes_runtime(self):
        self.run_command("sh", "-c", "exit 37", expected=37)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_command_preserves_callers_file_limit_and_umask(self):
        inherited_hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        hard = 131072 if inherited_hard == resource.RLIM_INFINITY else min(131072, inherited_hard)
        soft = min(65536, hard)
        arm = parent_death_guard()
        for mask in (0o002, 0o027, 0o777):
            with self.subTest(umask=oct(mask)):
                def configure_caller():
                    arm()
                    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
                    os.umask(mask)

                result = subprocess.run(
                    [str(HARNESS), "--", sys.executable, "-c",
                     "import json,os,resource; print(json.dumps({"
                     "'nofile': resource.getrlimit(resource.RLIMIT_NOFILE), 'umask': os.umask(0)}))"],
                    env=self.environment, preexec_fn=configure_caller,
                    capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout), {"nofile": [soft, hard], "umask": mask})
                self.assertEqual(list(self.runner.iterdir()), [])

    def test_low_bootstrap_file_limit_does_not_cap_the_command(self):
        program = '''
import importlib.util,sys
spec=importlib.util.spec_from_file_location('runtime',sys.argv[1])
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
original=runtime.subprocess.Popen
hits=0
def bootstrap(command,*args,**kwargs):
    global hits
    if command[:3]==['/usr/bin/sudo','-n','/usr/bin/unshare']:
        hits+=1
        command=command[:2]+['/usr/bin/prlimit','--nofile=1024:1024','--']+command[2:]
    return original(command,*args,**kwargs)
runtime.subprocess.Popen=bootstrap
result=runtime.launch([sys.executable,'-c',
    "import os; fds=[os.open('/dev/null',os.O_RDONLY) for _ in range(2048)]; "
    "[os.close(fd) for fd in fds]"])
assert hits==1, 'the low-limit bootstrap mutation must take effect'
sys.exit(result)
'''
        result = subprocess.run(
            [sys.executable, "-c", program, str(HARNESS.with_name("fsverity-runtime.py"))],
            env=self.environment, preexec_fn=parent_death_guard(),
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_runtime_mount_is_not_visible_to_other_jobs(self):
        report = self.root / "snapshot-root"
        finish = self.root / "finish"
        self.process = start_owner(
            [str(HARNESS), "--", "python3", "-c", """
import os, pathlib, time
pathlib.Path(%r).write_text(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT'])
deadline = time.monotonic() + 10
while not pathlib.Path(%r).exists():
    if time.monotonic() >= deadline:
        raise TimeoutError('parent did not finish mount visibility check')
    time.sleep(0.02)
""" % (str(report), str(finish))],
            env=self.environment, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            self.wait_for(report.exists, "wrapped command snapshot root")
            mountpoint = Path(report.read_text()).parent
            outside = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(outside.returncode, 1, outside.stdout + outside.stderr)
        finally:
            finish.touch()
            output, _ = self.process.communicate(timeout=10)
        self.assertEqual(self.process.returncode, 0, output)
        self.assertEqual(self.attached(), [])
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_restrictive_umask_preserves_private_root_and_cleanup(self):
        result = subprocess.run(
            [str(HARNESS), "--", "true"], env=self.environment,
            capture_output=True, text=True, timeout=20, umask=0o777, preexec_fn=parent_death_guard(),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_wrapped_command_retains_original_stdin(self):
        data = b"caller input\x00\n"
        result = subprocess.run(
            [str(HARNESS), "--", "python3", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
            env=self.environment, input=data, preexec_fn=parent_death_guard(), capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, data)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_test_runner_death_kills_launcher_and_waits_for_guardian(self):
        ready = self.root / "runner-death-ready"
        launcher = self.root / "fixture-launcher"
        program = """
import importlib.util, os, pathlib, subprocess
spec = importlib.util.spec_from_file_location('fixtures', %r)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
start = getattr(fixtures, 'start_owner', subprocess.Popen)
process = start([%r, '--', 'python3', '-c', %r], env=os.environ, start_new_session=True)
pathlib.Path(%r).write_text(str(process.pid))
process.wait()
""" % (str(Path(__file__).resolve()), str(HARNESS),
       "import pathlib,time; pathlib.Path(%r).touch(); time.sleep(2)" % str(ready), str(launcher))
        self.process = start_owner(["python3", "-c", program], env=self.environment,
                                        start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.wait_for(ready.exists, "fixture command ready before test runner dies")
        descriptor = os.pidfd_open(int(launcher.read_text()))
        try:
            self.process.kill()
            self.process.wait(timeout=5)
            exited, _, _ = select.select([descriptor], [], [], 1)
            self.assertTrue(exited, "dead test runner left its detached launcher alive")
        finally:
            os.close(descriptor)
        self.wait_for_guardians()
        self.process.communicate(timeout=5)
        self.assertEqual(list(self.runner.iterdir()), [])
        self.assertEqual(self.attached(), [])

    def test_slave_namespace_observes_another_jobs_unmount_without_pinning_it(self):
        other = self.root / "opc-fsverity.other-job"
        other.mkdir()
        image = other / "ext4.img"
        with image.open("xb") as stream:
            stream.truncate(32 * 1024**2)
        mountpoint = other / "tmp"
        mountpoint.mkdir()
        self.extra_images.append(image)
        self.extra_mounts.append(mountpoint)
        subprocess.run(["mkfs.ext4", "-q", str(image)], check=True, timeout=10)
        privileged("mount", "-o", "loop,nosuid,nodev", image, mountpoint)
        privileged("mount", "--make-shared", mountpoint)
        ready = self.root / "foreign-visible"
        finish = self.root / "foreign-unmounted"
        self.process = start_owner([str(HARNESS), "--", "python3", "-c", """
import pathlib, subprocess, time
result = subprocess.run(['findmnt', '--mountpoint', %r, '--noheadings'], capture_output=True)
assert result.returncode == 0, result.stdout
pathlib.Path(%r).touch()
deadline = time.monotonic() + 5
while not pathlib.Path(%r).exists():
    assert time.monotonic() < deadline, 'parent did not unmount the foreign fixture'
    time.sleep(.02)
result = subprocess.run(['findmnt', '--mountpoint', %r, '--noheadings'], capture_output=True)
assert result.returncode == 1, result.stdout
""" % (str(mountpoint), str(ready), str(finish), str(mountpoint))],
            env=self.environment, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.wait_for(ready.exists, "foreign mount initially visible in slave namespace")
        parent = subprocess.run(
            ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(parent.returncode, 0, parent.stderr)
        self.assertTrue(image.exists())
        privileged("umount", mountpoint)
        finish.touch()
        output, _ = self.process.communicate(timeout=10)
        self.assertEqual(self.process.returncode, 0, output)
        self.assertEqual(privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").strip(), "")

    def test_caller_lock_is_held_through_killed_launcher_cleanup(self):
        ready = self.root / "ready"
        lock = self.root / "caller-lock"
        with lock.open("w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.process = start_owner(
                [str(HARNESS), "--", "python3", "-c", """
import pathlib, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(%r).touch()
time.sleep(10)
""" % str(ready)],
                env=self.environment, pass_fds=(stream.fileno(),), start_new_session=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        self.wait_for(ready.exists, "TERM-resistant command")
        self.process.kill()
        self.process.wait(timeout=5)
        with lock.open("w") as observer:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.wait_for(lambda: not list(self.runner.iterdir()), "guardian cleanup")
            self.wait_for(lambda: self.lock_available(observer), "caller lock release")
        self.process.communicate(timeout=5)
        self.assertEqual(self.attached(), [])

    @staticmethod
    def lock_available(stream):
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    def test_cleanup_detaches_an_additional_binding_to_its_own_image(self):
        self.run_command("python3", "-c", """
import os, pathlib, subprocess
image = pathlib.Path(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT']).parents[1] / 'ext4.img'
subprocess.run(['sudo', '-n', 'losetup', '--find', '--show', str(image)], check=True)
""")
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_detach_refuses_a_different_backing_file(self):
        image = self.root / "image"
        with image.open("xb") as stream:
            stream.truncate(32 * 1024**2)
        self.extra_images.append(image)
        other = self.root / "other-image"
        other.write_bytes(b"different inode")
        loop = privileged("losetup", "--find", "--show", image).strip()
        result = subprocess.run(
            ["sudo", "-n", "python3", str(ROOT / "ci/fsverity-runtime.py"), "--detach-loop", str(other), loop],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to detach", result.stderr)
        self.assertEqual(privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").strip(), loop)

    def test_cleanup_waits_for_pending_loop_autoclear(self):
        ready = self.root / "ready"
        finish = self.root / "finish"
        held = self.root / "device-held"
        self.process = start_owner(
            [str(HARNESS), "--", "python3", "-c", """
import pathlib, time
pathlib.Path(%r).touch()
deadline = time.monotonic() + 10
while not pathlib.Path(%r).exists():
    if time.monotonic() >= deadline:
        raise TimeoutError('parent did not release command')
    time.sleep(0.02)
""" % (str(ready), str(finish))],
            env=self.environment, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.wait_for(ready.exists, "mounted runtime")
        image = self.images()[0]
        loop = privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").strip()
        # Model a device observer such as udev: LOOP_CLR_FD marks autoclear,
        # but the binding remains until this separate process closes its FD.
        observer = subprocess.Popen(["/usr/bin/sudo", "-n", "python3", "-c", """
import os, pathlib, time
descriptor = os.open(%r, os.O_RDONLY)
pathlib.Path(%r).touch()
time.sleep(1.5)
os.close(descriptor)
""" % (loop, str(held))])
        try:
            self.wait_for(held.exists, "external loop descriptor")
            finish.touch()
            output, _ = self.process.communicate(timeout=10)
        finally:
            observer.wait(timeout=5)
        self.assertEqual(self.process.returncode, 0, output)
        self.assertEqual(self.attached(), [])
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_preparation_failure_removes_runtime(self):
        shim = self.root / "bin"
        shim.mkdir()
        sudo = shim / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os, sys
arguments = sys.argv[1:]
if arguments[:1] == ['-n']:
    arguments = arguments[1:]
if arguments[0] == 'chown':
    sys.exit(42)
os.execv('/usr/bin/sudo', ['sudo', '-n', *arguments])
""")
        sudo.chmod(0o755)
        self.run_command("true", environment={"PATH": str(shim) + ":" + os.environ["PATH"]}, expected=42)
        self.assertEqual(list(self.runner.iterdir()), [])

    def failing_sudo(self, operation):
        shim = self.root / ("bin-" + operation)
        shim.mkdir()
        sudo = shim / "sudo"
        sudo.write_text("""#!/usr/bin/env python3
import os, sys
arguments = sys.argv[1:]
if arguments[:1] == ['-n']:
    arguments = arguments[1:]
if arguments[0] == %r and (arguments[0] != 'umount' or
        arguments[-1].startswith(os.environ['RUNNER_TEMP'] + '/')):
    sys.exit(42)
os.execv('/usr/bin/sudo', ['sudo', '-n', *arguments])
""" % operation)
        sudo.chmod(0o755)
        return {"PATH": str(shim) + ":" + os.environ["PATH"]}

    def test_cleanup_failure_fails_gate_and_next_sweep_preserves_attachment(self):
        # An explicit extra binding survives destruction of the owner's private
        # mount namespace, keeping this an actually attached startup-sweep case.
        self.run_command("python3", "-c", """
import os, pathlib, subprocess
image = pathlib.Path(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT']).parents[1] / 'ext4.img'
subprocess.run(['sudo', '-n', 'losetup', '--find', '--show', str(image)], check=True)
""", environment=self.failing_sudo("umount"), expected=1)
        images = self.images()
        self.assertEqual(len(images), 1)
        self.assertTrue(self.attached())
        self.run_command("true")
        self.assertEqual(self.images(), images)
        self.assertTrue(self.attached())

    def test_inventory_failure_preserves_stale_directory(self):
        stale = self.owned_directory("stale")
        image = stale / "ext4.img"
        image.write_bytes(b"retain without complete inventory")
        self.run_command("true", environment=self.failing_sudo("losetup"), expected=1)
        self.assertEqual(image.read_bytes(), b"retain without complete inventory")

    def test_signal_and_kill_during_command_release_resources(self):
        for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=signum):
                ready = self.root / f"ready-{signum}"
                self.process = start_owner(
                    [str(HARNESS), "--", "python3", "-c", """
import pathlib, signal, sys
pathlib.Path(sys.argv[1]).touch()
while True:
    signal.pause()
""", str(ready)], env=self.environment, start_new_session=True,
                )
                self.wait_for(ready.exists, "the wrapped command")
                os.killpg(self.process.pid, signum)
                self.process.wait(timeout=10)
                self.wait_for(lambda: not list(self.runner.iterdir()), "guardian cleanup")
                self.assertEqual(self.attached(), [])

    def test_escaped_term_resistant_descendant_is_reaped_before_unmount(self):
        report = self.root / "descendant"
        self.run_command("python3", "-c", """
import os, pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', '''
import os, pathlib, signal, sys
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
os.chdir(os.environ['OPC_FS_VERITY_SNAPSHOT_ROOT'])
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
while True:
    signal.pause()
''', sys.argv[1]])
deadline = time.monotonic() + 5
while not pathlib.Path(sys.argv[1]).exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('descendant did not start')
    time.sleep(.01)
""", report)
        self.assertFalse(Path(f"/proc/{report.read_text()}").exists())
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_orphan_is_reaped_while_the_wrapped_command_is_still_running(self):
        self.run_command("python3", "-c", """
import os, pathlib, subprocess, sys, time
parent = subprocess.Popen([sys.executable, '-c', '''
import os, sys
child = os.fork()
if child == 0:
    os._exit(0)
print(child, flush=True)
os._exit(0)
'''], stdout=subprocess.PIPE, text=True)
child = int(parent.stdout.read())
parent.wait(timeout=5)
deadline = time.monotonic() + 2
while pathlib.Path(f'/proc/{child}').exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('orphan zombie retained until the gate exits')
    time.sleep(.01)
""")
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_privileged_escaped_descendant_is_reaped_before_unmount(self):
        report = self.root / "privileged-descendant"
        self.run_command("python3", "-c", """
import pathlib, subprocess, sys, time
subprocess.run(['sudo', '-n', sys.executable, '-c', '''
import os, pathlib, signal, sys, time
if os.fork():
    os._exit(0)
os.setsid()
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(2)
os._exit(0)
''', %r], check=True)
deadline = time.monotonic() + 1
while not pathlib.Path(%r).exists():
    assert time.monotonic() < deadline, 'privileged fixture did not become ready'
    time.sleep(.01)
""" % (str(report), str(report)))
        self.assertFalse(Path(f"/proc/{report.read_text()}").exists())
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_privileged_disposal_refuses_a_process_outside_its_direct_children(self):
        parent = subprocess.Popen(["python3", "-c", """
import os, sys, time
child = os.fork()
if not child:
    time.sleep(1)
    os._exit(0)
print(child, flush=True)
_, status = os.waitpid(child, 0)
sys.exit(os.waitstatus_to_exitcode(status))
"""], stdout=subprocess.PIPE, text=True)
        descriptor = None
        try:
            child = int(parent.stdout.readline())
            descriptor = os.pidfd_open(child)
            with self.assertRaisesRegex(RuntimeError, "refusing to signal an unowned process"):
                RUNTIME.privileged_request("kill-child", [descriptor],
                                           owner_start=RUNTIME.process_stat(os.getpid())[1],
                                           child_start=RUNTIME.process_stat(child)[1])
        finally:
            if descriptor is not None:
                os.close(descriptor)
            parent.communicate(timeout=5)
        self.assertEqual(parent.returncode, 0, "privileged disposer signalled the unrelated fixture")

    def test_startup_sweeps_only_unattached_owned_unlocked_directories(self):
        stale = self.owned_directory("stale")
        (stale / "ext4.img").write_bytes(b"unattached image")
        active = self.owned_directory("active")
        (active / "ext4.img").write_bytes(b"unattached active image")
        unknown = self.runner / "unrelated"
        unknown.mkdir(mode=0o700)
        public = self.owned_directory("public")
        (public / "ext4.img").write_bytes(b"unattached public image")
        public.chmod(0o755)
        symlink = self.runner / (RUNTIME.PREFIX + "symlink")
        symlink.symlink_to(unknown, target_is_directory=True)
        descriptor = os.open(active, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self.run_command("true")
        finally:
            os.close(descriptor)
        self.assertFalse(stale.exists())
        self.assertEqual(set(self.runner.iterdir()), {active, unknown, public, symlink})

    def test_startup_preserves_legacy_unattached_images(self):
        legacy = self.runner / "opc-fsverity.stale"
        legacy.mkdir(mode=0o700)
        (legacy / "ext4.img").write_bytes(b"old unattached image")
        outer = self.runner / "fs-verity-runtime.older"
        outer.mkdir(mode=0o700)
        nested = outer / "opc-fsverity.nested"
        nested.mkdir(mode=0o700)
        (nested / "ext4.img").write_bytes(b"old nested unattached image")
        self.run_command("true")
        self.assertTrue(legacy.exists())
        self.assertTrue(outer.exists())
        self.assertEqual((legacy / "ext4.img").read_bytes(), b"old unattached image")
        self.assertEqual((nested / "ext4.img").read_bytes(), b"old nested unattached image")

    def test_startup_preserves_loop_backing_inode_even_through_other_path(self):
        for prefix in (RUNTIME.PREFIX, "fs-verity-runtime.", "opc-fsverity."):
            with self.subTest(prefix=prefix):
                directory = self.runner / (prefix + "attached")
                directory.mkdir(mode=0o700)
                if prefix == RUNTIME.PREFIX:
                    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    RUNTIME.mark_owned(descriptor)
                    os.close(descriptor)
                    (directory / "tmp").mkdir(mode=0o700)
                image = directory / "ext4.img"
                with image.open("xb") as stream:
                    stream.truncate(32 * 1024**2)
                outside = self.root / (prefix + "same-image-other-path")
                os.link(image, outside)
                self.extra_images.append(outside)
                loop = privileged("losetup", "--find", "--show", outside).strip()
                self.run_command("true")
                self.assertTrue(image.is_file())
                self.assertEqual(privileged("losetup", "--associated", outside, "--noheadings", "--output", "NAME").strip(), loop)

    def test_startup_preserves_a_mounted_directory_without_an_image(self):
        directory = self.owned_directory("mounted")
        mountpoint = directory / "tmp"
        source = self.root / "bind-source"
        source.mkdir(mode=0o700)
        (source / "sentinel").write_text("preserve me")
        privileged("mount", "--bind", source, mountpoint)
        self.extra_mounts.append(mountpoint)
        self.run_command("true")
        self.assertEqual((mountpoint / "sentinel").read_text(), "preserve me")


if __name__ == "__main__":
    unittest.main()
