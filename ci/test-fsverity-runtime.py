#!/usr/bin/env python3
"""Linux integration contracts for the private fs-verity filesystem owner.

These tests mount real images and require the same passwordless mount, chown,
umount and losetup privileges as the harness. Fixtures always clean their own
resources, including the leftovers from a deliberately interrupted old helper.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "ci/setup-fsverity-tmp.sh"


def privileged(*args):
    return subprocess.run(
        ["/usr/bin/sudo", "-n", *map(str, args)], check=True,
        capture_output=True, text=True, timeout=10,
    ).stdout


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fsverity-test-")
        self.root = Path(self.temporary.name)
        self.runner = self.root / "runner"
        self.runner.mkdir()
        self.environment = os.environ | {
            "RUNNER_TEMP": str(self.runner),
            "GITHUB_ENV": str(self.root / "github-env"),
        }
        self.process = None

    def images(self):
        return list(self.runner.glob("*/ext4.img"))

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
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        # Even the RED must not strand a loop mount on the shared host.
        for image in self.images():
            mountpoint = image.parent / "tmp"
            mounted = subprocess.run(
                ["findmnt", "--mountpoint", str(mountpoint), "--noheadings"],
                capture_output=True, timeout=5,
            )
            if mounted.returncode == 0:
                privileged("umount", mountpoint)
            for loop in privileged("losetup", "--associated", image, "--noheadings", "--output", "NAME").split():
                privileged("losetup", "--detach", loop)
        self.temporary.cleanup()

    def wait_for(self, predicate, description, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail(f"timed out waiting for {description}")

    def test_interrupted_setup_releases_mount_loop_and_image(self):
        """Interrupt after mount succeeds but before setup can export its root."""
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
subprocess.run(['/usr/bin/sudo', '-n', *sys.argv[1:]], check=True)
if sys.argv[1] == 'mount':
    Path(os.environ['MOUNT_READY']).write_text(str(os.getpid()))
    while True:
        signal.pause()
""")
        sudo.chmod(0o755)
        self.process = subprocess.Popen(
            [str(HARNESS), "--", "true"],
            env=self.environment | {"PATH": str(shim) + ":" + os.environ["PATH"], "MOUNT_READY": str(ready)},
            start_new_session=True,
        )
        self.wait_for(ready.exists, "the real loop mount")
        self.assertTrue(self.attached(), "fixture did not mount a real image")
        os.killpg(self.process.pid, signal.SIGTERM)
        self.process.wait(timeout=10)
        # Give an independent cleanup guardian time to finish after interruption.
        deadline = time.monotonic() + 10
        while list(self.runner.iterdir()) and time.monotonic() < deadline:
            time.sleep(0.02)
        leftovers = {"directories": [str(p) for p in self.runner.iterdir()], "attached": self.attached()}
        print("interruption leftovers: " + json.dumps(leftovers), flush=True)
        self.assertEqual(leftovers, {"directories": [], "attached": []})


if __name__ == "__main__":
    unittest.main()
