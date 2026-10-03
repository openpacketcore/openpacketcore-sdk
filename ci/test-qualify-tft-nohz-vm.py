#!/usr/bin/env python3
"""Exercise the real nohz VM driver with deterministic, offline transports."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "ci/qualify-tft-nohz-vm.sh"
OLD_BOOT = "11111111-1111-4111-8111-111111111111"
NEW_BOOT = "22222222-2222-4222-8222-222222222222"
QUALIFIED = "OPC_GTPU_TFT_NOHZ_VM_QUALIFIED"


def fake_command(command, args):
    """Replace only VM/network dependencies; Bash control flow stays real."""
    control = Path(os.environ["FAKE_TFT_CONTROL"])
    state_path = control / "state.json"
    state = json.loads(state_path.read_text())

    def finish(status=0, event=None):
        if event:
            state["events"].append(event)
        state_path.write_text(json.dumps(state))
        return status

    def reboot():
        state["reboot_requested"] = True
        return finish(state["reboot_status"], "reboot")

    if command == "curl":
        Path(args[args.index("--output") + 1]).write_text("offline image fixture\n")
        return 0
    if command == "sha256sum":
        if args == ["-c", "-"]:
            # The pinned cloud image is external; local fixture checksums below
            # still use the real sha256sum command and real files.
            _, image_path = sys.stdin.read().strip().split(maxsplit=1)
            return int(Path(image_path).read_text() != "offline image fixture\n")
        os.execv(os.environ["FAKE_TFT_SHA256"], ["sha256sum", *args])
    if command == "ssh-keygen":
        key = Path(args[args.index("-f") + 1])
        key.write_text("offline private key fixture\n")
        key.with_suffix(".pub").write_text("offline public key fixture\n")
        return 0
    if command == "cloud-localds":
        Path(args[0]).write_text("offline seed fixture\n")
        return 0
    if command == "sudo":
        if args == ["test", "-c", "/dev/kvm"]:
            return 1
        if args[:2] == ["test", "-s"]:
            return int(not Path(args[2]).is_file())
        if args[0] == "cat":
            print(Path(args[1]).read_text(), end="")
            return 0
        if args[0] == "qemu-system-x86_64":
            Path(args[args.index("-pidfile") + 1]).write_text("12345\n")
            return finish(event="vm-start")
        if args == ["kill", "12345"]:
            return finish(event="vm-cleanup")
    if command == "scp":
        return finish(event="copy")
    if command == "ssh":
        remote = args[args.index("opc@127.0.0.1") + 1:]
        if remote == ["cat /proc/sys/kernel/random/boot_id"]:
            if not state.get("reboot_requested"):
                print(OLD_BOOT)
                return finish(event="initial-boot")
            state["boot_queries"] += 1
            if state["boot_behavior"] == "unreachable":
                return finish(255, "boot-unreachable")
            if state["boot_behavior"] == "unchanged" or state["boot_queries"] == 1:
                print(OLD_BOOT)
                return finish(event="boot-unchanged")
            if state["boot_queries"] == 2:
                return finish(255, "boot-unreachable")
            print(NEW_BOOT)
            return finish(event="boot-changed")
        if remote[:3] == ["bash", "-s", "--"]:
            script = sys.stdin.read()
            if "sudo grubby" in script:
                if state["setup_status"]:
                    return finish(state["setup_status"], "setup-failed")
                finish(event="setup-completed")
                # Characterize the original combined setup/reboot session too:
                # its transport can close after all setup commands succeeded.
                if "sudo systemctl reboot --no-block" in script:
                    return reboot()
                return 0
            if "effective_nohz_full=" in script:
                print("CONFIG_NO_HZ_FULL=y\neffective_nohz_full=1")
                return finish(state["kernel_status"], "kernel-check")
            if "sudo dpkg -i" in script:
                return finish(event="package-install")
        if remote == ["sudo systemctl reboot --no-block"]:
            return reboot()
        if len(remote) == 1 and "chmod 0755 datapath grace" in remote[0]:
            return finish(event="binary-before")
        if len(remote) == 1 and "/tmp/opc-tft-nohz/grace --ignored" in remote[0]:
            print("test result: ok. 1 passed; 0 failed; 0 ignored;")
            print("OPC_GTPU_MAP_READER_GRACE_PROVEN")
            print("OPC_GTPU_MAP_READER_GRACE_NEGATIVE_CONTROL_PROVEN")
            if not state["omit_thread_control"]:
                print("OPC_GTPU_MAP_READER_GRACE_THREAD_CONTROL_PROVEN")
            return finish(state["grace_status"], "grace-proof")
        if len(remote) == 1 and "/tmp/opc-tft-nohz/datapath --ignored" in remote[0]:
            print("test result: ok. 3 passed; 0 failed; 0 ignored;")
            for _ in range(3):
                print("OPC_GTPU_TFT_NOHZ_PROFILE_PROVEN")
                print("OPC_GTPU_TFT_NOHZ_CAPABILITY_PROVEN")
            print("OPC_GTPU_TFT_NOHZ_BANK_REUSE_PROVEN")
            print("OPC_GTPU_TFT_NOHZ_LIFECYCLE_PROVEN")
            print("OPC_GTPU_TFT_IPV4_LIVE_PROVEN")
            print("OPC_GTPU_TFT_REMOVAL_FENCE_DEFAULT_PROVEN: offline fixture")
            print("OPC_GTPU_TFT_REMOVAL_CONTINUITY_PROVEN: offline fixture")
            if state["packet_skip"]:
                print("skipping: offline negative fixture")
            return finish(state["packet_status"], "packet-proof")
        if remote == ["cd /tmp/opc-tft-nohz && sha256sum -c SHA256SUMS"]:
            return finish(state["binary_after_status"], "binary-after")
    print(f"unexpected offline command: {command} {args!r}", file=sys.stderr)
    return 98


class GuestRebootTests(unittest.TestCase):
    def run_driver(self, profile="el9", **scenario):
        directory = tempfile.TemporaryDirectory(prefix="tft-nohz-offline-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        commands = root / "commands"
        commands.mkdir()
        wrapper = commands / "fake-command"
        wrapper.write_text(
            "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
            + shlex.quote(str(Path(__file__).resolve()))
            + ' --fake-command "${0##*/}" "$@"\n'
        )
        wrapper.chmod(0o755)
        for command in ("curl", "sha256sum", "ssh-keygen", "cloud-localds",
                        "sudo", "scp", "ssh"):
            (commands / command).symlink_to(wrapper)
        # Advance the fake clock without changing the driver's attempt bound or
        # interval; retaining every requested sleep detects bound regressions.
        sleep = commands / "sleep"
        sleep.write_text(
            '#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = 2 ] || exit 98\n'
            'printf "%s\\n" "$1" >> "$FAKE_TFT_CONTROL/sleeps"\n'
        )
        sleep.chmod(0o755)
        state = {
            "events": [], "boot_queries": 0, "boot_behavior": "changed",
            "setup_status": 0, "reboot_status": 0, "kernel_status": 0,
            "grace_status": 0, "omit_thread_control": False,
            "packet_status": 0, "packet_skip": False, "binary_after_status": 0,
        }
        state.update(scenario)
        (root / "state.json").write_text(json.dumps(state))
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        binaries, packages = root / "binaries", root / "packages"
        for destination, files in (
            (binaries, {"datapath": "offline\n", "grace": "offline\n",
                        "source-revision": revision + "\n"}),
            (packages, {"package-versions.txt": "offline\n", "repositories.txt": "offline\n"}),
        ):
            destination.mkdir()
            for name, content in files.items():
                (destination / name).write_text(content)
            (destination / "SHA256SUMS").write_text("".join(
                f"{hashlib.sha256(content.encode()).hexdigest()}  {name}\n"
                for name, content in files.items()
            ))
        env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
                   FAKE_TFT_CONTROL=str(root), FAKE_TFT_SHA256=shutil.which("sha256sum"))
        result = subprocess.run(
            ["bash", str(DRIVER), profile, str(binaries), str(packages), str(root / "vm")],
            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30,
        )
        state = json.loads((root / "state.json").read_text())
        sleeps = (root / "sleeps").read_text().splitlines() if (root / "sleeps").exists() else []
        return result, state, root / "vm/evidence", sleeps

    def assert_refused(self, result, logs):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(QUALIFIED, result.stdout)
        self.assertFalse((logs / "binary-after.txt").exists())

    def test_success_and_transport_disconnect_require_changed_boot(self):
        for profile in ("linux68", "el9"):
            for status in (0, 255):
                with self.subTest(profile=profile, reboot_status=status):
                    result, state, logs, sleeps = self.run_driver(profile, reboot_status=status)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual((logs / "boot-before.txt").read_text().strip(), OLD_BOOT)
                    self.assertEqual((logs / "boot-after.txt").read_text().strip(), NEW_BOOT)
                    self.assertEqual((logs / "reboot-request.txt").read_text(),
                                     f"ssh_exit_status={status}\n")
                    self.assertEqual(result.stdout.count(QUALIFIED), 1)
                    self.assertEqual(sleeps, ["2", "2"])
                    events = state["events"]
                    self.assertLess(events.index("setup-completed"), events.index("reboot"))
                    self.assertLess(events.index("boot-changed"), events.index("kernel-check"))
                    self.assertLess(events.index("grace-proof"), events.index("packet-proof"))
                    self.assertIn("binary-after", events)

    def test_missing_changed_or_reachable_boot_exhausts_original_bound(self):
        for profile, status, behavior, attempts in (
            ("linux68", 0, "unchanged", 120),
            ("el9", 255, "unchanged", 150),
            ("el9", 255, "unreachable", 150),
        ):
            with self.subTest(profile=profile, reboot_status=status, boot=behavior):
                result, state, logs, sleeps = self.run_driver(
                    profile, reboot_status=status, boot_behavior=behavior
                )
                self.assert_refused(result, logs)
                self.assertIn("guest did not complete the required boot", result.stderr)
                self.assertEqual(state["boot_queries"], attempts)
                self.assertEqual(sleeps, ["2"] * attempts)
                self.assertFalse((logs / "boot-after.txt").exists())
                self.assertNotIn("kernel-check", state["events"])

    def test_setup_failure_never_requests_reboot(self):
        for status in (1, 255):
            with self.subTest(setup_status=status):
                result, state, logs, _ = self.run_driver(setup_status=status)
                self.assert_refused(result, logs)
                self.assertEqual(result.returncode, status)
                self.assertNotIn("reboot", state["events"])
                self.assertFalse((logs / "boot-after.txt").exists())
                self.assertFalse((logs / "reboot-request.txt").exists())

    def test_other_reboot_error_fails_without_waiting(self):
        result, state, logs, _ = self.run_driver(reboot_status=42)
        self.assert_refused(result, logs)
        self.assertEqual(result.returncode, 42)
        self.assertEqual(state["boot_queries"], 0)
        self.assertFalse((logs / "boot-after.txt").exists())

    def test_changed_boot_does_not_hide_later_kernel_or_proof_failure(self):
        for failure in ("kernel_status", "grace_status", "packet_status"):
            with self.subTest(failure=failure):
                result, _, logs, _ = self.run_driver(reboot_status=255, **{failure: 42})
                self.assert_refused(result, logs)
                self.assertEqual(result.returncode, 42)
                self.assertEqual((logs / "boot-after.txt").read_text().strip(), NEW_BOOT)

    def test_changed_boot_requires_every_grace_control_marker(self):
        result, state, logs, _ = self.run_driver(reboot_status=255, omit_thread_control=True)
        self.assert_refused(result, logs)
        self.assertIn("grace-proof", state["events"])
        self.assertNotIn("packet-proof", state["events"])

    def test_changed_boot_still_rejects_skipped_packet_proofs(self):
        result, _, logs, _ = self.run_driver(reboot_status=255, packet_skip=True)
        self.assert_refused(result, logs)
        self.assertIn("nohz_full packet proofs skipped", result.stderr)

    def test_changed_boot_requires_final_binary_check(self):
        result, state, logs, _ = self.run_driver(reboot_status=255, binary_after_status=42)
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertNotIn(QUALIFIED, result.stdout)
        self.assertIn("binary-after", state["events"])
        self.assertTrue((logs / "boot-after.txt").exists())


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fake-command"]:
        sys.exit(fake_command(sys.argv[2], sys.argv[3:]))
    unittest.main()
