#!/usr/bin/env python3
"""Qualify the explicit local lifecycle cases on a Linux kernel, without skips.

Each test gets a fresh network namespace and private bpffs mount. Compilation
uses Cargo's existing development cache. Evidence binds the complete source,
compiler, build command and emitted binary hashes to the exact selected cases.
A static bundle carries that build evidence to a guest without Rust or Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).with_name("local-kernel-lifecycle-cases.json")
RUNNER_FILES = [
    "ci/qualify-local-kernel-lifecycle.py",
    "ci/local-kernel-lifecycle-cases.json",
    "ci/deny-bpf-enumeration.py",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source() -> dict[str, str]:
    names = subprocess.check_output(
        ["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"], cwd=ROOT
    ).split(b"\0")
    return {
        os.fsdecode(name): sha256(ROOT / os.fsdecode(name))
        for name in names
        if name and (ROOT / os.fsdecode(name)).is_file()
    }


def source_digest(files: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def required_cases(manifest: Path) -> dict[str, list[str]]:
    cases = json.loads(manifest.read_text())
    expected = [case for group in cases.values() for case in group]
    if not expected or len(expected) != len(set(expected)):
        raise ValueError("manifest must contain distinct required cases")
    return cases


def bundle_path(bundle: Path, name: str) -> Path:
    path = (bundle / name).resolve()
    if not path.is_relative_to(bundle.resolve()):
        raise ValueError("bundle member escapes its directory")
    return path


def verify_bundle(bundle: Path, record: dict) -> None:
    if not record["build_complete"] or record["build_exit_code"] != 0 or not record["source_unchanged"]:
        raise ValueError("bundle does not contain a successful, source-bound build")
    if record["source_digest"] != source_digest(record["source"]):
        raise ValueError("bundle source digest mismatch")
    for name in ["head", "rustc", "cargo", "build_command"]:
        if not record[name]:
            raise ValueError(f"bundle build identity is incomplete: {name}")
    for name, digest in record["bundle_files"].items():
        if sha256(bundle_path(bundle, name)) != digest:
            raise ValueError(f"bundle member changed: {name}")
    for name in RUNNER_FILES:
        if record["bundle_files"].get(name) != record["source"][name]:
            raise ValueError(f"bundle runner does not match compiled source: {name}")
    for name in ["build.jsonl", "build.log"]:
        if record["bundle_files"].get(name) != record[name + "_sha256"]:
            raise ValueError(f"bundle is missing build evidence: {name}")
    cases = required_cases(bundle / RUNNER_FILES[1])
    if not record["full_manifest"] or record["selected"] != cases:
        raise ValueError("bundle must contain the complete committed manifest")
    if record["manifest_sha256"] != sha256(bundle / RUNNER_FILES[1]):
        raise ValueError("bundle manifest digest mismatch")
    if set(record["binaries"]) != set(cases):
        raise ValueError("bundle must contain every required test binary")
    for binary in record["binaries"].values():
        if record["bundle_files"].get(binary["path"]) != binary["sha256"]:
            raise ValueError("bundle binary is not bound to its build evidence")


def write_bundle(bundle: Path, evidence: Path, record: dict) -> None:
    bundle.mkdir(parents=True, exist_ok=False)
    payload = json.loads(json.dumps(record))
    payload["bundle_files"] = {}
    copies = [(ROOT / name, name) for name in RUNNER_FILES]
    copies += [(evidence / name, name) for name in ["build.jsonl", "build.log"]]
    for name in ["build.jsonl", "build.log"]:
        payload[name + "_sha256"] = sha256(evidence / name)
    for crate, binary in payload["binaries"].items():
        original = Path(binary["path"])
        headers = subprocess.check_output(["readelf", "-l", str(original)], text=True)
        if re.search(r"^\s*INTERP\s", headers, re.MULTILINE):
            raise RuntimeError(f"guest bundle requires a static binary: {crate}")
        binary["path"] = "binaries/" + crate
        copies.append((original, binary["path"]))
    for original, name in copies:
        destination = bundle_path(bundle, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, destination)
        payload["bundle_files"][name] = sha256(destination)
    verify_bundle(bundle, payload)
    (bundle / "bundle.json").write_text(json.dumps(payload, indent=2) + "\n")


def case_passed(code: int, output: str) -> bool:
    return (
        code == 0
        and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE)
        is not None
        and not re.search(r"skipping:|_SKIPPED:", output, re.IGNORECASE)
    )


def check_kernel(pattern: str | None) -> None:
    if pattern and re.fullmatch(pattern, platform.release()) is None:
        raise RuntimeError(f"guest kernel {platform.release()} does not match {pattern}")


def run_cases(record: dict, evidence: Path, binaries: dict, runner_root: Path, unchanged, save) -> None:
    for crate, binary in binaries.items():
        listing = subprocess.check_output([str(binary), "--ignored", "--list"], text=True)
        available = {line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")}
        missing = set(record["selected"][crate]) - available
        if missing:
            raise RuntimeError(f"required native cases missing from {crate}: {sorted(missing)}")
    for crate, cases in record["selected"].items():
        binary = binaries[crate]
        for case in cases:
            if not unchanged() or sha256(binary) != record["binaries"][crate]["sha256"]:
                raise RuntimeError("source, bundle or emitted binary changed before native execution")
            run = [] if os.geteuid() == 0 else ["sudo", "-n"]
            run += [
                "timeout", "--kill-after=5s", "120s", "env", "OPC_GTPU_RUN_PRIVILEGED=1",
                "unshare", "-n", "-m", "--propagation", "private", "--", "sh", "-eu", "-c",
                'mount -t bpf -o mode=0700 bpf /sys/fs/bpf\nexec "$@"',
                "local-lifecycle-test", sys.executable,
                str(runner_root / "ci/deny-bpf-enumeration.py"),
                str(binary), "--ignored", "--exact", case,
                "--nocapture", "--test-threads=1",
            ]
            log = evidence / f"case-{len(record['cases']):02d}.log"
            started = time.monotonic()
            with log.open("w") as output:
                result = subprocess.run(run, stdout=output, stderr=subprocess.STDOUT, check=False)
            passed = case_passed(result.returncode, log.read_text(errors="replace"))
            record["cases"].append({
                "crate": crate, "test": case, "command": run, "exit_code": result.returncode,
                "seconds": time.monotonic() - started, "passed": passed,
                "log": log.name, "log_sha256": sha256(log),
            })
            save()
            print(f"{case}: {'passed' if passed else 'FAILED'}", flush=True)
            if not passed:
                raise RuntimeError(f"native case failed or skipped: {case}; inspect {log}")
    record["complete"] = True
    record["passed"] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--toolchain", help="optional installed Rust toolchain")
    parser.add_argument("--target", help="optional Cargo build target")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--build-bundle", type=Path, help="build the full static suite for a guest; do not execute")
    mode.add_argument("--run-bundle", type=Path, help="execute a verified static bundle without Cargo or Git")
    parser.add_argument("--require-kernel", help="full regular expression for the execution kernel release")
    parser.add_argument("--case", action="append", default=[], help="exact case; omit for the full manifest")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("native lifecycle qualification requires Linux")
    if (args.build_bundle or args.run_bundle) and args.case:
        parser.error("guest bundles always qualify the full manifest")
    if args.run_bundle and (args.target or args.toolchain):
        parser.error("a guest bundle is already compiled")
    if args.build_bundle and args.require_kernel:
        parser.error("kernel requirements apply to execution, not bundle compilation")
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if (evidence / "result.json").exists():
        parser.error("use a new evidence directory; the build cache is reusable")
    record = {"complete": False, "passed": False, "cases": [], "kernel": platform.uname()._asdict()}
    before = None
    bundle = args.run_bundle.resolve() if args.run_bundle else None
    bundle_record = None
    bundle_digest = None

    def save() -> None:
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    def unchanged() -> bool:
        if bundle:
            if bundle_digest != sha256(bundle / "bundle.json"):
                return False
            verify_bundle(bundle, bundle_record)
            return True
        return before is not None and source() == before

    save()
    try:
        check_kernel(args.require_kernel)
        if bundle:
            bundle_digest = sha256(bundle / "bundle.json")
            bundle_record = json.loads((bundle / "bundle.json").read_text())
            verify_bundle(bundle, bundle_record)
            record.update(bundle_record)
            record.update({
                "bundle_sha256": bundle_digest, "build_kernel": bundle_record["kernel"],
                "kernel": platform.uname()._asdict(), "source_unchanged": None,
                "source_verified_on_execution_host": False,
                "complete": False, "passed": False, "cases": [],
            })
            binaries = {crate: bundle_path(bundle, binary["path"]) for crate, binary in record["binaries"].items()}
            save()
            run_cases(record, evidence, binaries, bundle, unchanged, save)
        else:
            os.chdir(ROOT)
            all_cases = required_cases(MANIFEST)
            unknown = set(args.case) - {case for cases in all_cases.values() for case in cases}
            if unknown:
                raise ValueError(f"unknown cases: {sorted(unknown)}")
            selected = {crate: [case for case in cases if not args.case or case in args.case]
                        for crate, cases in all_cases.items()}
            selected = {crate: cases for crate, cases in selected.items() if cases}
            before = source()
            toolchain = ["+" + args.toolchain] if args.toolchain else []
            command = ["cargo", *toolchain, "test", "--locked"]
            if args.target:
                command.extend(["--target", args.target])
            for crate in selected:
                command.extend(["-p", crate])
            features = []
            if "opc-local-kernel-lifecycle" in selected:
                features.append("opc-local-kernel-lifecycle/store")
            if "opc-ipsec-xfrm" in selected:
                features.append("opc-ipsec-xfrm/scope-store")
            if features:
                command.extend(["--features", ",".join(features)])
            command.extend(["--lib", "--no-run", "--message-format=json"])
            record.update({
                "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                "source": before, "source_digest": source_digest(before),
                "rustc": subprocess.check_output(["rustc", *toolchain, "-vV"], text=True),
                "cargo": subprocess.check_output(["cargo", *toolchain, "--version"], text=True).strip(),
                "profile": {name: os.environ[name] for name in [
                    "CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG",
                    "CARGO_PROFILE_TEST_DEBUG", "CARGO_PROFILE_TEST_OPT_LEVEL", "RUSTFLAGS",
                    "CARGO_BUILD_TARGET", "CARGO_ENCODED_RUSTFLAGS", "CC_x86_64_unknown_linux_musl",
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
                ] if name in os.environ},
                "manifest_sha256": sha256(MANIFEST), "build_command": command,
                "selected": selected, "full_manifest": not args.case, "binaries": {},
                "build_complete": False, "source_verified_on_execution_host": True,
            })
            save()
            with (evidence / "build.jsonl").open("w") as stdout, (evidence / "build.log").open("w") as stderr:
                result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
            record["build_exit_code"] = result.returncode
            if result.returncode:
                raise RuntimeError("native test compilation failed; inspect build.log")
            artifacts = [json.loads(line) for line in (evidence / "build.jsonl").read_text().splitlines()]
            if not unchanged():
                raise RuntimeError("source changed during compilation")
            binaries = {}
            for crate in selected:
                found = {row["executable"] for row in artifacts
                         if row.get("reason") == "compiler-artifact" and row.get("executable")
                         and row.get("profile", {}).get("test")
                         and row["target"]["name"] == crate.replace("-", "_")}
                if len(found) != 1:
                    raise RuntimeError(f"expected exactly one emitted test binary for {crate}")
                binary = Path(found.pop()).resolve()
                binaries[crate] = binary
                record["binaries"][crate] = {"path": str(binary), "sha256": sha256(binary)}
            record["build_complete"] = True
            record["source_unchanged"] = True
            save()
            if args.build_bundle:
                write_bundle(args.build_bundle.resolve(), evidence, record)
                record["bundle"] = str(args.build_bundle.resolve())
                record["bundle_sha256"] = sha256(args.build_bundle.resolve() / "bundle.json")
            else:
                run_cases(record, evidence, binaries, ROOT, unchanged, save)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        record["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        try:
            stable = unchanged()
        except (OSError, ValueError, KeyError, TypeError):
            stable = False
        record["bundle_unchanged" if bundle else "source_unchanged"] = stable
        record["passed"] = record["passed"] and stable
        for name in ["build.jsonl", "build.log"]:
            if (evidence / name).exists():
                record[name + "_sha256"] = sha256(evidence / name)
        save()
    if args.build_bundle:
        return 0 if "bundle_sha256" in record and record["source_unchanged"] and "error" not in record else 1
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
