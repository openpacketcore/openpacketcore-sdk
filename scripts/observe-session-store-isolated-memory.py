#!/usr/bin/env python3
"""Observe one cold voter image per fresh process; never qualify pod memory.

Run inside the authorized build controller with CARGO_BUILD_JOBS and
OPC_FS_VERITY_SNAPSHOT_ROOT set. The snapshot root must be a fresh directory on
an existing fs-verity filesystem; this program does not create mounts.
The manifest describes three existing sealed snapshots (path, device, inode,
bytes, fsverity_measurement and expected table counts). Derived files and all
evidence are retained. Only the test's freshly extracted raw input cache is
removed after its original installer finishes.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import threading
import time


TEST = "consensus::native::isolated_snapshot_memory::one_voter_cold_image_memory_in_a_fresh_process"
STAGES = ["baseline", "original_install_complete", "generation_written",
          "catalog_admitted", "cold_image_retained", "native_roots_released"]


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def kib(text, field):
    rows = [line.split() for line in text.splitlines() if line.startswith(field + ":")]
    require(len(rows) == 1 and len(rows[0]) == 3, "missing or duplicate memory field")
    require(rows[0][2] == "kB" and rows[0][1].isdigit(), "invalid memory units/value")
    return int(rows[0][1])


def process_identity(pid):
    # comm can contain spaces and parentheses. Field 22 is starttime.
    tail = Path(f"/proc/{pid}/stat").read_text().rpartition(") ")[2].split()
    require(len(tail) > 19, "invalid process identity")
    return int(tail[19])


def memory_sample(pid, identity):
    require(process_identity(pid) == identity, "PID reused before sample")
    smaps = Path(f"/proc/{pid}/smaps_rollup").read_text()
    status = Path(f"/proc/{pid}/status").read_text()
    require(process_identity(pid) == identity, "PID reused during sample")
    return dict(pid=pid, process_start_ticks=identity, monotonic_ns=time.monotonic_ns(),
                smaps_rss_kib=kib(smaps, "Rss"), smaps_pss_kib=kib(smaps, "Pss"),
                vmhwm_estimate_kib=kib(status, "VmHWM"))


def sealed_sources(manifest, root):
    rows = []
    for expected in manifest["snapshots"]:
        path = Path(expected["path"])
        require(path.resolve(strict=True).is_relative_to(root), "source outside declared root")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            observed = os.fstat(fd)
            require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1,
                    "source is not a singly linked regular file")
            require(observed.st_uid == os.geteuid(), "source owner differs")
            require((observed.st_dev, observed.st_ino, observed.st_size) ==
                    (expected["device"], expected["inode"], expected["bytes"]),
                    "source descriptor identity differs")
            digest = bytearray(struct.pack("=HH", 0, 32) + bytes(32))
            fcntl.ioctl(fd, (3 << 30) | (4 << 16) | (ord("f") << 8) | 134, digest, True)
            require(struct.unpack("=HH", digest[:4]) == (1, 32), "unexpected verity algorithm")
            measured = "sha256:" + digest[4:].hex()
            require(measured == expected["fsverity_measurement"], "source seal differs")
            rows.append(dict(path=str(path), device=observed.st_dev, inode=observed.st_ino,
                             bytes=observed.st_size, mtime_ns=observed.st_mtime_ns,
                             ctime_ns=observed.st_ctime_ns, fsverity_measurement=measured))
        finally:
            os.close(fd)
    return rows


def observe(command, env, evidence, voter):
    stages, samples, errors = [], [], []
    selected = {}
    lock = threading.Lock()
    started = time.monotonic_ns()
    with (evidence / f"voter-{voter}.log").open("w") as log, \
            (evidence / f"voter-{voter}.samples.jsonl").open("w") as sample_log:
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)

        def output():
            try:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    print(line, end="", flush=True)
                    _, marker, payload = line.partition("isolated_voter_stage=")
                    if marker:
                        event = json.loads(payload)
                        require(event["voter"] == voter and event["voter_instances"] == 1,
                                "mixed voter measurements")
                        require(event["deployment_memory_qualified"] is False,
                                "cold fixture claims deployment qualification")
                        pid = event["pid"]
                        with lock:
                            if not selected:
                                selected.update(pid=pid, identity=process_identity(pid))
                            require(selected["pid"] == pid, "test process changed")
                            stages.append(event)
            except Exception as error:
                errors.append(repr(error))

        reader = threading.Thread(target=output)
        reader.start()
        while process.poll() is None:
            with lock:
                target = selected.copy()
            if target:
                try:
                    sample = memory_sample(target["pid"], target["identity"])
                    samples.append(sample)
                    sample_log.write(json.dumps(sample) + "\n")
                    sample_log.flush()
                except (FileNotFoundError, ProcessLookupError):
                    # Test exit can precede cargo exit. It is not a zero-RSS sample.
                    pass
                except Exception as error:
                    errors.append(repr(error))
            time.sleep(0.25)
        code = process.wait()
        reader.join()
        process.stdout.close()
    observed = samples + stages
    complete = (code == 0 and not errors and bool(samples) and
                [event["stage"] for event in stages] == STAGES)
    times = [sample["monotonic_ns"] for sample in samples]
    return dict(voter=voter, command=command, exit_code=code, measurement_complete=complete,
                elapsed_ns=time.monotonic_ns() - started, process=selected,
                sample_count=len(samples), stages=stages, errors=errors,
                sample_interval_ms=250,
                maximum_sample_gap_ns=max((b - a for a, b in zip(times, times[1:])), default=None),
                maximum_observed_smaps_rss_kib=max((s["smaps_rss_kib"] for s in observed), default=None),
                maximum_observed_smaps_pss_kib=max((s["smaps_pss_kib"] for s in observed), default=None),
                maximum_observed_vmhwm_estimate_kib=max((s["vmhwm_estimate_kib"] for s in observed), default=None),
                transient_peaks_may_be_missed=True, voter_instances=1,
                scope="one_cold_image_including_original_install_and_conversion",
                live_replica_runtime=False, deployment_memory_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--derived-directory", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    require(len(manifest["snapshots"]) == 3, "expected three independently sealed source images")
    require(args.evidence_directory.is_dir(), "evidence directory must already exist")
    require(not (args.evidence_directory / "isolated-memory-preflight.json").exists(),
            "measurement evidence must be fresh")
    require(not args.derived_directory.exists(), "derived directory must be fresh")
    require(os.environ.get("OPC_FS_VERITY_QUALIFICATION") == "required", "verity is required")
    snapshot_root = Path(os.environ["OPC_FS_VERITY_SNAPSHOT_ROOT"])
    require(snapshot_root.is_dir(), "existing snapshot directory required")
    mutable_space = os.statvfs(args.derived_directory.parent)
    require(mutable_space.f_bavail * mutable_space.f_frsize >= 40 * 1024**3,
            "need 40 GiB free for retained derived files on the existing mutable filesystem")
    sealed_space = os.statvfs(snapshot_root)
    require(sealed_space.f_bavail * sealed_space.f_frsize >=
            max(source["bytes"] for source in manifest["snapshots"]) + 1024**3,
            "insufficient existing fs-verity space for one fresh extraction cache")
    require(not os.environ.get("LD_PRELOAD"), "allocator override is not allowed")
    source_root = args.source_root.resolve(strict=True)
    before = sealed_sources(manifest, source_root)
    args.derived_directory.mkdir()
    command = ["cargo", "test", "--locked", "--release", "-p", "opc-session-store",
               "--lib", "--all-features", "--", "--ignored", "--exact", TEST,
               "--nocapture", "--test-threads=1"]
    preflight = dict(timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     command=command, manifest_sha256=sha(args.manifest), controller_sha256=sha(__file__),
                     sources=before, affinity=sorted(os.sched_getaffinity(0)),
                     cargo_build_jobs=os.environ.get("CARGO_BUILD_JOBS"),
                     host_load_average=os.getloadavg(), quiet_host=False,
                     performance_qualification=False, deployment_memory_qualified=False)
    write_json(args.evidence_directory / "isolated-memory-preflight.json", preflight)
    results = []
    for voter in range(3):
        env = os.environ.copy()
        env.update(OPC_NATIVE_RETAINED_SNAPSHOT_MANIFEST=str(args.manifest.resolve()),
                   OPC_NATIVE_RETAINED_OUTPUT=str(args.derived_directory.resolve() / f"voter-{voter}"),
                   OPC_NATIVE_RETAINED_VOTER=str(voter))
        result = observe(command, env, args.evidence_directory, voter)
        results.append(result)
        write_json(args.evidence_directory / f"voter-{voter}.result.json", result)
        if not result["measurement_complete"]:
            break
    after = sealed_sources(manifest, source_root)
    files = [dict(path=str(path), bytes=path.stat().st_size, sha256=sha(path))
             for path in sorted(args.derived_directory.rglob("*")) if path.is_file()]
    identities = {(r["process"].get("pid"), r["process"].get("identity")) for r in results}
    complete = (before == after and len(results) == 3 and len(identities) == 3 and
                all(r["measurement_complete"] for r in results))
    result = dict(measurement_complete=complete, voters=results,
                  sources_before=before, sources_after=after, sources_unchanged=before == after,
                  derived_artifacts=files, controller_sha256=sha(__file__),
                  preflight_sha256=sha(args.evidence_directory / "isolated-memory-preflight.json"),
                  quiet_host=False, performance_qualification=False, deployment_memory_qualified=False)
    write_json(args.evidence_directory / "isolated-memory-result.json", result)
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
