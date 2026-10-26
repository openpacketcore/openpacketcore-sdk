#!/usr/bin/env python3
"""Build a pinned patched kernel and qualify ESP dummies in a diskless isolated guest."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile

if sys.flags.optimize:
    raise RuntimeError("qualification requires Python assertions enabled")

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mobike_kernel", ROOT / "ci/qualify-n3-mobike-kernel.py"
)
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)
COMMON = (
    "EXPERT",
    "MULTIUSER",
    "PRINTK",
    "BUG",
    "SMP",
    "FUTEX",
    "POSIX_TIMERS",
    "EPOLL",
    "EVENTFD",
    "SIGNALFD",
    "TIMERFD",
    "ADVISE_SYSCALLS",
    "BINFMT_ELF",
    "BINFMT_SCRIPT",
    "BLK_DEV_INITRD",
    "RD_GZIP",
    "TTY",
    "UNIX98_PTYS",
    "PROC_FS",
    "SYSFS",
    "SYSCTL",
    "DEVTMPFS",
    "DEVTMPFS_MOUNT",
    "NAMESPACES",
    "UTS_NS",
    "PID_NS",
    "NET_NS",
    "NET",
    "UNIX",
    "PACKET",
    "INET",
    "IPV6",
    "NETFILTER",
    "XFRM_USER",
    "XFRM_STATISTICS",
    "INET_ESP",
    "INET6_ESP",
    "CRYPTO_GCM",
    "CRYPTO_CBC",
    "CRYPTO_AES",
    "CRYPTO_HMAC",
    "CRYPTO_SHA256",
    "CRYPTO_AUTHENC",
    "CRYPTO_SEQIV",
    "CRYPTO_ECHAINIV",
    "NETDEVICES",
    "NET_CORE",
    "VETH",
    "IPV6_MULTIPLE_TABLES",
)


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_program(source, destination, root):
    source, destination = Path(source).resolve(), root / str(destination).lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    result = subprocess.run(
        ["ldd", str(source)],
        capture_output=True,
        text=True,
        env=dict(os.environ, LC_ALL="C"),
    )
    if result.returncode:
        assert result.returncode == 1 and "not a dynamic executable" in result.stderr, (
            result
        )
        with source.open("rb") as stream:
            assert stream.read(4) == b"\x7fELF", source
        return
    listing = result.stdout
    assert "not found" not in listing, listing
    for library in re.findall(r"(?:=>\s+)?(/[^\s]+)", listing):
        target = root / library.lstrip("/")
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(library).resolve(), target)


def initramfs(binary, directory, output):
    root = directory / "root"
    for name in (
        "bin",
        "sbin",
        "usr/bin",
        "proc",
        "sys",
        "dev",
        "tmp",
        "run/netns",
        "var/run",
        "etc",
        "test",
    ):
        (root / name).mkdir(parents=True, exist_ok=True)
    copy_program(shutil.which("busybox"), "/bin/busybox", root)
    for name in ("sh", "mount", "mkdir", "poweroff", "uname"):
        (root / "bin" / name).symlink_to("/bin/busybox")
    copy_program(shutil.which("ip"), "/sbin/ip", root)
    python = Path(sys.executable).resolve()
    copy_program(python, python, root)
    stdlib = Path(sysconfig.get_path("stdlib"))
    shutil.copytree(
        stdlib,
        root / str(stdlib).lstrip("/"),
        ignore=shutil.ignore_patterns(
            "__pycache__",
            "site-packages",
            "dist-packages",
            "test",
            "tests",
            "tkinter",
            "idlelib",
            "ensurepip",
        ),
    )
    for library in (stdlib / "lib-dynload").glob("*.so"):
        copy_program(library, library, root)
    copy_program(binary, "/test/sender", root)
    shutil.copy2(ROOT / "kernel/xfrm-tfc-dummy/selftest.py", root / "test/selftest.py")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (root / "etc/group").write_text("root:x:0:\n")
    script = root / "init"
    script.write_text(
        "#!/bin/sh\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
        "export PYTHON_COLORS=0\n"
        "mount -t proc proc /proc\nmount -t sysfs sysfs /sys\n"
        "mount -t devtmpfs devtmpfs /dev\nuname -a\n"
        f"{python} /test/selftest.py --sender /test/sender\n"
        "result=$?\necho OPC_TFC_PROBE_EXIT=$result\npoweroff -f\n"
    )
    script.chmod(0o755)
    with (directory / "initramfs.cpio").open("wb") as archive:
        names = (
            b"\0".join(
                os.fsencode("." + str(p)[len(str(root)) :])
                for p in sorted(root.rglob("*"))
            )
            + b"\0"
        )
        run(
            ["cpio", "--null", "-o", "--format=newc", "--owner=0:0"],
            cwd=root,
            input=names,
            stdout=archive,
        )
    with output.open("wb") as compressed:
        run(["gzip", "-1", "-c", directory / "initramfs.cpio"], stdout=compressed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="export the kernel/initramfs for a separate native VM host",
    )
    args = parser.parse_args()
    assert sys.platform == "linux"
    assert 1 <= args.jobs <= 32 and args.binary.is_file()
    machine = platform.machine()
    assert machine in ("x86_64", "aarch64"), machine
    output, cache = args.output.resolve(), args.cache.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    patch = ROOT / "kernel/xfrm-tfc-dummy/linux.patch"
    source_archive = cache / "linux-n3-mobike.tar.gz"
    REFERENCE.download(
        f"https://codeload.github.com/torvalds/linux/tar.gz/{REFERENCE.COMMIT}",
        source_archive,
        REFERENCE.SOURCE_SHA,
    )
    with tempfile.TemporaryDirectory(prefix="esp-tfc-build-", dir=cache) as temporary:
        directory = Path(temporary)
        with tarfile.open(source_archive) as source:
            source.extractall(directory, filter="data")
        source = directory / f"linux-{REFERENCE.COMMIT}"
        build = directory / "build"
        build.mkdir()
        run(
            [
                "perl",
                source / "scripts/checkpatch.pl",
                "--no-tree",
                "--no-signoff",
                patch,
            ]
        )
        with patch.open("rb") as stream:
            run(["patch", "--fuzz=0", "-p1"], cwd=source, stdin=stream)
        with (output / "kernel-build.log").open("w") as log:
            make = ["make", "-C", source, f"O={build}"]
            run(make + ["tinyconfig"], stdout=log, stderr=subprocess.STDOUT)
            features = COMMON + (
                (
                    "64BIT",
                    "ACPI",
                    "SERIAL_8250",
                    "SERIAL_8250_CONSOLE",
                    "CRYPTO_AES_NI_INTEL",
                )
                if machine == "x86_64"
                else (
                    "SERIAL_AMBA_PL011",
                    "SERIAL_AMBA_PL011_CONSOLE",
                    "CRYPTO_AES_ARM64_CE_BLK",
                    "CRYPTO_GHASH_ARM64_CE",
                )
            )
            options = [source / "scripts/config", "--file", build / ".config"]
            for feature in features:
                options += ["--enable", feature]
            options += [
                "--disable",
                "LOCALVERSION_AUTO",
                "--disable",
                "DEBUG_INFO",
                "--set-str",
                "LOCALVERSION",
                "-opc-tfc-v1",
            ]
            run(options, stdout=log, stderr=subprocess.STDOUT)
            run(make + ["olddefconfig"], stdout=log, stderr=subprocess.STDOUT)
            config = (build / ".config").read_text()
            for feature in features:
                assert f"CONFIG_{feature}=y\n" in config, feature
            image = (
                "arch/x86/boot/bzImage"
                if machine == "x86_64"
                else "arch/arm64/boot/Image"
            )
            run(
                make
                + [f"-j{args.jobs}", "bzImage" if machine == "x86_64" else "Image"],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        shutil.copy2(build / image, output / "kernel")
        shutil.copy2(build / ".config", output / "config")
        initramfs(args.binary.resolve(), directory, output / "initramfs.gz")
    receipt = dict(
        source_commit=REFERENCE.COMMIT,
        source_sha256=REFERENCE.SOURCE_SHA,
        patch_sha256=digest(patch),
        binary_sha256=digest(args.binary),
        kernel_sha256=digest(output / "kernel"),
        config_sha256=digest(output / "config"),
        initramfs_sha256=digest(output / "initramfs.gz"),
        architecture=machine,
        compiler=subprocess.check_output(["cc", "--version"], text=True).splitlines()[
            0
        ],
    )
    (output / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if args.prepare_only:
        print("Prepared artifacts; runtime qualification has not run.")
        return
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    command = ["qemu-system-x86_64" if machine == "x86_64" else "qemu-system-aarch64"]
    command += [
        "-machine",
        "pc" if machine == "x86_64" else "virt,gic-version=3",
        "-accel",
        "kvm" if kvm else "tcg",
        "-cpu",
        "host" if kvm else "max",
        "-smp",
        "2",
        "-m",
        "1024",
        "-nographic",
        "-nic",
        "none",
        "-no-reboot",
        "-kernel",
        output / "kernel",
        "-initrd",
        output / "initramfs.gz",
        "-append",
        "console="
        + ("ttyS0" if machine == "x86_64" else "ttyAMA0")
        + " rdinit=/init panic=-1",
    ]
    with (output / "guest-serial.log").open("w") as log:
        run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=300,
        )
    with (output / "wire-verification.json").open("w") as result:
        run(
            [
                sys.executable,
                ROOT / "kernel/xfrm-tfc-dummy/verify-wire.py",
                output / "guest-serial.log",
            ],
            stdout=result,
        )
    print((output / "wire-verification.json").read_text())


if __name__ == "__main__":
    main()
