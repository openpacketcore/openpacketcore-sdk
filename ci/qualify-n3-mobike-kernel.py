#!/usr/bin/env python3
"""Run the supported N3 whole-roster profile in an isolated, pinned Linux VM.

The standard XFRM job owns observation/BTF and unsupported-kernel evidence.
This kernel deliberately qualifies only migration, packet continuity and restart.
All download inputs are immutable and digest checked; no host kernel is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request

COMMIT = "fd73f4a6659897191fa0d40695fe370925dd3780"
SOURCE_SHA = "1846a6d56bda7798cdff7b743d54975f1e96cbcf89cb48d5f92b2b863cdf262f"
IMAGE_URL = "https://cloud-images.ubuntu.com/releases/noble/release-20260705/ubuntu-24.04-server-cloudimg-amd64.img"
IMAGE_SHA = "ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6"
RELEASE = "7.3.0-rc3-opc-n3-mobike"
BUILTINS = (
    "XFRM", "XFRM_USER", "XFRM_MIGRATE", "XFRM_INTERFACE", "INET_ESP", "INET_ESPINTCP",
    "INET6_ESP", "NET_NS", "USER_NS", "IP_ADVANCED_ROUTER", "IP_MULTIPLE_TABLES",
    "IPV6_MULTIPLE_TABLES", "CRYPTO_AUTHENC", "CRYPTO_HMAC", "CRYPTO_SHA256", "CRYPTO_CBC",
    "CRYPTO_AES", "CRYPTO_AES_NI_INTEL", "CRYPTO_GCM", "CRYPTO_NULL", "VIRTIO_PCI",
    "VIRTIO_BLK", "VIRTIO_NET", "VETH", "DEVTMPFS", "DEVTMPFS_MOUNT", "EXT4_FS",
    "EFI_PARTITION", "BINFMT_ELF", "UNIX", "PACKET",
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def download(url, path, expected):
    if not path.exists() or digest(path) != expected:
        temporary = path.with_suffix(path.suffix + ".download")
        try:
            with urllib.request.urlopen(url, timeout=90) as source, temporary.open("wb") as target:
                shutil.copyfileobj(source, target)
            if digest(temporary) != expected:
                raise RuntimeError("download digest mismatch")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    assert digest(path) == expected


def kernel(cache, output, jobs):
    image, config, receipt = (cache / name for name in ("bzImage", "config", "build.json"))
    if receipt.exists():
        previous = json.loads(receipt.read_text())
        if (previous["commit"] == COMMIT and previous["source_sha256"] == SOURCE_SHA
                and image.exists() and config.exists()
                and digest(image) == previous["kernel_sha256"]
                and digest(config) == previous["config_sha256"]):
            (output / "kernel-build.json").write_text(json.dumps(previous, indent=2) + "\n")
            return image
    with tempfile.TemporaryDirectory(prefix="n3-kernel-build-", dir=cache) as temporary:
        root = Path(temporary)
        archive = root / "source.tar.gz"
        download(f"https://codeload.github.com/torvalds/linux/tar.gz/{COMMIT}", archive, SOURCE_SHA)
        with tarfile.open(archive) as source:
            source.extractall(root, filter="data")
        source = root / f"linux-{COMMIT}"
        build = root / "build"
        build.mkdir()
        with (output / "kernel-build.log").open("w") as log:
            common = ["make", "-C", source, f"O={build}"]
            run(common + ["defconfig"], stdout=log, stderr=subprocess.STDOUT)
            options = [source / "scripts/config", "--file", build / ".config"]
            for feature in BUILTINS:
                options += ["-e", feature]
            options += ["-d", "LOCALVERSION_AUTO", "-d", "DEBUG_INFO",
                        "-d", "SYSTEM_TRUSTED_KEYRING", "-d", "SYSTEM_REVOCATION_LIST",
                        "--set-str", "LOCALVERSION", "-opc-n3-mobike"]
            run(options, stdout=log, stderr=subprocess.STDOUT)
            run(common + ["olddefconfig"], stdout=log, stderr=subprocess.STDOUT)
            run(common + [f"-j{jobs}", "bzImage"], stdout=log, stderr=subprocess.STDOUT)
        config_text = (build / ".config").read_text()
        for feature in BUILTINS:
            assert f"CONFIG_{feature}=y\n" in config_text, feature
        shutil.copy2(build / "arch/x86/boot/bzImage", image)
        shutil.copy2(build / ".config", config)
        facts = dict(commit=COMMIT, source_sha256=SOURCE_SHA, kernel_sha256=digest(image),
                     config_sha256=digest(config), release=RELEASE,
                     compiler=subprocess.check_output(["cc", "--version"], text=True).splitlines()[0])
        receipt.write_text(json.dumps(facts, indent=2) + "\n")
        (output / "kernel-build.json").write_text(receipt.read_text())
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    os.umask(0o022)
    binary, cache, output = args.binary.resolve(), args.cache.resolve(), args.output.resolve()
    assert binary.is_file() and 1 <= args.jobs <= 32
    cache.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    kernel_image = kernel(cache, output, args.jobs)
    base = cache / "ubuntu-24.04.img"
    download(IMAGE_URL, base, IMAGE_SHA)
    vm = Path(tempfile.mkdtemp(prefix="n3-mobike-vm-", dir=cache))
    pid = None
    try:
        disk, seed, key = (vm / name for name in ("disk.qcow2", "seed.iso", "ssh-key"))
        run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base, disk, "12G"], stdout=subprocess.DEVNULL)
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key])
        user = vm / "user-data"
        user.write_text("#cloud-config\nusers:\n  - name: opc\n    groups: [adm, sudo]\n"
                        "    shell: /bin/bash\n    sudo: ALL=(ALL) NOPASSWD:ALL\n"
                        "    lock_passwd: true\n    ssh_authorized_keys:\n      - "
                        + key.with_suffix(".pub").read_text().strip()
                        + "\nssh_pwauth: false\ndisable_root: true\npackage_update: false\n")
        meta = vm / "meta-data"
        meta.write_text("instance-id: opc-n3-mobike-profile\nlocal-hostname: opc-n3-mobike-profile\n")
        run(["cloud-localds", seed, user, meta])
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        kvm = subprocess.run(["sudo", "-n", "test", "-r", "/dev/kvm"]).returncode == 0
        pidfile = vm / "pid"
        # QEMU runs as root and otherwise creates a root-owned mode-0600 log.
        # Create it as the invoking runner so evidence upload can read it.
        serial = output / "guest-serial.log"
        serial.write_bytes(b"")
        run(["sudo", "-n", "qemu-system-x86_64", "-machine", "accel=kvm" if kvm else "accel=tcg",
             "-cpu", "host" if kvm else "max", "-smp", "2", "-m", "3072",
             "-kernel", kernel_image, "-append", "root=/dev/vda1 rw console=ttyS0",
             "-drive", f"file={disk},format=qcow2,if=virtio",
             "-drive", f"file={seed},format=raw,media=cdrom,readonly=on",
             "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22",
             "-device", "virtio-net-pci,netdev=net0", "-display", "none", "-serial",
             f"file:{serial}", "-daemonize", "-pidfile", pidfile])
        pid = int(subprocess.check_output(["sudo", "-n", "cat", str(pidfile)], text=True))
        common = ["-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                  "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
        ssh = ["ssh", *common, "-p", str(port), "-o", "ConnectTimeout=3", "opc@127.0.0.1"]
        for _ in range(180):
            ready = subprocess.run(ssh + ["uname -r"], capture_output=True, text=True)
            if ready.returncode == 0:
                assert ready.stdout.strip() == RELEASE
                break
            time.sleep(2)
        else:
            raise RuntimeError("isolated kernel guest did not become ready")
        with (output / "guest-profile.log").open("w") as log:
            run(ssh + ["uname -a; ip -V; systemd-detect-virt"], stdout=log, stderr=subprocess.STDOUT)
        bundle = vm / "bundle"
        libraries = bundle / "lib"
        libraries.mkdir(parents=True)
        executable = bundle / "roster"
        shutil.copy2(binary, executable)
        dependencies = subprocess.check_output(["ldd", str(binary)], text=True)
        paths = re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", dependencies)
        assert paths and "not found" not in dependencies
        for path in paths:
            shutil.copy2(path, libraries / Path(path).name)
        assert (libraries / "ld-linux-x86-64.so.2").is_file()
        guest = "/tmp/opc-n3-mobike"
        # Change only the transfer ELF interpreter/RPATH so child-process
        # exec uses the same verified host libraries on the older Ubuntu image.
        run(["patchelf", "--set-interpreter", guest + "/lib/ld-linux-x86-64.so.2",
             "--set-rpath", "$ORIGIN/lib", executable])
        facts = dict(binary_sha256=digest(binary), transfer_binary_sha256=digest(executable),
                     image_url=IMAGE_URL, image_sha256=IMAGE_SHA, acceleration="kvm" if kvm else "tcg",
                     libraries={p.name: digest(p) for p in sorted(libraries.iterdir())})
        (output / "transfer.json").write_text(json.dumps(facts, indent=2) + "\n")
        run(["scp", "-q", "-r", *common, "-P", str(port), str(bundle), f"opc@127.0.0.1:{guest}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with (output / "mobike-native.log").open("w") as log:
            run(ssh + ["sudo -n env OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED=1 unshare -n -- "
                       + guest + "/roster --ignored --nocapture --test-threads=1 mobike_roster::"],
                stdout=log, stderr=subprocess.STDOUT)
        evidence = (output / "mobike-native.log").read_text()
        assert "test result: ok. 3 passed; 0 failed; 0 ignored;" in evidence
        assert "N3_CHILD_SA_MOBIKE_PROOF_OK profiles=2 pairs=4 flows=7" in evidence
        assert "N3_CHILD_SA_MOBIKE_PROCESS_PROOF_OK profiles=2 cuts=32 processes=64" in evidence
        assert "N3_CHILD_SA_MOBIKE_AUTH_PROOF_OK" in evidence
        assert "N3_CHILD_SA_MOBIKE_CANCEL_PROOF_OK" in evidence
        assert "UNSUPPORTED" not in evidence and "skipping:" not in evidence
        (output / "result.json").write_text(json.dumps({"result": "pass", **facts}, indent=2) + "\n")
        print("Supported whole-roster relocation and 32 process-loss cuts passed", flush=True)
    finally:
        if pid is not None:
            command = subprocess.check_output(["sudo", "-n", "cat", f"/proc/{pid}/cmdline"])
            assert str(disk).encode() in command and b"qemu-system-x86_64" in command
            run(["sudo", "-n", "kill", "-TERM", str(pid)])
            for _ in range(100):
                if not Path(f"/proc/{pid}").exists():
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("owned guest did not stop; retaining its files")
        run(["sudo", "-n", "rm", "-rf", "--", vm])


if __name__ == "__main__":
    main()
