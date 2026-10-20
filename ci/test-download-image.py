#!/usr/bin/env python3
"""Exercise pinned image-download callers with real curl and local HTTP faults."""

import hashlib
import http.server
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
URL = ("https://dl.rockylinux.org/vault/rocky/9.4/images/x86_64/"
       "Rocky-9-GenericCloud-Base-9.4-20240609.1.x86_64.qcow2")
SHA = "2179864f4fa9799f11c0824c439666c2451d6751450494e20034efd4f3fa0559"
UBUNTU_URL = ("https://cloud-images.ubuntu.com/releases/noble/release-20260705/"
              "ubuntu-24.04-server-cloudimg-amd64.img")
UBUNTU_SHA = "ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6"
DATA = bytes(range(256)) * 2048
CHUNK = 65536
SITES = ("classifier", "ubuntu", "nohz", "mobike")
IMAGE_NAMES = {
    "classifier": "rocky94-el9.qcow2",
    "ubuntu": "ubuntu-24.04-linux68.img",
    "nohz": "guest.qcow2",
    "mobike": "ubuntu-24.04.img",
}
PINS = {
    "classifier": ((URL, SHA),),
    "ubuntu": ((UBUNTU_URL, UBUNTU_SHA),),
    "nohz": ((URL, SHA), (UBUNTU_URL, UBUNTU_SHA)),
    "mobike": ((UBUNTU_URL, UBUNTU_SHA),),
}


def download_block(site):
    if site in ("classifier", "ubuntu"):
        source = (ROOT / ".github/workflows/gtpu-privileged.yml").read_text()
        start = source.index('          image="${RUNNER_TEMP}/' + IMAGE_NAMES[site] + '"')
        end = source.index('          key="${RUNNER_TEMP}/gtpu-', start)
        return textwrap.dedent(source[start:end])
    if site == "mobike":
        source = (ROOT / "ci/qualify-n3-mobike-kernel.py").read_text()
        pins = source[source.index("IMAGE_URL = "):source.index("RELEASE = ")]
        start = source.index('    base = cache / "ubuntu-24.04.img"')
        end = source.index('    vm = Path(', start)
        return pins + textwrap.dedent(source[start:end])
    source = (ROOT / "ci/qualify-tft-nohz-vm.sh").read_text()
    pins = source[source.index('case "$profile" in'):source.index('logs="${state}/evidence"')]
    start = source.index('image="${private}/guest.qcow2"')
    end = source.index('key="${private}/ssh-key"', start)
    return pins + source[start:end]


def local_download_block(site, local_url, digest):
    block = download_block(site)
    for url, sha in PINS[site]:
        for kind, pinned, local in (("URL", url, local_url), ("digest", sha, digest)):
            count = block.count(pinned)
            if count != 1:
                raise AssertionError(f"{site}: expected exactly one pinned {kind}, found {count}")
            block = block.replace(pinned, local)
    return block


class DownloadTests(unittest.TestCase):
    def run_download(self, site, replies, expected_status, expected_ranges,
                     seed=b"", expected_errors=(), profile="el9"):
        requests = []
        cache_snapshots = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                range_header = self.headers.get("Range")
                requests.append(range_header)
                if site == "mobike":
                    cache_snapshots.append(target.read_bytes() if target.exists() else None)
                action = replies[min(len(requests) - 1, len(replies) - 1)]
                self.close_connection = True
                if action == "404":
                    self.send_error(404)
                    return
                if action == "empty":
                    return
                offset = int(range_header[6:-1]) if range_header else 0
                wrong_range = action in ("ignore-range", "wrong-offset")
                if wrong_range:
                    offset = 0
                partial_response = bool(range_header) and action != "ignore-range"
                self.send_response(206 if partial_response else 200)
                if partial_response:
                    self.send_header(
                        "Content-Range", f"bytes {offset}-{len(DATA) - 1}/{len(DATA)}"
                    )
                payload = DATA[offset:]
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Connection", "close")
                self.end_headers()
                if action in ("partial", "stall"):
                    payload = payload[:CHUNK]
                elif action == "corrupt":
                    payload = b"x" + payload[1:]
                try:
                    self.wfile.write(payload)
                    self.wfile.flush()
                    if action == "stall":
                        # Keep the incomplete response open until curl's real
                        # low-speed timeout closes it. No fake curl or clock.
                        self.connection.settimeout(90)
                        self.connection.recv(1)
                except (BrokenPipeError, ConnectionResetError, TimeoutError):
                    pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with tempfile.TemporaryDirectory(prefix="image-download-") as tmp:
                    # An absent CURL_HOME/.curlrc allows fallback to inherited
                    # XDG_CONFIG_HOME/curlrc. An empty file stops that search.
                    (Path(tmp) / ".curlrc").write_text("")
                    target = Path(tmp) / IMAGE_NAMES[site]
                    if seed is not None:
                        target.write_bytes(seed)
                    initial_inode = target.stat().st_ino if target.exists() else None
                    temporary = target.with_suffix(target.suffix + ".download")
                    if site == "mobike" and expected_ranges:
                        temporary.write_bytes(b"stale partial from an earlier invocation")
                    local_url = f"http://127.0.0.1:{server.server_port}/image"
                    digest = hashlib.sha256(DATA).hexdigest()
                    # Execute the callers' actual blocks, including their
                    # checksum gates; replace only the external image inputs.
                    script = local_download_block(site, local_url, digest)
                    env = {
                        **os.environ, "RUNNER_TEMP": tmp, "private": tmp,
                        "repository": str(ROOT), "profile": profile,
                        "NO_PROXY": "127.0.0.1",
                        "no_proxy": "127.0.0.1",
                        "CURL_HOME": tmp, "HOME": tmp, "XDG_CONFIG_HOME": tmp,
                    }
                    command = ["bash", "-c", "set -euo pipefail\n" + script]
                    if site == "mobike":
                        # Load the real driver without main/VM setup, then run
                        # its actual image call with only URL/digest redirected.
                        command = [sys.executable, "-c", (
                            "import os, runpy\n"
                            "from pathlib import Path\n"
                            f"driver = runpy.run_path({str(ROOT / 'ci/qualify-n3-mobike-kernel.py')!r})\n"
                            "driver.update(cache=Path(os.environ['private']))\n"
                            f"exec({script!r}, driver)\n"
                        )]
                    result = subprocess.run(
                        command,
                        cwd=ROOT,
                        env=env,
                        text=True, capture_output=True, timeout=100,
                    )
                    detail = f"{site}: {result.stdout}\n{result.stderr}"
                    status = 1 if site == "mobike" and expected_status else expected_status
                    self.assertEqual(result.returncode, status, detail)
                    self.assertEqual(requests, expected_ranges, detail)
                    for error in expected_errors:
                        self.assertIn(f"({error})", result.stderr, detail)
                    if expected_status == 0:
                        self.assertEqual(target.read_bytes(), DATA)
                        if site != "mobike":
                            self.assertIn(": OK", result.stdout, detail)
                    elif "corrupt" in replies:
                        if site == "mobike":
                            self.assertIn("download digest mismatch", result.stderr, detail)
                        else:
                            self.assertIn(": FAILED", result.stdout, detail)
                    else:
                        self.assertEqual(result.stdout, "", "checksum ran after failed download")
                        if site == "mobike":
                            self.assertIn(
                                f"returned non-zero exit status {expected_status}", result.stderr, detail
                            )
                    if site == "mobike":
                        self.assertEqual(cache_snapshots, [seed] * len(requests))
                        self.assertFalse(temporary.exists(), "temporary download was not cleaned up")
                        if expected_status:
                            self.assertEqual(target.read_bytes() if target.exists() else None, seed)
                        elif requests and initial_inode is not None:
                            self.assertNotEqual(target.stat().st_ino, initial_inode,
                                                "verified download must atomically replace cache")
                        elif not requests:
                            self.assertEqual(target.stat().st_ino, initial_inode)
                    print(f"{site} {replies}: exit={result.returncode}, ranges={requests}", flush=True)
            finally:
                server.shutdown()
                thread.join()

    def test_retries_resumption_exhaustion_and_checksum_at_all_sites(self):
        cases = [
            (["partial", "partial", "ok"], 0,
             [None, "bytes=65536-", "bytes=131072-"], b"", (18,)),
            # Bytes left by an earlier invocation/profile cannot seed this one.
            (["ok"], 0, [None], b"stale image prefix", ()),
            (["404", "ok"], 0, [None, None], b"", (22,)),
            (["empty", "ok"], 0, [None, None], b"", (52,)),
            (["partial"] * 4, 18,
             [None, "bytes=65536-", "bytes=131072-", "bytes=196608-"], b"", (18,)),
            (["404"] * 4, 22, [None] * 4, b"", (22,)),
            (["corrupt"], 1, [None], b"", ()),
            (["partial", "corrupt"], 1, [None, "bytes=65536-"], b"", (18,)),
            (["partial", "ignore-range", "ok"], 0,
             [None, "bytes=65536-", None], b"", (18, 33)),
            (["partial", "wrong-offset", "ok"], 0,
             [None, "bytes=65536-", None], b"", (18, 33)),
        ]
        for site in SITES:
            for replies, status, ranges, seed, errors in cases:
                with self.subTest(site=site, replies=replies):
                    self.run_download(site, replies, status, ranges, seed, errors)

    def test_stalled_transfer_times_out_and_resumes_at_all_sites(self):
        for site in SITES:
            with self.subTest(site=site):
                self.run_download(site, ["stall", "ok"], 0,
                                  [None, "bytes=65536-"], expected_errors=(28,))

    def test_mobike_cache_hit_miss_and_failed_replacement(self):
        self.run_download("mobike", ["404"], 0, [], seed=DATA)
        self.run_download("mobike", ["partial", "ok"], 0,
                          [None, "bytes=65536-"], seed=None, expected_errors=(18,))
        self.run_download("mobike", ["corrupt"], 1, [None], seed=b"old invalid cache")
        self.run_download("mobike", ["404"] * 4, 22, [None] * 4,
                          seed=b"old invalid cache", expected_errors=(22,))
        self.run_download("mobike", ["corrupt"], 1, [None], seed=None)

    def test_inherited_curl_config_and_proxies_cannot_change_downloads(self):
        with tempfile.TemporaryDirectory(prefix="inherited-curl-config-") as inherited:
            (Path(inherited) / ".curlrc").write_text("max-filesize = 1\n")
            (Path(inherited) / "curlrc").write_text("max-filesize = 1\n")
            with patch.dict(os.environ, {
                "CURL_HOME": inherited, "HOME": inherited, "XDG_CONFIG_HOME": inherited,
                "http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1",
                "all_proxy": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1",
                "no_proxy": "example.invalid", "NO_PROXY": "example.invalid",
            }):
                for site in SITES:
                    with self.subTest(site=site):
                        self.run_download(site, ["ok"], 0, [None])
                self.run_download("nohz", ["ok"], 0, [None], profile="linux68")

    def test_pin_drift_and_duplicate_pins_fail_before_starting_callers(self):
        for site in SITES:
            original = download_block(site)
            for url, sha in PINS[site]:
                for pin in (url, sha):
                    for replacement in ("changed-pin", pin + pin):
                        with self.subTest(site=site, pin=pin, replacement=replacement):
                            altered = original.replace(pin, replacement)
                            with patch.dict(globals(), {"download_block": lambda _site: altered}):
                                with patch("subprocess.run") as run:
                                    with self.assertRaisesRegex(
                                        AssertionError, "expected exactly one pinned"
                                    ):
                                        self.run_download(site, ["ok"], 0, [None])
                                    run.assert_not_called()

    def test_pinned_inputs_and_final_checksum_gates_remain(self):
        for site, url, sha in (("classifier", URL, SHA), ("ubuntu", UBUNTU_URL, UBUNTU_SHA)):
            workflow = download_block(site)
            self.assertIn(url, workflow)
            self.assertIn(
                'echo "' + sha + '  ${image}" \\\n  | sha256sum -c -\n', workflow
            )
        driver = (ROOT / "ci/qualify-tft-nohz-vm.sh").read_text()
        for url, sha in ((URL, SHA), (UBUNTU_URL, UBUNTU_SHA)):
            self.assertIn("image_url='" + url + "'", driver)
            self.assertIn("image_sha='" + sha + "'", driver)
        self.assertIn(
            "printf '%s  %s\\n' \"$image_sha\" \"$image\" | sha256sum -c -\n",
            download_block("nohz"),
        )
        mobike = (ROOT / "ci/qualify-n3-mobike-kernel.py").read_text()
        self.assertIn('IMAGE_URL = "' + UBUNTU_URL + '"', mobike)
        self.assertIn('IMAGE_SHA = "' + UBUNTU_SHA + '"', mobike)


if __name__ == "__main__":
    unittest.main(verbosity=2)
