#!/usr/bin/env python3
"""Exercise pinned image-download callers with real curl and local HTTP faults."""

import hashlib
import http.server
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
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
                     seed=b"", expected_errors=(), profile="el9",
                     expected_delays=None, cache_hit=False, real_backoff=False):
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
                if action.isdigit() or action.startswith("retry-after:"):
                    self.send_response(429 if action.startswith("retry-after:") else int(action))
                    if action.startswith("retry-after:"):
                        self.send_header("Retry-After", action.split(":", 1)[1])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
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
                    # Real curl and HTTP faults; only backoff time is virtual.
                    # The stalled-transfer test still exercises curl's real timeout.
                    clock = Path(tmp) / "clock"
                    clock.write_text("0")
                    delays = Path(tmp) / "delays"
                    delays.write_text("")
                    tools = Path(tmp) / "tools"
                    tools.mkdir()
                    for name, source in {
                        "sleep": '''\
                            #!/usr/bin/env python3
                            import os, pathlib, sys
                            clock = pathlib.Path(os.environ["DOWNLOAD_CLOCK"])
                            delay = int(sys.argv[1])
                            clock.write_text(str(int(clock.read_text()) + delay))
                            with open(os.environ["DOWNLOAD_DELAYS"], "a") as output:
                                output.write(str(delay) + "\\n")
                            ''',
                        "date": '''\
                            #!/usr/bin/env python3
                            import os, pathlib, sys
                            if sys.argv[1:] == ["+%s"]:
                                print(pathlib.Path(os.environ["DOWNLOAD_CLOCK"]).read_text())
                            else:
                                os.execv("/usr/bin/date", ["date", *sys.argv[1:]])
                            ''',
                    }.items():
                        tool = tools / name
                        tool.write_text(textwrap.dedent(source))
                        tool.chmod(0o755)
                    env = {
                        **os.environ, "RUNNER_TEMP": tmp, "private": tmp,
                        "repository": str(ROOT), "profile": profile,
                        "NO_PROXY": "127.0.0.1",
                        "no_proxy": "127.0.0.1",
                        "CURL_HOME": tmp, "HOME": tmp, "XDG_CONFIG_HOME": tmp,
                        "PATH": (os.environ["PATH"] if real_backoff else
                                 str(tools) + os.pathsep + os.environ["PATH"]),
                        "DOWNLOAD_CLOCK": str(clock), "DOWNLOAD_DELAYS": str(delays),
                        "CI_IMAGE_CACHE_HIT": "true" if cache_hit else "false",
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
                    started = time.monotonic()
                    result = subprocess.run(
                        command,
                        cwd=ROOT,
                        env=env,
                        text=True, capture_output=True, timeout=100,
                    )
                    detail = f"{site}: {result.stdout}\n{result.stderr}"
                    if real_backoff:
                        elapsed = time.monotonic() - started
                        self.assertGreaterEqual(elapsed, 29, detail)
                        print(f"real 429 backoff elapsed={elapsed:.3f}s", flush=True)
                    status = 1 if site == "mobike" and expected_status else expected_status
                    self.assertEqual(result.returncode, status, detail)
                    self.assertEqual(requests, expected_ranges, detail)
                    actual_delays = [int(n) for n in delays.read_text().splitlines()]
                    if expected_delays is not None:
                        self.assertEqual(actual_delays, expected_delays, detail)
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
            (["404", "ok"], 22, [None], b"", (22,)),
            (["429", "ok"], 0, [None, None], b"", (22,)),
            (["empty", "ok"], 0, [None, None], b"", (52,)),
            (["partial"] * 4, 18,
             [None, "bytes=65536-", "bytes=131072-", "bytes=196608-"], b"", (18,)),
            (["404"] * 4, 22, [None], b"", (22,)),
            (["429"] * 5, 22, [None] * 5, b"", (22,)),
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
        self.run_download("mobike", ["404"] * 4, 22, [None],
                          seed=b"old invalid cache", expected_errors=(22,))
        self.run_download("mobike", ["corrupt"], 1, [None], seed=None)

    def test_http_backoff_budget_and_retry_after(self):
        self.run_download("mobike", ["429", "ok"], 0, [None, None],
                          expected_delays=[30])
        self.run_download("mobike", ["503"] * 5, 22, [None] * 5,
                          expected_delays=[30, 60, 120, 90])
        self.run_download("mobike", ["retry-after:45", "ok"], 0, [None, None],
                          expected_delays=[45])
        self.run_download("mobike", ["retry-after:Thu, 01 Jan 1970 00:00:45 GMT", "ok"],
                          0, [None, None], expected_delays=[45])
        self.run_download("mobike", ["retry-after:301", "ok"], 22, [None],
                          expected_delays=[])
        self.run_download("mobike", ["retry-after:invalid", "ok"], 0, [None, None],
                          expected_delays=[30])
        for status in ("500", "502", "504"):
            self.run_download("mobike", [status, "ok"], 0, [None, None],
                              expected_delays=[30])
        for status in ("400", "401", "403", "404", "410"):
            self.run_download("mobike", [status, "ok"], 22, [None],
                              expected_delays=[])
        self.run_download("mobike", ["partial", "429", "ok"], 0,
                          [None, "bytes=65536-", "bytes=65536-"],
                          expected_errors=(18, 22), expected_delays=[1, 30])

    def test_real_http_429_then_200(self):
        self.run_download("mobike", ["429", "ok"], 0, [None, None], real_backoff=True)

    def test_restored_images_are_verified_without_downloading(self):
        for site in SITES:
            with self.subTest(site=site):
                self.run_download(site, ["404"], 0, [], seed=DATA, cache_hit=True)
                # A restored corrupt file must still fail the original gate.
                requests = [None] if site == "mobike" else []
                self.run_download(site, ["corrupt"], 1, requests,
                                  seed=b"corrupt cached image", cache_hit=True)

    def test_workflow_caches_cover_every_pinned_download(self):
        pins = runpy.run_path(str(ROOT / "ci/qualify-n3-mobike-kernel.py"))
        self.assertEqual(pins["IMAGE_SHA"], UBUNTU_SHA)
        gtpu = (ROOT / ".github/workflows/gtpu-privileged.yml").read_text()
        ipsec = (ROOT / ".github/workflows/ipsec-xfrm.yml").read_text()
        cache_pattern = (r'uses: actions/cache@v5\n        with:\n'
                         r'          path: (.+)\n          key: (.+)\n')
        caches = dict(re.findall(cache_pattern, gtpu + ipsec))
        self.assertEqual(len(caches), 6)
        for filename, sha in (("ubuntu-24.04-linux68.img", UBUNTU_SHA),
                              ("rocky94-el9.qcow2", SHA)):
            self.assertEqual(caches['${{ runner.temp }}/' + filename],
                             'qualification-image-' + sha)
        nohz_key = caches['${{ runner.temp }}/gtpu-nohz/private/guest.qcow2']
        self.assertIn("matrix.profile == 'linux68' && '" + UBUNTU_SHA + "'", nohz_key)
        self.assertIn("|| '" + SHA + "'", nohz_key)
        for prefix in ("tfc-cache", "n3-mobike-kernel"):
            self.assertEqual(caches['${{ runner.temp }}/' + prefix + '/linux-n3-mobike.tar.gz'],
                             'qualification-image-${{ steps.image-pins.outputs.source }}')
        self.assertEqual(caches['${{ runner.temp }}/n3-mobike-kernel/ubuntu-24.04.img'],
                         'qualification-image-${{ steps.image-pins.outputs.image }}')
        # Execute the workflow's actual pin-reading steps, rather than duplicating
        # their checksum literals in the cache keys.
        blocks = re.findall(r"          python3 - <<'PY'\n(.*?)          PY\n", ipsec, re.S)
        pin_blocks = [block for block in blocks if 'pins = runpy.run_path' in block]
        self.assertEqual(len(pin_blocks), 2)
        for block in pin_blocks:
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'outputs'
                subprocess.run([sys.executable, '-c', textwrap.dedent(block)],
                               cwd=ROOT, env={**os.environ, 'GITHUB_OUTPUT': str(output)},
                               check=True)
                actual = dict(line.split('=', 1) for line in output.read_text().splitlines())
                self.assertEqual(actual['source'], pins['SOURCE_SHA'])
                if 'image' in actual:
                    self.assertEqual(actual['image'], pins['IMAGE_SHA'])

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
