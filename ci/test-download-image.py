#!/usr/bin/env python3
"""Exercise both image-download call sites with real curl and local HTTP faults."""

import hashlib
import http.server
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import threading
import unittest


ROOT = Path(__file__).resolve().parent.parent
URL = ("https://dl.rockylinux.org/vault/rocky/9.4/images/x86_64/"
       "Rocky-9-GenericCloud-Base-9.4-20240609.1.x86_64.qcow2")
SHA = "2179864f4fa9799f11c0824c439666c2451d6751450494e20034efd4f3fa0559"
DATA = bytes(range(256)) * 2048
CHUNK = 65536


def download_block(site):
    if site == "classifier":
        source = (ROOT / ".github/workflows/gtpu-privileged.yml").read_text()
        start = source.index('          image="${RUNNER_TEMP}/rocky94-el9.qcow2"')
        end = source.index('          key="${RUNNER_TEMP}/gtpu-el9-key"', start)
        return textwrap.dedent(source[start:end])
    source = (ROOT / "ci/qualify-tft-nohz-vm.sh").read_text()
    start = source.index('image="${private}/guest.qcow2"')
    end = source.index('key="${private}/ssh-key"', start)
    return source[start:end]


class DownloadTests(unittest.TestCase):
    def run_download(self, site, replies, expected_status, expected_ranges,
                     seed=b"", expected_errors=()):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                range_header = self.headers.get("Range")
                requests.append(range_header)
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
                    image_name = "rocky94-el9.qcow2" if site == "classifier" else "guest.qcow2"
                    target = Path(tmp) / image_name
                    target.write_bytes(seed)
                    local_url = f"http://127.0.0.1:{server.server_port}/image"
                    digest = hashlib.sha256(DATA).hexdigest()
                    # Execute the callers' actual blocks, including their
                    # checksum gates; replace only the external image inputs.
                    script = download_block(site).replace(URL, local_url).replace(SHA, digest)
                    result = subprocess.run(
                        ["bash", "-c", "set -euo pipefail\n" + script],
                        cwd=ROOT,
                        env={
                            **os.environ, "RUNNER_TEMP": tmp, "private": tmp,
                            "repository": str(ROOT), "image_url": local_url,
                            "image_sha": digest, "NO_PROXY": "127.0.0.1",
                            "CURL_HOME": tmp,
                        },
                        text=True, capture_output=True, timeout=100,
                    )
                    detail = f"{site}: {result.stdout}\n{result.stderr}"
                    self.assertEqual(result.returncode, expected_status, detail)
                    self.assertEqual(requests, expected_ranges, detail)
                    for error in expected_errors:
                        self.assertIn(f"({error})", result.stderr, detail)
                    if expected_status == 0:
                        self.assertEqual(target.read_bytes(), DATA)
                        self.assertIn(": OK", result.stdout, detail)
                    elif "corrupt" in replies:
                        self.assertIn(": FAILED", result.stdout, detail)
                    else:
                        self.assertEqual(result.stdout, "", "checksum ran after failed download")
                    print(f"{site} {replies}: exit={result.returncode}, ranges={requests}", flush=True)
            finally:
                server.shutdown()
                thread.join()

    def test_retries_resumption_exhaustion_and_checksum_at_both_sites(self):
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
            (["partial", "ignore-range", "ok"], 0,
             [None, "bytes=65536-", None], b"", (18, 33)),
            (["partial", "wrong-offset", "ok"], 0,
             [None, "bytes=65536-", None], b"", (18, 33)),
        ]
        for site in ("classifier", "nohz"):
            for replies, status, ranges, seed, errors in cases:
                with self.subTest(site=site, replies=replies):
                    self.run_download(site, replies, status, ranges, seed, errors)

    def test_stalled_transfer_times_out_and_resumes_at_both_sites(self):
        for site in ("classifier", "nohz"):
            with self.subTest(site=site):
                self.run_download(site, ["stall", "ok"], 0,
                                  [None, "bytes=65536-"], expected_errors=(28,))

    def test_pinned_inputs_and_final_checksum_gates_remain(self):
        workflow = download_block("classifier")
        self.assertIn(URL, workflow)
        self.assertIn(
            'echo "' + SHA + '  ${image}" \\\n  | sha256sum -c -\n', workflow
        )
        driver = (ROOT / "ci/qualify-tft-nohz-vm.sh").read_text()
        self.assertIn("image_url='" + URL + "'", driver)
        self.assertIn("image_sha='" + SHA + "'", driver)
        self.assertIn(
            "printf '%s  %s\\n' \"$image_sha\" \"$image\" | sha256sum -c -\n",
            download_block("nohz"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
