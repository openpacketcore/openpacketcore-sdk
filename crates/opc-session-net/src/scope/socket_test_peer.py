"""Silence one owned TCP peer after connecting, without a host packet filter."""

import socket
import struct
import sys

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(30)
    print(listener.getsockname()[1], flush=True)
    peer, _ = listener.accept()

with peer:
    # Linux struct tcp_md5sig: sockaddr_storage, flags, prefix length, key
    # length, interface index and 80 key bytes. Requiring a signature after
    # this unsigned connection was established silently drops its incoming
    # keepalive probes. This key is only a packet-loss fixture, not security.
    key = b"scan-key"
    peer.setsockopt(
        socket.IPPROTO_TCP,
        14,  # TCP_MD5SIG
        struct.pack(
            "=H2x4s120xBBHi80s",
            socket.AF_INET,
            socket.inet_aton("127.0.0.1"),
            0,
            0,
            len(key),
            0,
            key,
        ),
    )
    print("silent", flush=True)
    # The Rust fixture owns this child and reaps it even after a panic. Keep
    # the socket open until then: a FIN/RST must not satisfy the timeout test.
    sys.stdin.buffer.read(1)
