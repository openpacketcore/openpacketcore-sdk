# N2 DTLS fixture subset

PPID 66 metadata, isolated ServerHelloDone framing, and lifecycle labels.
SCTP-AUTH length, verified identity, reliable delivery, and key rotation are
explicit caller preconditions. DATA B/E flags describe message boundaries;
they do not prove reliability. Restart/path failure and error labels model
scenarios without executing a transport or handshake. Ordinary PPID 60 associations cannot satisfy this subset. No
certificates or exporter secrets are published.
