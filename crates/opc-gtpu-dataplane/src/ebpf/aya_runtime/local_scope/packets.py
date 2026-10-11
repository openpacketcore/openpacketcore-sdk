"""Private-netns packet qualification, using only Python's standard library."""
import socket
import errno
import struct
import sys
import time

mode = sys.argv[1]
core = bytes.fromhex('020000007901')
edge = bytes.fromhex('020000007902')
marker = b'OPC-local-scope-packet-' + str(time.monotonic_ns()).encode()


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(source, destination, payload):
    udp = struct.pack('!HHHH', 29778, 29779, len(payload) + 8, 0) + payload
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, 79, 0, 64, 17, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + udp


def arp(source_mac, source_ip, destination_mac, destination_ip, operation):
    return struct.pack('!HHBBH', 1, 0x800, 6, 4, operation) + source_mac + socket.inet_aton(source_ip) + destination_mac + socket.inet_aton(destination_ip)


def packet_socket(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((interface, 0))
    return sock


def capture_until(sock, observed):
    # Positive assertions wait for their packet, with the runner's case timeout
    # as the bound. Scheduler load cannot turn a short window into packet loss.
    packets = []
    while not observed(packets):
        frame, address = sock.recvfrom(65535)
        if address[2] != socket.PACKET_OUTGOING:
            packets.append(frame)
    return packets


def capture(sock, seconds):
    # Negative observations need a quiet interval. Start it after a positive
    # ARP event, and drain queued frames even if this process was descheduled.
    until = time.monotonic() + seconds
    packets = []
    while time.monotonic() < until:
        sock.settimeout(max(0.001, until - time.monotonic()))
        try:
            frame, address = sock.recvfrom(65535)
            if address[2] != socket.PACKET_OUTGOING:
                packets.append(frame)
        except socket.timeout:
            break
    sock.setblocking(False)
    while True:
        try:
            frame, address = sock.recvfrom(65535)
            if address[2] != socket.PACKET_OUTGOING:
                packets.append(frame)
        except BlockingIOError:
            break
    sock.settimeout(None)
    return packets


with packet_socket('core0') as sender, packet_socket('edge0') as receiver:
    # Peer capture is after core0's egress hook. A local outgoing capture
    # would incorrectly count packets that the containment filter drops.
    sender.send(edge + core + b'\x08\x06' + arp(core, '192.0.2.1', edge, '192.0.2.2', 2) + marker)
    inner = ipv4('10.79.0.2', '198.51.100.9', marker)
    try:
        sender.send(edge + core + b'\x08\x00' + inner)
    except OSError as error:
        # AF_PACKET reports a synchronous tc drop as ENOBUFS on this kernel.
        if mode != 'closed' or error.errno != errno.ENOBUFS:
            raise
    frames = capture_until(receiver, lambda frames: any(f[12:14] == b'\x08\x06' and marker in f for f in frames)
                           and (mode == 'closed' or any(f[12:14] == b'\x08\x00' and marker in f for f in frames)))
    if mode == 'closed':
        frames += capture(receiver, 2.0)
    assert any(f[12:14] == b'\x08\x06' and marker in f for f in frames), 'ARP egress was blocked'
    ip_frames = [f for f in frames if f[12:14] == b'\x08\x00' and marker in f]
    if mode == 'closed':
        assert not ip_frames, 'IP escaped egress containment'
    else:
        assert ip_frames, 'opened scoped session did not forward a packet'
        for frame in ip_frames:
            assert frame[26:30] == socket.inet_aton('192.0.2.1'), frame[:70].hex()
            assert frame[30:34] == socket.inet_aton('192.0.2.2'), 'plain inner IP escaped'
            assert frame[23] == 17 and struct.unpack('!H', frame[36:38])[0] == 2152
            assert frame[42:44] == b'\x30\xff'
            assert struct.unpack('!I', frame[46:50])[0] == 802
            assert frame[50:] == inner, 'GTP payload differs from the inner packet'

    # ARP reaches the kernel through core0 ingress and the reply crosses its
    # egress hook. UDP delivery is observed at the IP stack, after ingress tc.
    receiver.send(b'\xff' * 6 + edge + b'\x08\x06' + arp(edge, '192.0.2.2', bytes(6), '192.0.2.1', 1))
    frames = capture_until(receiver, lambda frames: any(f[12:14] == b'\x08\x06' and f[20:22] == b'\x00\x02'
                           and f[28:32] == socket.inet_aton('192.0.2.1') for f in frames))
    assert any(f[12:14] == b'\x08\x06' and f[20:22] == b'\x00\x02'
               and f[28:32] == socket.inet_aton('192.0.2.1') for f in frames), 'ARP ingress/reply was blocked'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(('192.0.2.1', 29779))
        listener.settimeout(2.0 if mode == 'closed' else None)
        receiver.send(core + edge + b'\x08\x00' + ipv4('192.0.2.2', '192.0.2.1', marker))
        try:
            received = listener.recv(4096)
        except socket.timeout:
            received = None
        assert (received == marker) == (mode == 'open'), 'ingress IP containment state differs'
print('packet state verified:', mode)
