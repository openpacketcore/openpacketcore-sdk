#!/usr/bin/env python3
"""Independent synthetic TS 24.502 envelope streams; no SDK/writer imports."""
import argparse
import hashlib
from pathlib import Path
import struct

TARGET = Path(__file__).with_suffix('.tsv')


def observe(wire, limit, closed):
    frames = []
    cursor = 0
    while cursor < len(wire):
        if len(wire) - cursor < 2:
            return frames, 'truncated' if closed else 'need-more-data'
        size = wire[cursor] * 256 + wire[cursor + 1]
        if size == 0:
            return frames, 'empty'
        if size > limit:
            return frames, 'too-large'
        end = cursor + 2 + size
        if end > len(wire):
            return frames, 'truncated' if closed else 'need-more-data'
        frames.append(wire[cursor + 2:end])
        cursor = end
    return frames, 'complete'


def envelope(payload):
    return struct.pack('!H', len(payload)) + payload


def rows():
    result = []

    def add(name, wire, limit, closed):
        frames, outcome = observe(wire, limit, closed)
        result.append((name, str(limit), str(int(closed)), outcome,
                       ','.join(frame.hex() for frame in frames) or '-', wire.hex() or '-'))

    for size in [1, 2, 3, 15, 16, 255, 256, 257, 4096]:
        payload = bytes((index * 29 + size) % 256 for index in range(size))
        wire = envelope(payload)
        for closed in [False, True]:
            add(f'length-{size}-closed-{int(closed)}', wire, size, closed)
            if size > 1:
                add(f'above-{size}-closed-{int(closed)}', wire, size - 1, closed)
            for cut in sorted({0, 1, 2, len(wire) - 1}):
                add(f'cut-{size}-{cut}-closed-{int(closed)}', wire[:cut], size, closed)
    for index, payload in enumerate([bytes.fromhex('7e0041'), bytes.fromhex('7e021122334409a55a'), bytes.fromhex('7fff00'), b'opaque-test-only']):
        add(f'opaque-{index}', envelope(payload), 256, True)
    first, second, third = (envelope(bytes.fromhex(x)) for x in ['7e0041', '7e005d', '7f0000'])
    for index, wire in enumerate([first + first, first + second + third]):
        for cut in range(len(wire) + 1):
            for closed in [False, True]:
                add(f'coalesced-{index}-{cut}-{int(closed)}', wire[:cut], 256, closed)
    for name, bad in [('empty', b'\0\0'), ('over-limit', b'\x01\x01'), ('wrapped-zero', b'\0\0' + b'\xa5' * 16)]:
        for prefix_name, prefix in [('only', b''), ('after-frame', first)]:
            for closed in [False, True]:
                add(f'{prefix_name}-{name}-{int(closed)}', prefix + bad, 256, closed)
    assert len({row[0] for row in result}) == len(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write', action='store_true')
    group.add_argument('--check', action='store_true')
    args = parser.parse_args()
    # Literal independent controls for length byte order and prefix exclusion.
    assert envelope(b'\xa5' * 256)[:2] == b'\x01\x00'
    assert observe(b'\0\x01\xff\0', 1, False) == ([b'\xff'], 'need-more-data')
    assert observe(b'\0\x01\xff\0', 1, True) == ([b'\xff'], 'truncated')
    assert observe(b'\x01\x00', 255, False) == ([], 'too-large')
    records = rows()
    data = ('name\tlimit\tclosed\toutcome\tpayloads_hex\twire_hex\n' + ''.join('\t'.join(row) + '\n' for row in records)).encode()
    if args.write:
        TARGET.write_bytes(data)
    elif TARGET.read_bytes() != data:
        raise SystemExit('nas_tcp_reference_mismatch')
    counts = {name: sum(row[3] == name for row in records) for name in ['complete', 'need-more-data', 'truncated', 'empty', 'too-large']}
    print(f'nas_tcp_reference_pass rows={len(records)} sha256={hashlib.sha256(data).hexdigest()} outcomes={counts}')


if __name__ == '__main__':
    main()
