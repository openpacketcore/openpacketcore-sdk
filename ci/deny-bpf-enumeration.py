#!/usr/bin/env python3
"""Run one native lifecycle case with BPF ID enumeration and reopen denied.

The filter is inherited by this case's threads and child processes. Only load
descriptors, private pins and tc dumps remain available to graph discovery; it
cannot depend on the CAP_SYS_ADMIN requirement of program/map ID reopen.
"""

import ctypes
import os
import resource
import sys


class Argument(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint), ("op", ctypes.c_uint),
        ("value", ctypes.c_uint64), ("unused", ctypes.c_uint64),
    ]


def main():
    if len(sys.argv) < 2:
        raise SystemExit("expected a native test executable and its arguments")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
        ctypes.POINTER(Argument),
    ]
    context = library.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("seccomp initialization failed")
    try:
        syscall = library.seccomp_syscall_resolve_name(b"bpf")
        if syscall < 0:
            raise RuntimeError("native BPF syscall is unavailable")
        # SCMP_CMP_EQ on bpf's command argument: program/map GET_NEXT_ID and
        # GET_FD_BY_ID. SCMP_ACT_KILL_PROCESS makes even an ignored reopen fail
        # qualification, instead of merely returning a recoverable errno.
        for command in [11, 12, 13, 14]:
            match = Argument(0, 4, command, 0)
            if library.seccomp_rule_add_array(context, 0x80000000, syscall, 1, ctypes.byref(match)):
                raise RuntimeError("BPF ID filter construction failed")
        if library.seccomp_load(context):
            raise RuntimeError("BPF enumeration filter installation failed")
    finally:
        library.seccomp_release(context)
    print("BPF program/map ID enumeration and reopen denied for this case", flush=True)
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
