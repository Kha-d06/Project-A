"""The jail every hostile-file parser runs in.

Applied by the child process itself, after its imports and before it reads
the sample, so it works inside the hardened worker container without extra
capabilities (seccomp needs only no_new_privs, which the container already
sets):

* rlimits: address space, CPU seconds, no file writes, few open files, no
  core dumps;
* Landlock (Linux 5.13+, unprivileged): the process may read only the
  interpreter, the app, the rules and its own sample, so it can't read other
  people's uploads or another process's /proc entries. Where the kernel has
  no Landlock this layer is skipped (and reported), the others still apply;
* a seccomp-bpf allowlist whose default action kills the process. It has no
  socket, connect, fork or execve, threads only, and files can only be opened
  for reading. A parser exploit gets no network, no new process and nothing
  written to disk.

libseccomp (LGPL-2.1, a system library) is loaded with ctypes, so there is
no extra Python dependency.
"""

import ctypes
import ctypes.util
import errno
import os
import resource
import struct
import sys
import sysconfig
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# libseccomp actions and comparison operators (seccomp.h).
ACT_KILL_PROCESS = 0x80000000
ACT_ALLOW = 0x7FFF0000
CMP_MASKED_EQ = 7


def act_errno(code: int) -> int:
    return 0x00050000 | (code & 0xFFFF)


# Calls a computational Python process needs once its imports are done.
# Names unknown on this architecture are skipped.
ALLOWED_SYSCALLS: tuple[str, ...] = (
    "read", "readv", "pread64", "write", "writev", "close", "close_range",
    "fstat", "newfstatat", "statx", "stat", "lstat", "fstatfs", "statfs", "lseek",
    "getdents64", "readlink", "readlinkat", "getcwd", "access", "faccessat", "faccessat2",
    "fcntl", "dup", "dup2", "dup3",
    "mmap", "munmap", "mprotect", "mremap", "madvise", "brk", "mincore", "membarrier",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "tgkill",
    "futex", "futex_waitv", "set_robust_list", "get_robust_list", "rseq", "set_tid_address",
    "sched_getaffinity", "sched_yield", "arch_prctl",
    "getpid", "gettid", "getppid", "getuid", "geteuid", "getgid", "getegid",
    "getrandom", "clock_gettime", "clock_getres", "gettimeofday", "time",
    "nanosleep", "clock_nanosleep", "getrusage", "times", "sysinfo", "uname", "prlimit64",
    "exit", "exit_group",
)  # fmt: skip

# Answered with an error instead of killing: Python probes these and copes.
SOFT_DENIED: dict[str, int] = {
    "ioctl": errno.ENOTTY,  # isatty() on the output pipe
    "prctl": errno.EPERM,
    "clone3": errno.ENOSYS,  # glibc then falls back to clone, which is filtered below
    "openat2": errno.ENOSYS,
}

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_CLONE_THREAD = 0x00010000


class _ArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class Limits:
    memory_bytes: int = 512 * 1024 * 1024
    cpu_seconds: int = 60
    open_files: int = 64


class SandboxUnavailableError(RuntimeError):
    """libseccomp is missing: the caller must not run the parser unjailed."""


def apply_limits(limits: Limits) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _library() -> ctypes.CDLL:
    # The soname first: find_library runs helper programs, which the jail forbids.
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError:
        name = ctypes.util.find_library("seccomp")
        if not name:
            raise SandboxUnavailableError("libseccomp is not installed.") from None
        try:
            lib = ctypes.CDLL(name, use_errno=True)
        except OSError as exc:
            raise SandboxUnavailableError(f"libseccomp could not be loaded ({exc}).") from exc
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_ArgCmp),
    ]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    return lib


def _resolve(lib: ctypes.CDLL, name: str) -> int | None:
    number = lib.seccomp_syscall_resolve_name(name.encode())
    return number if number >= 0 else None


def apply_seccomp(extra_allowed: Iterable[str] = (), lib: ctypes.CDLL | None = None) -> None:
    lib = lib or _library()
    ctx = lib.seccomp_init(ACT_KILL_PROCESS)
    if not ctx:
        raise SandboxUnavailableError("seccomp_init failed.")

    def add(action: int, name: str, *conditions: _ArgCmp) -> None:
        number = _resolve(lib, name)
        if number is None:
            return
        array = (_ArgCmp * len(conditions))(*conditions) if conditions else None
        if lib.seccomp_rule_add_array(ctx, action, number, len(conditions), array) != 0:
            raise SandboxUnavailableError(f"Could not add the seccomp rule for {name}.")

    try:
        for name in (*ALLOWED_SYSCALLS, *extra_allowed):
            add(ACT_ALLOW, name)
        for name, code in SOFT_DENIED.items():
            add(act_errno(code), name)
        # Open for reading only: any write, create, truncate or append flag is fatal.
        read_only = _ArgCmp(2, CMP_MASKED_EQ, _WRITE_FLAGS, 0)
        add(ACT_ALLOW, "openat", read_only)
        add(ACT_ALLOW, "open", _ArgCmp(1, CMP_MASKED_EQ, _WRITE_FLAGS, 0))
        # Threads only: clone without CLONE_THREAD would be a new process.
        add(ACT_ALLOW, "clone", _ArgCmp(0, CMP_MASKED_EQ, _CLONE_THREAD, _CLONE_THREAD))
        if lib.seccomp_load(ctx) != 0:
            raise SandboxUnavailableError("seccomp_load failed.")
    finally:
        lib.seccomp_release(ctx)


# --- Landlock ---------------------------------------------------------------------

_SYS_LANDLOCK_CREATE_RULESET = 444  # same number on x86_64 and aarch64
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_FS_EXECUTE, _FS_READ_FILE, _FS_READ_DIR = 1 << 0, 1 << 2, 1 << 3
# Every filesystem right each ABI version knows about.
_FS_ALL_BY_ABI = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1}


def read_only_roots(extra: Iterable[str] = ()) -> list[str]:
    """Folders the interpreter, its libraries and the app are loaded from."""
    roots = {
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/localtime",
        sys.prefix,
        sys.base_prefix,
    }
    roots.update(
        sysconfig.get_paths()[key] for key in ("stdlib", "platstdlib", "purelib", "platlib")
    )
    roots.add(str(Path(__file__).resolve().parents[2]))  # the app itself (editable installs)
    roots.update(extra)
    return sorted(r for r in roots if r and Path(r).exists())


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def landlock_abi() -> int:
    libc = _libc()
    abi = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET, None, 0, _LANDLOCK_CREATE_RULESET_VERSION)
    return int(abi) if abi > 0 else 0


def apply_landlock(readable: Iterable[str]) -> bool:
    """Allows reading only beneath `readable`; returns False where Landlock is unavailable."""
    abi = landlock_abi()
    if abi <= 0:
        return False
    handled = _FS_ALL_BY_ABI.get(abi, _FS_ALL_BY_ABI[3])
    libc = _libc()
    attr = ctypes.create_string_buffer(struct.pack("=Q", handled))
    ruleset = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET, attr, 8, 0)
    if ruleset < 0:
        return False
    try:
        for path in readable:
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                is_dir = os.path.isdir(path)
                access = (_FS_READ_FILE | _FS_EXECUTE | (_FS_READ_DIR if is_dir else 0)) & handled
                rule = ctypes.create_string_buffer(struct.pack("=Qi", access, fd))
                if (
                    libc.syscall(
                        _SYS_LANDLOCK_ADD_RULE, ruleset, _LANDLOCK_RULE_PATH_BENEATH, rule, 0
                    )
                    != 0
                ):
                    raise SandboxUnavailableError(f"Landlock refused a rule for {path}.")
            finally:
                os.close(fd)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise SandboxUnavailableError("no_new_privs could not be set.")
        if libc.syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0) != 0:
            raise SandboxUnavailableError("Landlock could not be applied.")
        return True
    finally:
        os.close(ruleset)


def enter(limits: Limits, readable: Iterable[str] = ()) -> bool:
    """Locks the current process down. There is no way back.

    Returns whether the filesystem layer (Landlock) is in place.
    """
    seccomp = _library()  # loaded while the filesystem is still reachable
    apply_limits(limits)
    landlocked = apply_landlock(readable)
    apply_seccomp(lib=seccomp)
    return landlocked


_PR_SET_DUMPABLE = 4


def make_undumpable() -> bool:
    """Makes this process's /proc entries (environ, memory maps) unreadable to its own children.

    The worker calls it at start-up: even where Landlock is missing, a jailed
    parser can't read the worker's environment through /proc.
    """
    if not sys.platform.startswith("linux"):
        return False
    return bool(_libc().prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0)
