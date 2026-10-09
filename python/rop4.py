"""Python bindings for rop4 (a Go port of rop3).

Loads the rop4 C-shared library (librop4.so) built with
`go build -buildmode=c-shared -o python/librop4.so ./pybind` and exposes a
Rop4 class whose API mirrors rop3's Rop3 class:

    from rop4 import Rop4
    r = Rop4("libc.so.6", base="0x7f0000000000", symbols=True)
    for g in r.gadgets():
        print(g["vaddr"], g["gadget"])
    r.find_op("mov", ["rdi", "rax"])   # list of gadget dicts, or list of chains
    r.ropchain("chain.txt")            # list of chains (each a list of gadget dicts)
    r.describe()                       # per-binary metadata

`Rop3` is provided as an alias for drop-in familiarity.
"""

import ctypes
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB_PATH = os.environ.get("ROP4_LIB", os.path.join(_HERE, "librop4.so"))
_lib = ctypes.CDLL(_LIB_PATH)
_lib.Rop4Call.argtypes = [ctypes.c_char_p]
_lib.Rop4Call.restype = ctypes.c_void_p
_lib.Rop4Version.argtypes = []
_lib.Rop4Version.restype = ctypes.c_void_p
_lib.Rop4Free.argtypes = [ctypes.c_void_p]


class Rop4Error(Exception):
    """Raised when the rop4 engine reports an error."""


def _take(ptr):
    """Read a Go-owned C string and free it."""
    if not ptr:
        raise Rop4Error("null response from rop4")
    try:
        return ctypes.cast(ptr, ctypes.c_char_p).value.decode("utf-8")
    finally:
        _lib.Rop4Free(ptr)


def _call(req):
    resp = json.loads(_take(_lib.Rop4Call(json.dumps(req).encode("utf-8"))))
    if not resp.get("ok"):
        raise Rop4Error(resp.get("error", "unknown error"))
    return resp


def version():
    """The rop4 version string."""
    return _take(_lib.Rop4Version())


def _aslist(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return list(v)


class Rop4:
    """High-level entry point; mirrors rop3's Rop3 class.

    Gadgets are scanned per call on the Go side. Results are plain dicts/lists
    with the same shape as rop4's ``--output json``.
    """

    def __init__(self, binaries, *, depth=None, rop=True, jop=False, retf=False,
                 all=False, allow_undeterministic=False, allow_complex_mem=False,
                 avoid_canary=True, ret_imm=False, reg_aliases=False,
                 keep_contradictory=False, framed=True, ropblock=False, base=None,
                 badchars=None, badchar_bytes=None, arch=None, symbols=False,
                 raw=False, jobs=None):
        bins = [binaries] if isinstance(binaries, str) else list(binaries)
        self._opts = dict(
            binaries=bins, depth=depth or 0, rop=rop, jop=jop, retf=retf, all=all,
            allow_undeterministic=allow_undeterministic,
            allow_complex_mem=allow_complex_mem, avoid_canary=avoid_canary,
            ret_imm=ret_imm, reg_aliases=reg_aliases,
            keep_contradictory=keep_contradictory, frame=framed, ropblock=ropblock,
            base=_aslist(base), badchars=_aslist(badchars),
            badchar_bytes=_aslist(badchar_bytes), arch=arch or "", symbols=symbols,
            raw=raw, jobs=jobs or 0)

    def _req(self, method, **extra):
        return {**self._opts, "method": method, **extra}

    def gadgets(self):
        """All gadgets as a list of dicts."""
        return _call(self._req("gadgets"))["data"]

    def find_op(self, op, operands=None):
        """Gadgets (list of dicts) or, for a compound operation, a list of
        chains (each a list of gadget dicts) -- like rop3's find_op. Check with
        ``isinstance(result[0], list)``."""
        return _call(self._req("find_op", op=op, operands=list(operands or [])))["data"]

    def ropchain(self, ropfile, exhaustive=True):
        """Every ROP chain satisfying the ROPLang file, each a list of dicts."""
        return _call(self._req("ropchain", ropfile=ropfile, exhaustive=exhaustive))["data"]

    def describe(self):
        """Per-binary metadata dicts (format, arch, sections, ...)."""
        return _call(self._req("describe"))["data"]


Rop3 = Rop4  # drop-in name for users coming from rop3
