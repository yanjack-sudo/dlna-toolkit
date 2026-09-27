#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 Unicorn 在 PC 上跑 arm64 Android `.so` 里的导出函数。

组成：
  · Heap        —— 给 guest 用的 bump 分配器
  · Hooks       —— 132 个外部 libc 符号的 Python 实现 + 钩子页调度 + 假 JNIEnv
  · Emu         —— 装载模块、重定位、起栈、调用导出函数

作者备注：guest 调外部函数时 PC 会落在钩子页里，UC_HOOK_CODE 拦下来，
执行 Python 实现，把返回值塞 x0，然后把 PC 设回 LR（等价于 ret）。
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pylibs"))
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_LR, UC_ARM64_REG_PC,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_TPIDR_EL0)
from loader import (Module, HEAP, HEAP_SIZE, STACK, STACK_SIZE, HOOKS, HOOKS_SIZE,
                    JNITBL, JNITBL_SIZE, TCB, TCB_SIZE, SCRATCH, SCRATCH_SIZE,
                    SENTINEL, p64)

S = {}          # 全局：uc / heap / 日志


def log(msg):
    S.get("log", print)("[emu] %s" % msg)


# --------------------------------------------------------------------- 基础读写
def u8(uc, a): return uc.mem_read(a, 1)[0]
def u32(uc, a): return struct.unpack("<I", uc.mem_read(a, 4))[0]
def s32(uc, a): return struct.unpack("<i", uc.mem_read(a, 4))[0]
def u64(uc, a): return struct.unpack("<Q", uc.mem_read(a, 8))[0]
def w32(uc, a, v): uc.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))
def w64(uc, a, v): uc.mem_write(a, p64(v))


def cstr(uc, addr, maxlen=1 << 16):
    if not addr:
        return b""
    out = bytearray()
    while len(out) < maxlen:
        try:
            chunk = bytes(uc.mem_read(addr + len(out), 256))
        except Exception:
            break                       # 指针非法就返回已读到的部分
        i = chunk.find(b"\0")
        if i >= 0:
            out += chunk[:i]
            break
        out += chunk
    return bytes(out)


def arg(uc, i):
    return uc.reg_read(UC_ARM64_REG_X0 + i)


# --------------------------------------------------------------------- 堆
class Heap:
    def __init__(self, uc):
        self.uc = uc
        self.cur = HEAP + 0x1000
        uc.mem_map(HEAP, HEAP_SIZE)

    def alloc(self, size, align=16):
        if size <= 0:
            size = 1
        size = (size + 15) & ~15
        p = (self.cur + align - 1) // align * align
        if p + size + 32 >= HEAP + HEAP_SIZE:
            raise MemoryError("guest heap exhausted (%d)" % size)
        self.cur = p + size + 32
        w64(self.uc, p - 16, size)
        return p

    def size_of(self, p):
        try:
            return u64(self.uc, p - 16)
        except Exception:
            return 0


# ------------------------------------------------------------------ libc 实现
def h_malloc(uc):
    return S["heap"].alloc(arg(uc, 0))


def h_calloc(uc):
    n, sz = arg(uc, 0), arg(uc, 1)
    p = S["heap"].alloc(n * sz)
    uc.mem_write(p, b"\0" * (n * sz))
    return p


def h_realloc(uc):
    p, sz = arg(uc, 0), arg(uc, 1)
    if not p:
        return S["heap"].alloc(sz)
    old = S["heap"].size_of(p)
    np = S["heap"].alloc(sz)
    uc.mem_write(np, bytes(uc.mem_read(p, min(old, sz) or 1)))
    return np


def h_posix_memalign(uc):
    out, align, size = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    p = S["heap"].alloc(size, max(align, 16))
    w64(uc, out, p)
    return 0


def mem_copy(uc):
    dst, src, n = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    if n:
        uc.mem_write(dst, bytes(uc.mem_read(src, n)))
    return dst


def mem_set(uc):
    dst, c, n = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    if n:
        uc.mem_write(dst, bytes([c & 0xFF]) * n)
    return dst


def mem_cmp(uc):
    a, b, n = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    x, y = bytes(uc.mem_read(a, n)), bytes(uc.mem_read(b, n))
    return 0 if x == y else (-1 if x < y else 1)


def mem_chr(uc):
    s, c, n = arg(uc, 0), arg(uc, 1) & 0xFF, arg(uc, 2)
    buf = bytes(uc.mem_read(s, n))
    i = buf.find(bytes([c]))
    return s + i if i >= 0 else 0


def c_strlen(uc):
    return len(cstr(uc, arg(uc, 0)))


def str_cmp(uc):
    a, b = cstr(uc, arg(uc, 0)), cstr(uc, arg(uc, 1))
    return 0 if a == b else (-1 if a < b else 1)


def str_ncmp(uc):
    a, b, n = cstr(uc, arg(uc, 0))[:arg(uc, 2)], cstr(uc, arg(uc, 1))[:arg(uc, 2)]
    return 0 if a == b else (-1 if a < b else 1)


def str_cpy(uc):
    dst, src = arg(uc, 0), cstr(uc, arg(uc, 1))
    uc.mem_write(dst, src + b"\0")
    return dst


def str_ncpy(uc):
    dst, src, n = arg(uc, 0), cstr(uc, arg(uc, 1)), arg(uc, 2)
    data = src[:n]
    uc.mem_write(dst, data + b"\0" * (n - len(data)))
    return dst


def str_cat(uc):
    dst, src = arg(uc, 0), cstr(uc, arg(uc, 0)) + cstr(uc, arg(uc, 1))
    uc.mem_write(dst, src + b"\0")
    return dst


def str_chr(uc):
    s = cstr(uc, arg(uc, 0))
    c = arg(uc, 1) & 0xFF
    i = s.find(bytes([c]))
    return arg(uc, 0) + i if i >= 0 else 0


def str_rchr(uc):
    s = cstr(uc, arg(uc, 0))
    c = arg(uc, 1) & 0xFF
    i = s.rfind(bytes([c]))
    return arg(uc, 0) + i if i >= 0 else 0


def str_str(uc):
    h = cstr(uc, arg(uc, 0))
    n = cstr(uc, arg(uc, 1))
    i = h.find(n)
    return arg(uc, 0) + i if i >= 0 else 0


def str_dup(uc):
    s = cstr(uc, arg(uc, 0))
    p = S["heap"].alloc(len(s) + 1)
    uc.mem_write(p, s + b"\0")
    return p


def h_strtol(uc):
    s = cstr(uc, arg(uc, 0)).strip().split(b"\0")[0]
    base = arg(uc, 2) or 10
    endp = arg(uc, 1)
    try:
        txt = s.decode("ascii", "ignore")
        v = int(txt, base) if base != 16 or not txt.lower().startswith("0x") else int(txt, 16)
    except Exception:
        v = 0
    if endp:
        w64(uc, endp, arg(uc, 0) + len(s))
    return v


def h_atoi(uc):
    try:
        return int(cstr(uc, arg(uc, 0)).strip() or b"0")
    except Exception:
        return 0


def h_abs(uc):
    v = s32(uc, 0) if False else arg(uc, 0)
    return abs(struct.unpack("<i", struct.pack("<I", v & 0xFFFFFFFF))[0])


# ---- 时间 / 随机 ----
def h_clock_gettime(uc):
    ts, sec = arg(uc, 1), time.time()
    w64(uc, ts, int(sec))
    w64(uc, ts + 8, int((sec % 1) * 1e9))
    return 0


def h_time(uc):
    t = int(time.time())
    if arg(uc, 0):
        w64(uc, arg(uc, 0), t)
    return t


def h_gettimeofday(uc):
    tv, sec = arg(uc, 0), time.time()
    if tv:
        w64(uc, tv, int(sec))
        w64(uc, tv + 8, int((sec % 1) * 1e6))
    return 0


def h_getrandom(uc):
    buf, n = arg(uc, 0), arg(uc, 1)
    uc.mem_write(buf, os.urandom(n))
    return n


def h_open(uc):
    path = cstr(uc, arg(uc, 0)).decode("utf-8", "replace")
    S.setdefault("fds", {})
    if "urandom" in path or "random" in path:
        fd = 900 + len(S["fds"])
        S["fds"][fd] = "random"
        return fd
    return -1


def h_read(uc):
    fd, buf, n = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    if S.get("fds", {}).get(fd) == "random":
        uc.mem_write(buf, os.urandom(n))
        return n
    return 0


def h_close(uc):
    return 0


# ---- 日志 ----
def h_log_print(uc):
    try:
        tag = cstr(uc, arg(uc, 0)).decode("utf-8", "replace")
        fmtp = 2
        if arg(uc, 3):
            fmtp = 3
        msg = cstr(uc, arg(uc, fmtp)).decode("utf-8", "replace")
        log("android_log[%s] %s" % (tag, msg))
    except Exception:
        pass
    return 0


def h_fprintf(uc):
    return 0


def h_fwrite(uc):
    return arg(uc, 2)


def h_abort(uc):
    raise RuntimeError("guest called abort()")


# AArch64 Linux 系统调用号（bionic 的 syscall() 是普通 C 函数：号在 x0，参数 x1..x5）
SYSCALL_NAMES = {56: "openat", 57: "close", 63: "read", 64: "write", 66: "writev", 96: "set_tid_address",
                 98: "futex", 99: "set_robust_list", 101: "nanosleep", 113: "clock_gettime",
                 117: "ptrace", 129: "kill", 131: "tgkill", 134: "rt_sigaction", 135: "rt_sigprocmask",
                 160: "uname", 169: "gettimeofday", 172: "getpid", 178: "gettid", 214: "brk", 215: "munmap",
                 222: "mmap", 226: "clock_nanosleep", 260: "wait4", 261: "prlimit64", 278: "getrandom",
                 291: "statx", 293: "rseq"}


def h_syscall(uc):
    n = arg(uc, 0)
    a1, a2, a3, a4 = arg(uc, 1), arg(uc, 2), arg(uc, 3), arg(uc, 4)
    if n == 278:                                  # getrandom
        try:
            uc.mem_write(a1, os.urandom(a2))
        except Exception:
            return 0xFFFFFFFFFFFFFFFF
        return a2
    if n == 113:                                  # clock_gettime
        sec = time.time()
        p = a2 if a2 else a1
        w64(uc, p, int(sec))
        w64(uc, p + 8, int((sec % 1) * 1e9))
        return 0
    if n == 169:                                  # gettimeofday
        sec = time.time()
        w64(uc, a1, int(sec))
        w64(uc, a1 + 8, int((sec % 1) * 1e6))
        return 0
    if n in (64, 66):                             # write / writev → 打到日志里
        try:
            log("guest write: %r" % bytes(uc.mem_read(a2, min(a3, 200))))
        except Exception:
            pass
        return a3
    if n == 63:                                   # read
        return 0
    if n in (57, 56):                             # close / openat
        return -1 if n == 56 else 0
    if n == 222:                                  # mmap → 从 guest 堆里给一块
        size = a2
        p = S["heap"].alloc(max(size, 0x1000), 0x1000)
        return p
    if n in (215, 214, 98, 99, 226, 101, 135, 260, 261):
        return 0                                  # munmap/brk/futex/... 当作成功
    if n == 96:                                   # set_tid_address
        return 1
    if n in (172, 178):                           # getpid / gettid
        return 4242
    if n == 293:                                  # rseq
        return 0xFFFFFFFFFFFFFFFF
    if n == 160:                                  # uname
        if a1:
            uc.mem_write(a1, b"Linux\0" + b"\0" * 250)
        return 0
    if n == 131:                                  # tgkill（线程自杀）
        raise RuntimeError("guest tgkill -> abort path")
    log("!! 未实现的 syscall %d(%s) args=%x,%x,%x" % (n, SYSCALL_NAMES.get(n, "?"), a1, a2, a3))
    return 0xFFFFFFFFFFFFFFFF


def h_stack_chk_fail(uc):
    raise RuntimeError("guest __stack_chk_fail (canary mismatch!)")


# ---- pthread（单线程：全部 trivially 成功）----
def _ret0(uc):
    return 0


def h_pthread_key_create(uc):
    S.setdefault("tls_keys", [])
    k = len(S["tls_keys"]) + 1
    S["tls_keys"].append({})
    w32(uc, arg(uc, 0), k)
    return 0


def h_pthread_getspecific(uc):
    return S.setdefault("tls_vals", {}).get(arg(uc, 0), 0)


def h_pthread_setspecific(uc):
    S.setdefault("tls_vals", {})[arg(uc, 0)] = arg(uc, 1)
    return 0


def h_pthread_self(uc):
    return 1


def h_pthread_equal(uc):
    return 1 if arg(uc, 0) == arg(uc, 1) else 0


# ---- locale / ctype（尽量保守）----
def h_newlocale(uc):
    return 1


def h_localeconv(uc):
    p = S.setdefault("lconv", S["heap"].alloc(128))
    dot = S.setdefault("dot", S["heap"].alloc(2))
    S["uc"].mem_write(dot, b".\0")
    w64(S["uc"], p, dot)
    return p


def h_setlocale(uc):
    ret = S.setdefault("c_locale", S["heap"].alloc(2))
    S["uc"].mem_write(ret, b"C\0")
    return ret


def h_mb_cur_max(uc):
    return 4


def h_btowc(uc):
    return arg(uc, 0) & 0xFF if (arg(uc, 0) & 0xFF) < 0x80 else 0xFFFFFFFFFFFFFFFF


def _empty_cstr():
    uc = S["uc"]
    p = S.setdefault("empty_str", S["heap"].alloc(1))
    uc.mem_write(p, b"\0")
    return p


def h_wcslen(uc):
    p, n = arg(uc, 0), 0
    while u32(S["uc"], p + 4 * n) != 0:
        n += 1
    return n


def h_wcrtomb(uc):
    dst, wc = arg(uc, 0), arg(uc, 1)
    try:
        b = chr(wc).encode("utf-8")
    except Exception:
        b = b"?"
    S["uc"].mem_write(dst, b + b"\0")
    return len(b)


def _simple_wc_test(pred):
    def f(uc):
        try:
            return 1 if pred(chr(arg(uc, 0) & 0x10FFFF)) else 0
        except Exception:
            return 0
    return f


def h_mbrtowc(uc):
    pwc, s, n = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    if not s or n == 0:
        return 0
    b = bytes(uc.mem_read(s, min(n, 4)))
    for ln in (1, 2, 3, 4):
        try:
            ch = b[:ln].decode("utf-8")
            if len(ch) == 1:
                if pwc:
                    w32(uc, pwc, ord(ch))
                return ln
        except Exception:
            continue
    return 0xFFFFFFFFFFFFFFFE  # (size_t)-2


def h_mbrlen(uc):
    s, n = arg(uc, 0), arg(uc, 1)
    if not s:
        return 0
    b = bytes(uc.mem_read(s, min(n, 4)))
    for ln in (1, 2, 3, 4):
        try:
            if len(b[:ln].decode("utf-8")) == 1:
                return ln
        except Exception:
            continue
    return 0xFFFFFFFFFFFFFFFE


def h_mbtowc(uc):
    pwc, s, n = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    if not s or n == 0:
        return 0
    b = bytes(uc.mem_read(s, min(n, 4)))
    for ln in (1, 2, 3, 4):
        try:
            ch = b[:ln].decode("utf-8")
            if len(ch) == 1:
                if pwc:
                    w32(uc, pwc, ord(ch))
                return ln
        except Exception:
            continue
    return -1


def h_mbsrtowcs(uc):
    dst, srcp, len_, ps = arg(uc, 0), arg(uc, 1), arg(uc, 2), arg(uc, 3)
    s = cstr(uc, u64(uc, srcp))
    try:
        txt = s.decode("utf-8", "replace")
    except Exception:
        return 0xFFFFFFFFFFFFFFFF
    cnt = 0
    for i, ch in enumerate(txt):
        if len_ and i >= len_:
            break
        if dst:
            w32(uc, dst + 4 * i, ord(ch))
        cnt += 1
    if dst:
        w32(uc, dst + 4 * cnt, 0)
        w64(uc, srcp, 0)
    return cnt


# ---- printf ----
def _fmt(uc, fmt, next_int, next_fp=None):
    out = bytearray()
    i, n = 0, len(fmt)
    while i < n:
        c = fmt[i]
        if c != 0x25:                      # '%'
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        if fmt[i:i + 1] == b"%":
            out.append(0x25)
            i += 1
            continue
        flags = b""
        while i < n and fmt[i:i + 1] in b"-+ #0":
            flags += fmt[i:i + 1]
            i += 1
        width = b""
        while i < n and fmt[i:i + 1].isdigit():
            width += fmt[i:i + 1]
            i += 1
        prec = None
        if i < n and fmt[i:i + 1] == b".":
            i += 1
            prec = b""
            while i < n and fmt[i:i + 1].isdigit():
                prec += fmt[i:i + 1]
                i += 1
            prec = int(prec or b"0")
        length = b""
        while i < n and fmt[i:i + 1] in b"lhLzjtq":
            length += fmt[i:i + 1]
            i += 1
        if i >= n:
            break
        conv = chr(fmt[i])
        i += 1
        if conv in "di":
            v = next_int()
            if "l" not in length and not length:
                v = struct.unpack("<i", struct.pack("<I", v & 0xFFFFFFFF))[0]
            txt = str(v).encode()
        elif conv == "u":
            txt = str(next_int() & 0xFFFFFFFFFFFFFFFF).encode()
        elif conv in "xX":
            txt = ("%x" % (next_int() & 0xFFFFFFFFFFFFFFFF)).encode()
            if conv == "X":
                txt = txt.upper()
        elif conv == "o":
            txt = ("%o" % (next_int() & 0xFFFFFFFFFFFFFFFF)).encode()
        elif conv == "p":
            txt = ("0x%x" % next_int()).encode()
        elif conv == "c":
            txt = bytes([next_int() & 0xFF])
        elif conv == "s":
            p = next_int()
            txt = cstr(uc, p) if p else b"(null)"
            if prec is not None:
                txt = txt[:prec]
        elif conv in "fFeEgG":
            v = next_fp() if next_fp else 0.0
            txt = ("%f" % v).encode()
        elif conv == "%":
            txt = b"%"
        else:
            txt = (b"%" + length + conv.encode())
        if width:
            w = int(width)
            pad = b"0" if (b"0" in flags and b"-" not in flags) else b" "
            if len(txt) < w:
                if b"-" in flags:
                    txt = txt + b" " * (w - len(txt))
                else:
                    txt = pad * (w - len(txt)) + txt
        out += txt
    return bytes(out)


def _va_next(uc, va, fp=False):
    stack, gr_top, vr_top = u64(uc, va), u64(uc, va + 8), u64(uc, va + 16)
    gr_off, vr_off = s32(uc, va + 24), s32(uc, va + 28)
    if fp:
        if vr_off < 0:
            val = struct.unpack("<d", uc.mem_read(vr_top + vr_off, 8))[0]
            w32(uc, va + 28, vr_off + 16)
        else:
            val = struct.unpack("<d", uc.mem_read(stack, 8))[0]
            w64(uc, va, stack + 8)
        return val
    if gr_off < 0:
        val = u64(uc, gr_top + gr_off)
        w32(uc, va + 24, gr_off + 8)
    else:
        val = u64(uc, stack)
        w64(uc, va, stack + 8)
    return val


def _make_va(uc, regs, sp):
    """把 x3..x7 + 栈参数伪造成一个 AAPCS64 va_list"""
    va = SCRATCH
    gr_base = SCRATCH + 0x400
    for i, v in enumerate(regs):
        w64(uc, gr_base - 40 + i * 8, v)
    w64(uc, va + 0, sp)
    w64(uc, va + 8, gr_base)
    w64(uc, va + 16, gr_base)
    w32(uc, va + 24, -8 * len(regs))     # 依次向上取
    w32(uc, va + 28, -128)
    return va


def _vsnprintf_common(uc, buf, size, fmtp, va):
    fmt = bytes(uc.mem_read(fmtp, 512)).split(b"\0")[0] if fmtp else b""
    txt = _fmt(uc, fmt, lambda: _va_next(uc, va), lambda: _va_next(uc, va, True))
    n = min(len(txt), size - 1) if size else 0
    if size:
        try:
            uc.mem_write(buf, txt[:n] + b"\0")
        except Exception:
            pass
    return len(txt)


def h_snprintf(uc):
    buf, size, fmtp = arg(uc, 0), arg(uc, 1), arg(uc, 2)
    va = _make_va(uc, [arg(uc, 3), arg(uc, 4), arg(uc, 5), arg(uc, 6), arg(uc, 7)],
                  uc.reg_read(UC_ARM64_REG_SP))
    return _vsnprintf_common(uc, buf, size, fmtp, va)


def h_vsnprintf(uc):
    return _vsnprintf_common(uc, arg(uc, 0), arg(uc, 1), arg(uc, 2), arg(uc, 3))


def h_vsnprintf_chk(uc):
    # int __vsnprintf_chk(char* s, size_t n, int flag, size_t slen, const char* fmt, va_list ap)
    return _vsnprintf_common(uc, arg(uc, 0), arg(uc, 1), arg(uc, 4), arg(uc, 5))


def h_snprintf_chk(uc):
    # int __snprintf_chk(char* s, size_t n, int flag, size_t slen, const char* fmt, ...)
    buf, size, fmtp = arg(uc, 0), arg(uc, 1), arg(uc, 4)
    va = _make_va(uc, [arg(uc, 5), arg(uc, 6), arg(uc, 7), 0, 0],
                  uc.reg_read(UC_ARM64_REG_SP))
    return _vsnprintf_common(uc, buf, size, fmtp, va)


# --------------------------------------------------------------- 假 JNIEnv
JNI_STRINGS = {}
JNI_NEW_STRING_UTF = 167
JNI_GET_STRING_UTFLEN = 168
JNI_GET_STRING_UTFCHARS = 169
JNI_GET_STRING_LENGTH = 170
JNI_RELEASE_STRING_UTFCHARS = 171


def jni_new_string_utf(uc):
    s = cstr(uc, arg(uc, 1))
    p = S["heap"].alloc(len(s) + 1)
    uc.mem_write(p, s + b"\0")
    h = S["heap"].alloc(16)
    w64(uc, h, p)
    w64(uc, h + 8, len(s))
    JNI_STRINGS[h] = s
    return h


def jni_get_string_utfchars(uc):
    j = arg(uc, 1)
    return u64(uc, j) if j in JNI_STRINGS else 0


def jni_get_string_length(uc):
    j = arg(uc, 1)
    return len(JNI_STRINGS.get(j, b"").decode("utf-8", "replace"))


def jni_get_string_utflen(uc):
    return len(JNI_STRINGS.get(arg(uc, 1), b""))


# --------------------------------------------------------------- 钩子调度器
class Hooks:
    def __init__(self, uc):
        self.uc = uc
        self.n = 0
        self.handlers = {}
        self.by_name = {}
        uc.mem_map(HOOKS, HOOKS_SIZE)
        uc.mem_map(JNITBL, JNITBL_SIZE)
        uc.mem_map(TCB, TCB_SIZE)
        uc.mem_map(SCRATCH, SCRATCH_SIZE)
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TCB + 0x800)
        self.errno_slot = S["heap"].alloc(8)

    def stub(self, name, fn):
        addr = HOOKS + self.n * 8
        self.n += 1
        self.uc.mem_write(addr, b"\x1f\x20\x03\xd5")     # nop
        if fn is None:
            def fn(uc, _n=name):
                raise RuntimeError("没实现的符号被调用了: %s" % _n)
        self.handlers[addr] = (name, fn)
        if name:
            self.by_name[name] = addr
        return addr

    def resolve(self, name, is_data=False):
        if name in self.by_name:
            return self.by_name[name]
        if name == "__sF":                      # bionic 的 stdio 数组（data 符号）
            addr = S["heap"].alloc(3 * 256)
            self.by_name[name] = addr
            return addr
        if name == "__errno":                   # bionic 里是函数，返回 int*
            self.by_name[name] = self.stub(name, lambda uc: self.errno_slot)
            return self.by_name[name]
        if is_data and name not in TABLE:       # 其它数据符号：给一块清零内存
            addr = S["heap"].alloc(512)
            log("数据符号 %s -> 0x%x (清零)" % (name, addr))
            self.by_name[name] = addr
            return addr
        fn = TABLE.get(name)
        addr = self.stub(name, fn)
        self.by_name[name] = addr
        return addr

    def make_jnienv(self):
        table = {JNI_NEW_STRING_UTF: jni_new_string_utf,
                 JNI_GET_STRING_UTFLEN: jni_get_string_utflen,
                 JNI_GET_STRING_UTFCHARS: jni_get_string_utfchars,
                 JNI_GET_STRING_LENGTH: jni_get_string_length,
                 JNI_RELEASE_STRING_UTFCHARS: lambda uc: 0}
        for i in range(256):
            a = self.stub("jni_%d" % i, table.get(i))
            w64(self.uc, JNITBL + i * 8, a)
        # JNI 的 C ABI：native 函数收到的是 JNIEnv*，即"指向函数表指针的指针"
        # （(*env)->NewStringUTF），所以要先放一个指向 JNITBL 的指针
        holder = S["heap"].alloc(8)
        w64(self.uc, holder, JNITBL)
        return holder

    def install(self):
        self.trace = []
        self.trace_on = bool(os.environ.get("EMU_TRACE"))

        def cb(uc, address, size, user):
            name, fn = self.handlers[address]
            try:
                ret = fn(uc)
            except Exception as e:
                raise RuntimeError("符号 %s 处理出错: %r (x0..x3=%x,%x,%x,%x)" % (
                    name, e, arg(uc, 0), arg(uc, 1), arg(uc, 2), arg(uc, 3))) from e
            uc.reg_write(UC_ARM64_REG_X0, (ret or 0) & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

        self.uc.hook_add(UC_HOOK_CODE, cb, None, HOOKS, HOOKS + HOOKS_SIZE)

        # 返回哨兵：栈上 ret 回到 SENTINEL 时停止模拟
        self.uc.mem_map(SENTINEL, 0x1000)
        self.uc.mem_write(SENTINEL, b"\x1f\x20\x03\xd5")      # nop

        def stop_cb(uc, address, size, user):
            uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, stop_cb, None, SENTINEL, SENTINEL + 0x1000)

        if self.trace_on:
            def tr(uc, address, size, user):
                self.trace.append(address)
                if len(self.trace) > 200:
                    del self.trace[:100]
            self.uc.hook_add(UC_HOOK_CODE, tr, None, self.module_range[0], self.module_range[1])

    def set_module_range(self, lo, hi):
        self.module_range = (lo, hi)


# ------------------------------------------------------------------ 符号表
TABLE = {
    "malloc": h_malloc, "free": _ret0, "calloc": h_calloc, "realloc": h_realloc,
    "posix_memalign": h_posix_memalign,
    "memcpy": mem_copy, "memmove": mem_copy, "memset": mem_set, "memcmp": mem_cmp,
    "memchr": mem_chr, "__memmove_chk": mem_copy, "__strlen_chk": c_strlen,
    "__stack_chk_fail": h_stack_chk_fail,
    "strlen": c_strlen, "strcmp": str_cmp, "strncmp": str_ncmp, "strcpy": str_cpy,
    "strncpy": str_ncpy, "strcat": str_cat, "strchr": str_chr, "strrchr": str_rchr,
    "strstr": str_str, "strdup": str_dup, "strtol": h_strtol, "atoi": h_atoi,
    "clock_gettime": h_clock_gettime, "time": h_time, "gettimeofday": h_gettimeofday,
    "nanosleep": _ret0, "getrandom": h_getrandom, "syscall": h_syscall,
    "open": h_open, "__open_2": h_open, "read": h_read, "__read_chk": h_read,
    "close": h_close,
    "__android_log_print": h_log_print, "__android_log_write": h_log_print,
    "openlog": _ret0, "closelog": _ret0,
    "android_set_abort_message": _ret0, "abort": h_abort,
    "fprintf": h_fprintf, "fwrite": h_fwrite, "fputc": _ret0, "fflush": _ret0,
    "fputs": _ret0, "puts": _ret0, "printf": _ret0,
    "snprintf": h_snprintf, "vsnprintf": h_vsnprintf,
    "__vsnprintf_chk": h_vsnprintf_chk, "__snprintf_chk": h_snprintf_chk,
    "pthread_mutex_init": _ret0, "pthread_mutex_destroy": _ret0,
    "pthread_mutex_lock": _ret0, "pthread_mutex_unlock": _ret0,
    "pthread_mutex_trylock": _ret0,
    "pthread_cond_init": _ret0, "pthread_cond_destroy": _ret0, "pthread_cond_wait": _ret0,
    "pthread_cond_timedwait": _ret0, "pthread_cond_signal": _ret0,
    "pthread_cond_broadcast": _ret0,
    "pthread_key_create": h_pthread_key_create, "pthread_key_delete": _ret0,
    "pthread_getspecific": h_pthread_getspecific, "pthread_setspecific": h_pthread_setspecific,
    "pthread_self": h_pthread_self, "pthread_equal": h_pthread_equal,
    "pthread_detach": _ret0, "pthread_join": _ret0,
    "pthread_once": _ret0,
    "__cxa_atexit": _ret0, "__cxa_finalize": _ret0,
    "__cxa_guard_acquire": lambda uc: 1,
    "__cxa_guard_release": _ret0, "__cxa_guard_abort": _ret0,
    "dl_iterate_phdr": _ret0, "dlopen": _ret0, "dlsym": _ret0, "dlclose": _ret0,
    "sched_yield": _ret0, "sysconf": lambda uc: 4096,
    "getpid": lambda uc: 4242, "gettid": lambda uc: 4242,
    "setlocale": h_setlocale, "newlocale": h_newlocale, "freelocale": _ret0,
    "localeconv": h_localeconv, "__ctype_get_mb_cur_max": h_mb_cur_max, "btowc": h_btowc,    "mbrtowc": h_mbrtowc, "mbrlen": h_mbrlen, "mbtowc": h_mbtowc,
    "mbsrtowcs": h_mbsrtowcs, "mbsnrtowcs": h_mbsrtowcs,
    "isdigit_l": _simple_wc_test(lambda c: c.isdigit()),
    "islower_l": _simple_wc_test(lambda c: c.islower()),
    "isupper_l": _simple_wc_test(lambda c: c.isupper()),
    "isxdigit_l": _simple_wc_test(lambda c: c in "0123456789abcdefABCDEF"),
    "iswalpha_l": _simple_wc_test(lambda c: c.isalpha()),
    "iswblank_l": _simple_wc_test(lambda c: c in " \t"),
    "iswcntrl_l": _simple_wc_test(lambda c: ord(c) < 32),
    "iswdigit_l": _simple_wc_test(lambda c: c.isdigit()),
    "iswlower_l": _simple_wc_test(lambda c: c.islower()),
    "iswprint_l": _simple_wc_test(lambda c: c.isprintable()),
    "iswpunct_l": _simple_wc_test(lambda c: not c.isalnum() and c.isprintable()),
    "iswspace_l": _simple_wc_test(lambda c: c.isspace()),
    "iswupper_l": _simple_wc_test(lambda c: c.isupper()),
    "iswxdigit_l": _simple_wc_test(lambda c: c in "0123456789abcdefABCDEF"),
    # libc++ 用到但对我们无关紧要的 locale/字符串/宽字符
    "uselocale": lambda uc: 1, "duplocale": lambda uc: 1,
    "localeconv_l": h_localeconv, "mbsinit": lambda uc: 1,
    "nl_langinfo": lambda uc: _empty_cstr(), "nl_langinfo_l": lambda uc: _empty_cstr(),
    "strtod": lambda uc: 0, "strtof": lambda uc: 0,
    "strtoll": h_strtol, "strtoull": h_strtol, "strtoul": h_strtol,
    "strncat": str_cat, "strspn": lambda uc: 0, "strcspn": lambda uc: 0,
    "strpbrk": lambda uc: 0, "memmem": lambda uc: 0,
    "snprintf_l": h_snprintf, "vsnprintf_l": h_vsnprintf,
    "wcscoll": lambda uc: 0, "wcslen": h_wcslen, "wcrtomb": h_wcrtomb,
    "mbrtoc32": lambda uc: 0xFFFFFFFFFFFFFFFE, "c32rtomb": lambda uc: 1,
    "__cxa_thread_atexit_impl": _ret0, "__cxa_pure_virtual": h_abort,
    "posix_memalign(?)": _ret0,
}



# ------------------------------------------------------------------ 对外的 Emu
class Emu:
    def __init__(self, so_path, logfn=print):
        S["log"] = logfn
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        S["uc"] = self.uc
        S["heap"] = Heap(self.uc)
        self.hooks = Hooks(self.uc)
        self.mod = Module(self.uc, so_path)
        n, unk = self.mod.relocate(self.hooks.resolve, logfn)
        logfn("[emu] 重定位 %d 条，未识别类型 %s" % (n, set(unk) or "无"))
        self.uc.mem_map(STACK, STACK_SIZE)
        self.env = self.hooks.make_jnienv()
        self.hooks.set_module_range(self.mod.base, self.mod.end)
        self.hooks.install()
        logfn("[emu] 加载完成: %s" % os.path.basename(so_path))

    def call(self, name, args=(), count=2_000_000, timeout=30_000_000):
        addr = self.mod.func(name)
        if addr is None:
            raise RuntimeError("找不到导出函数 %s" % name)
        sp = STACK + STACK_SIZE - 0x2000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_LR, SENTINEL)
        for i, a in enumerate(args):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, a)
        pc_before = addr
        try:
            self.uc.emu_start(addr, SENTINEL, timeout=timeout, count=count)
        except UcError as e:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            lr = self.uc.reg_read(UC_ARM64_REG_LR)
            info = "[emu] %s 执行失败: %s  PC=0x%x LR=0x%x 入口=0x%x" % (name, e, pc, lr, addr)
            if self.hooks.trace:
                tail = self.hooks.trace[-24:]
                info += "\n[emu] 最后 24 条指令地址: " + " ".join("0x%x" % a for a in tail)
            raise RuntimeError(info) from e
        return self.uc.reg_read(UC_ARM64_REG_X0)

    def jstring(self, handle):
        try:
            return JNI_STRINGS.get(handle, b"").decode("utf-8", "replace")
        except Exception:
            return ""

    def new_jstring(self, text: str):
        """把一个 UTF-8 字符串变成 guest 里的 jstring"""
        s = text.encode("utf-8")
        p = S["heap"].alloc(len(s) + 1)
        self.uc.mem_write(p, s + b"\0")
        h = S["heap"].alloc(16)
        w64(self.uc, h, p)
        w64(self.uc, h + 8, len(s))
        JNI_STRINGS[h] = s
        return h
