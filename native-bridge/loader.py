#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""迷你 ELF 加载器：把 arm64 的 .so 映射进 Unicorn 并处理重定位。

在我们实测的那个 .so 上只出现了 4 种重定位：
  ABS64(257), GLOB_DAT(1025), RELATIVE(1027), JUMP_SLOT(1026)
且没有任何 TLS 重定位，所以不需要搭 TLS 块，
只要给 tpidr_el0 一个可写地址（栈保护字在 TP+0x28）即可。

遇到别的 .so 时这几种可能不够 —— 缺什么补什么，报错会带重定位类型。
"""
import os
import struct
import sys

# 兼容「依赖放在同级 pylibs 目录」的用法；正常装完 requirements.txt 后这段是空操作
_LOCAL_LIBS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pylibs")
if os.path.isdir(_LOCAL_LIBS):
    sys.path.insert(0, _LOCAL_LIBS)
from elftools.elf.elffile import ELFFile

BASE = 0x40000000
HEAP = 0x50000000
HEAP_SIZE = 0x8000000        # 128MB
STACK = 0x60000000
STACK_SIZE = 0x200000
HOOKS = 0x70000000
HOOKS_SIZE = 0x40000         # 32768 个钩子槽
JNITBL = 0x71000000
JNITBL_SIZE = 0x10000
TCB = 0x72000000
TCB_SIZE = 0x10000
SCRATCH = 0x73000000
SCRATCH_SIZE = 0x10000
SENTINEL = 0x7F000000

R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027


def p64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def align_up(v, a):
    return (v + a - 1) // a * a


class Module:
    def __init__(self, uc, path, base=BASE):
        self.uc, self.path, self.base = uc, path, base
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.end = base
        self._map_and_load()

    def _map_and_load(self):
        loads = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        span = max(s["p_vaddr"] + s["p_memsz"] for s in loads)
        total = align_up(span, 0x1000) + 0x1000
        self.uc.mem_map(self.base, total)
        self.end = self.base + total
        for s in loads:
            self.f.seek(s["p_offset"])
            data = self.f.read(s["p_filesz"])
            if data:
                self.uc.mem_write(self.base + s["p_vaddr"], data)

    def sym_addr(self, sym, resolve_external):
        if sym["st_shndx"] == "SHN_UNDEF":
            return resolve_external(sym.name, sym["st_info"]["type"] == "STT_OBJECT")
        return self.base + sym["st_value"]

    def relocate(self, resolve_external, log=print):
        dynsym = self.elf.get_section_by_name(".dynsym")
        n = 0
        unknowns = []
        for secname in (".rela.dyn", ".rela.plt"):
            sec = self.elf.get_section_by_name(secname)
            if not sec:
                continue
            for rel in sec.iter_relocations():
                t = rel["r_info_type"]
                off = self.base + rel["r_offset"]
                addend = rel["r_addend"] if rel.is_RELA() else 0
                sym = dynsym.get_symbol(rel["r_info_sym"]) if rel["r_info_sym"] else None
                if t == R_AARCH64_RELATIVE:
                    val = self.base + addend
                elif t in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64):
                    val = self.sym_addr(sym, resolve_external)
                else:
                    unknowns.append((t, sym.name if sym else "?"))
                    continue
                self.uc.mem_write(off, p64(val))
                n += 1
        return n, unknowns

    def func(self, name):
        for s in self.elf.get_section_by_name(".dynsym").iter_symbols():
            if s.name == name and s["st_shndx"] != "SHN_UNDEF":
                return self.base + s["st_value"]
        return None

    def init_array(self):
        out = []
        for name in (".init_array", ".preinit_array"):
            sec = self.elf.get_section_by_name(name)
            if not sec:
                continue
            self.f.seek(sec["sh_offset"])
            raw = self.f.read(sec["sh_size"])
            for i in range(0, len(raw) - 7, 8):
                out.append(struct.unpack("<Q", raw[i:i + 8])[0])
        return out
