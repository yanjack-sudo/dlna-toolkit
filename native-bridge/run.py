#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""native-bridge 命令行入口：加载一个 arm64 Android `.so`，列出或调用它的导出函数。

用法:
    # 先看看这个 .so 导出了哪些 JNI 函数
    python run.py --so /path/to/libfoo.so --list

    # 调一个返回字符串的无参函数（JNI 签名：env, thiz）
    python run.py --so /path/to/libfoo.so --call Java_com_example_Foo_getVersion

    # 调一个接收字符串的函数
    python run.py --so /path/to/libfoo.so --call Java_com_example_Foo_hash --arg hello

    # 自检：能不能装载、重定位、起栈
    python run.py --so /path/to/libfoo.so --selftest
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    from emu import Emu
except ImportError as e:      # pragma: no cover
    print("依赖缺失：%s" % e)
    print("先跑：pip install -r requirements.txt")
    sys.exit(1)


def list_exports(so):
    from elftools.elf.elffile import ELFFile
    out = []
    with open(so, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".dynsym")
        if symtab is None:
            return out
        for sym in symtab.iter_symbols():
            name = sym.name
            if not name:
                continue
            if sym["st_shndx"] == "SHN_UNDEF":
                continue
            out.append((name, sym["st_info"]["type"], sym["st_size"]))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(description="在桌面上调用 arm64 Android .so 的导出函数")
    ap.add_argument("--so", required=True, help="目标 .so 路径")
    ap.add_argument("--list", action="store_true", help="列出导出符号后退出")
    ap.add_argument("--call", metavar="SYMBOL", help="要调用的导出函数名")
    ap.add_argument("--arg", action="append", default=[],
                    help="传给函数的字符串参数（可重复；会作为 jstring 传入）")
    ap.add_argument("--selftest", action="store_true", help="只做装载自检")
    ap.add_argument("--verbose", action="store_true", help="打印模拟层日志")
    a = ap.parse_args()

    if not os.path.exists(a.so):
        print("找不到文件：%s" % a.so)
        return 1

    if a.list:
        syms = list_exports(a.so)
        print("=== %s 共 %d 个导出符号 ===" % (os.path.basename(a.so), len(syms)))
        for name, typ, size in syms:
            if name.startswith("Java_"):
                print("  %-70s FUNC %6d" % (name, size))
        print("\n（上面只列了 JNI 函数；完整符号表用 `nm -D` 或 readelf 看）")
        return 0

    log = (lambda m: print("    [emu] %s" % m)) if a.verbose else (lambda m: None)
    print("装载 %s …" % a.so)
    e = Emu(a.so, logfn=log)
    print("  ✓ PT_LOAD 段已映射、重定位已完成、栈与 TCB 就绪")

    if a.selftest or not a.call:
        print("\n自检通过。用 --list 看导出函数，用 --call 调用它们。")
        return 0

    # 组装参数：JNI 约定 (JNIEnv*, jobject|jclass, ...)
    args = [e.env, 0]
    for s in a.arg:
        args.append(e.new_jstring(s))

    print("\n调用 %s(%s)" % (a.call, ", ".join(["env", "0"] + list(a.arg))))
    try:
        ret = e.call(a.call, args)
    except Exception as ex:
        print("  ✗ 调用失败：%r" % ex)
        print("  如果提示缺少某个符号，说明它的 libc/JNI 依赖还没实现 —— "
              "在 emu.py 的钩子表里补一个即可。")
        return 1

    # 猜一下返回值：字符串指针就尝试读出来
    try:
        s = e.jstring(ret)
        print("  ✓ 返回字符串：%s" % s)
    except Exception:
        print("  ✓ 返回（原始寄存器值）：%s" % ret)
    return 0


if __name__ == "__main__":
    sys.exit(main())
