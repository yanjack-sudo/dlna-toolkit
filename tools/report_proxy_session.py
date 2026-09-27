#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 http_proxy_capture.py 的日志汇总成一份会话报告。

用法:
    python report_proxy_session.py [日志路径]        # 默认 proxy_full.log
    python report_proxy_session.py --top 30          # 多列一些主机
"""
import argparse
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.join(HERE, "proxy_full.log")

URL_RE = re.compile(r"https?://([A-Za-z0-9\.\-]+)")
TUNNEL_RE = re.compile(r"\[TUNNEL https\]\s+([A-Za-z0-9\.\-]+):(\d+)")
METHOD_RE = re.compile(r"\[([A-Z]+)\]\s+(https?://\S+)")
LOCAL_RE = re.compile(r"^https?://(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG)
    ap.add_argument("--top", type=int, default=20)
    a = ap.parse_args()

    if not os.path.exists(a.log):
        print("没有日志文件：%s" % a.log)
        return 1

    lines = open(a.log, encoding="utf-8", errors="replace").read().splitlines()

    # 只看最后一次启动之后的记录
    start = 0
    for i, ln in enumerate(lines):
        if "代理" in ln and "启动" in ln:
            start = i
    sess = lines[start:]
    print("=== 本次会话 %d 行 ===" % len(sess))
    if sess:
        print("起始：%s\n" % sess[0])

    hosts = collections.Counter()
    tunnels = collections.Counter()
    local = collections.Counter()
    methods = collections.Counter()

    for ln in sess:
        for m in URL_RE.finditer(ln):
            hosts[m.group(1)] += 1
        m = TUNNEL_RE.search(ln)
        if m:
            tunnels[m.group(1)] += 1
        m = METHOD_RE.search(ln)
        if m:
            methods[m.group(1).upper()] += 1
            if LOCAL_RE.match(m.group(2)):
                local[URL_RE.search(m.group(2)).group(1)] += 1

    print("--- 请求方法 ---")
    for k, v in methods.most_common():
        print("  %-8s %d" % (k, v))
    if not methods:
        print("  （无明文请求）")

    print("\n--- HTTPS 隧道（内容不可见）---")
    if tunnels:
        for h, n in tunnels.most_common(a.top):
            print("  %-40s %d 次" % (h, n))
    else:
        print("  （无）")

    print("\n--- 明文请求主机 ---")
    if hosts:
        for h, n in hosts.most_common(a.top):
            print("  %-40s %d 次" % (h, n))
    else:
        print("  （无）")

    print("\n--- 局域网内被访问的设备 ---")
    if local:
        for h, n in local.most_common(a.top):
            print("  %-40s %d 次" % (h, n))
    else:
        print("  （无）")

    print("\n--- 媒体类地址 ---")
    media = [ln for ln in sess if re.search(r"\.(m3u8|ts|mp4|flv|m4s|mpd|aac)(\?|$)", ln)]
    for ln in media[:a.top]:
        print("  " + ln[:200])
    if not media:
        print("  （无）")

    print("\n提示：想确认「设备有没有走代理」，看上面第一段——如果连一个请求都没有，"
          "说明该 App 忽略了系统代理（很多播放器会）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
