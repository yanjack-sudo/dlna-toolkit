#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSDP 扫描（组播 + 全网段单播），把局域网里所有助手/DLNA 渲染器的自报身份打出来。

单播：直接往每个 IP 的 1900 端口发 M-SEARCH，Cling 绑定 0.0.0.0:1900 时会回单播响应，
      可以绕开"本机组播出不去"的问题。
"""
import re
import socket
import sys
import threading
import time
import urllib.request

FIELDS = ["friendlyName", "manufacturer", "modelDescription", "modelName",
          "modelNumber", "UDN", "deviceType", "X_DLNADOC"]


def build_msearch(st):
    return ("M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: %s\r\n\r\n" % st).encode()


def parse(txt, fromip):
    def g(p):
        m = re.search(r"(?im)^%s:\s*(\S.*)$" % p, txt)
        return m.group(1).strip() if m else ""
    return {"from": fromip, "location": g("LOCATION"), "st": g("ST"),
            "server": g("SERVER"), "usn": g("USN")}


def collect_unicast(ips, st, timeout=2.0, out=None, lock=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(0.3)
    msg = build_msearch(st)
    for ip in ips:
        try:
            s.sendto(msg, (ip, 1900))
        except Exception:
            pass
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break
        rec = parse(data.decode("utf-8", "replace"), addr[0])
        with lock:
            out[(addr[0], rec["usn"] or rec["location"])] = rec
    s.close()


def local_ipv4s():
    """列出本机所有非回环 IPv4（用来决定组播从哪些网卡发、单播扫哪些网段）。"""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    if not ips:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("223.5.5.5", 80))
            ips.append(s.getsockname()[0])
        except Exception:
            pass
        finally:
            s.close()
    return ips


def main():
    mine = local_ipv4s()
    default_prefixes = []
    for ip in mine:
        pfx = ip.rsplit(".", 1)[0] + "."
        if pfx not in default_prefixes:
            default_prefixes.append(pfx)
    prefixes = sys.argv[1:] or default_prefixes
    out, lock = {}, threading.Lock()
    print("本机地址: %s" % (", ".join(mine) or "探测失败"))
    print("扫描网段: %s\n" % (", ".join(prefixes) or "无"))

    # 1) 组播（本机每个网卡都试一遍；有些环境组播出不去，所以下面还有单播兜底）
    for ifip in mine:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ifip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(2)
            for st in ("urn:schemas-upnp-org:device:MediaRenderer:1", "ssdp:all"):
                try:
                    s.sendto(build_msearch(st), ("239.255.255.250", 1900))
                except Exception as e:
                    print("组播(if=%s) 发送失败: %r" % (ifip, e))
            t0 = time.time()
            while time.time() - t0 < 2:
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    break
                rec = parse(data.decode("utf-8", "replace"), addr[0])
                out[(addr[0], rec["usn"] or rec["location"])] = rec
            s.close()
        except Exception as e:
            print("组播(if=%s) 异常: %r" % (ifip, e))

    # 2) 全网段单播
    for pfx in prefixes:
        ips = ["%s%d" % (pfx, i) for i in range(1, 255)]
        for st in ("urn:schemas-upnp-org:device:MediaRenderer:1", "ssdp:all"):
            th = threading.Thread(target=collect_unicast, args=(ips, st, 2.5, out, lock))
            th.start()
            th.join()

    print("=== 共发现 %d 个响应端点 ===" % len(out))
    seen = set()
    for k, v in sorted(out.items(), key=lambda kv: kv[1]["from"]):
        print("\n  from=%-16s st=%s" % (v["from"], v["st"]))
        print("   SERVER: %s" % v["server"])
        print("   USN   : %s" % v["usn"])
        print("   LOC   : %s" % v["location"])
        if not v["location"] or v["location"] in seen:
            continue
        seen.add(v["location"])
        try:
            xml = urllib.request.urlopen(v["location"], timeout=5).read().decode("utf-8", "replace")
        except Exception as e:
            print("   描述取不到: %r" % e)
            continue
        for f in FIELDS:
            m = re.search(r"<%s>([^<]*)</%s>" % (f, f), xml)
            if m:
                print("   %-18s = %s" % (f, m.group(1)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
