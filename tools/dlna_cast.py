#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 DLNA / UPnP 渲染器控制器。

扮演「发送端」给任意 UPnP AVTransport 渲染器发指令，不依赖任何具体 App。

用法:
    # 投一个地址并播放
    python dlna_cast.py --base "http://192.168.1.50:36657/upnp/dev/<UDN>/desc" \
                        --res "http://example.com/live.m3u8" --play

    # 只投不播
    python dlna_cast.py --base "<desc-url>" --res "<url>"

    # 控制 / 查询
    python dlna_cast.py --base "<desc-url>" --status
    python dlna_cast.py --base "<desc-url>" --pause
    python dlna_cast.py --base "<desc-url>" --stop

    # 用自己的 DIDL 元数据（有些渲染器要求带 metadata，有些要求为空）
    python dlna_cast.py --base "<desc-url>" --res "<url>" --metadata my_didl.xml
    python dlna_cast.py --base "<desc-url>" --res "<url>" --metadata ""

先用 ssdp_scan.py 找到 --base（设备描述 URL）。
"""
import argparse
import re
import sys
import time
import urllib.error
import urllib.request

NS = "urn:schemas-upnp-org:service:AVTransport:1"

# 标准 DIDL-Lite 模板。--metadata 可以覆盖成自己的文件，或传空串表示不带元数据。
DIDL_TMPL = """<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" \
xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">
  <item id="{item_id}" parentID="0" restricted="0">
    <upnp:class>object.item.videoItem</upnp:class>
    <dc:title>{title}</dc:title>
    <res protocolInfo="http-get:*:video/mp4:*">{res}</res>
  </item>
</DIDL-Lite>"""


def http_get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def soap(url, action, inner, timeout=20):
    body = ('<?xml version="1.0"?>\n'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>'
            % (action, NS, inner, action))
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST")
    req.add_header("Content-Type", 'text/xml; charset="utf-8"')
    req.add_header("SOAPACTION", '"%s#%s"' % (NS, action))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, repr(e)


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def find_avtransport(desc_url, desc):
    """从设备描述里找出 AVTransport 的 controlURL。"""
    pairs = re.findall(r"<serviceType>([^<]+)</serviceType>", desc)
    ctls = re.findall(r"<controlURL>([^<]+)</controlURL>", desc)
    root = desc_url.rsplit("/upnp/dev/", 1)[0] if "/upnp/dev/" in desc_url else desc_url
    found = []
    for i, st in enumerate(pairs):
        cu = ctls[i] if i < len(ctls) else ""
        full = cu if cu.startswith("http") else root.rstrip("/") + "/" + cu.lstrip("/")
        found.append((st, full))
    for st, full in found:
        if "AVTransport" in st:
            return full, found
    return None, found


def main():
    ap = argparse.ArgumentParser(description="通用 DLNA / UPnP 渲染器控制器")
    ap.add_argument("--base", required=True, help="设备描述 URL（.../upnp/dev/<UDN>/desc）")
    ap.add_argument("--res", default="", help="要投的媒体地址")
    ap.add_argument("--title", default="DLNA Test")
    ap.add_argument("--item-id", default="0")
    ap.add_argument("--metadata", default=None,
                    help="自定义 DIDL 文件路径；传空串表示不带元数据（默认用内置模板）")
    ap.add_argument("--play", action="store_true", help="投完后接着 Play")
    ap.add_argument("--pause", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args()

    try:
        desc = http_get(a.base)
    except Exception as e:
        print("取设备描述失败：%r" % e)
        return 1

    av_url, services = find_avtransport(a.base, desc)
    print("=== 服务与控制地址 ===")
    for st, full in services:
        print("  %-56s %s" % (st, full))
    if not av_url:
        print("!! 没找到 AVTransport 控制地址")
        return 1

    # 控制类动作
    if a.pause or a.stop or a.status:
        action = "Pause"
        if a.stop:
            action = "Stop"
        elif a.status:
            action = "GetTransportInfo"
        print("\n=== %s ===" % action)
        st, body = soap(av_url, action, "<InstanceID>0</InstanceID>")
        print("  HTTP %s\n  %s" % (st, body[:600]))
        return 0

    if not a.res:
        print("!! 需要 --res <媒体地址>（或使用 --pause/--stop/--status）")
        return 1

    # 组装元数据
    if a.metadata is None:
        didl = DIDL_TMPL.format(item_id=a.item_id, title=esc(a.title), res=esc(a.res))
    elif a.metadata == "":
        didl = ""
    else:
        didl = open(a.metadata, encoding="utf-8").read()

    print("\n=== SetAVTransportURI ===")
    st, body = soap(av_url, "SetAVTransportURI",
                    "<InstanceID>0</InstanceID><CurrentURI>%s</CurrentURI>"
                    "<CurrentURIMetaData>%s</CurrentURIMetaData>" % (esc(a.res), esc(didl)))
    print("  HTTP %s\n  %s" % (st, body[:400]))

    if a.play:
        time.sleep(1)
        print("\n=== Play ===")
        st, body = soap(av_url, "Play", "<InstanceID>0</InstanceID><Speed>1</Speed>")
        print("  HTTP %s\n  %s" % (st, body[:400]))

    print("\n提示：如果渲染器没反应，用 --status 查状态，或换一台渲染器对比，"
          "以判断是渲染器还是发送端的问题。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
