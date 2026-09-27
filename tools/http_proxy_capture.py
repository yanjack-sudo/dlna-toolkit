#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
只记录、不解密的 HTTP 转发代理（用来抓媒体地址和明文上报 WebSocket）

它能干什么：
  · 转发并记录所有**明文 HTTP** 请求的完整 URL（媒体 m3u8/ts 等）
  · 解析 WebSocket 帧（客户端帧要解掩码），把 App 上报给服务端的播放地址抓出来
  · 对 **HTTPS 只记 CONNECT 隧道**，不解密（所以看不到 App 的 HTTPS 接口内容）

顺手修掉的两个坑：
  1) Host 头/URI 是 IPv6 字面量（如 http://[2408:...]:80/）时会解析异常 → 请求直接失败；
  2) 上游优先走 IPv6，本机 IPv6 不通就 15 秒超时 → 502。现在默认强制 IPv4。

用法：
  python tools/http_proxy_capture.py --port 8888 --verbose
  手机/模拟器：设置 → WLAN → 当前网络 → 代理 → 手动 → 主机 <本机局域网IP> 端口 8888
  投屏播放 30 秒 → 看 tools/captured_urls.txt
  结束后把代理设回「无」
"""
import argparse
import os
import socket
import re
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
FULL_LOG = os.path.join(HERE, "proxy_full.log")
URL_LOG = os.path.join(HERE, "captured_urls.txt")

# 什么算"值得记进 captured_urls.txt"：媒体流、WebSocket，以及按需扩展的关键字。
# 想抓别的，直接往这个正则里加域名/后缀即可。
MEDIA_RE = re.compile(r"\.(m3u8|ts|mp4|flv|f4v|m4s|mpd|aac|mp3|webm)(\?|$)|/ws(\?|$)", re.I)

_lock = threading.Lock()


def log(msg, media=False):
    line = "%s  %s" % (time.strftime("%H:%M:%S"), msg)
    with _lock:
        try:
            with open(FULL_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            if media:
                with open(URL_LOG, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception:
            pass
    print(line, flush=True)


def split_hostport(hosthdr, default_port):
    """安全解析 Host 头：支持 host:port、[v6]、[v6]:port、裸 v6"""
    h = (hosthdr or "").strip()
    if not h:
        return "", default_port
    if h.startswith("["):
        i = h.find("]")
        if i > 0:
            host = h[1:i]
            rest = h[i + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, default_port
            return host, default_port
    if h.count(":") == 1:
        host, _, p = h.partition(":")
        try:
            return host, int(p)
        except ValueError:
            return host, default_port
    return h, default_port


def connect(host, port, args):
    """默认强制 IPv4，避免 PC 侧 IPv6 不通导致超时"""
    last = None
    families = [socket.AF_INET] if args.ipv4_only else [socket.AF_INET, socket.AF_INET6]
    for fam in families:
        try:
            infos = socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM)
        except Exception as e:
            last = e
            continue
        for info in infos:
            try:
                s = socket.socket(info[0], info[1], info[2])
                s.settimeout(args.timeout)
                s.connect(info[4])
                s.settimeout(None)
                return s
            except Exception as e:
                last = e
                try:
                    s.close()
                except Exception:
                    pass
    raise last if last else OSError("connect failed")


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


class WsReader:
    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def need(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def ws_relay(src, dst, tag, unmask):
    """逐帧转发并记录文本负载（客户端帧有掩码，需 XOR 还原）"""
    r = WsReader(src)
    pending = b""
    try:
        while True:
            b0, b1 = r.need(2)
            fin = b0 & 0x80
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            ln = b1 & 0x7F
            ext = b""
            if ln == 126:
                ext = r.need(2)
                ln = int.from_bytes(ext, "big")
            elif ln == 127:
                ext = r.need(8)
                ln = int.from_bytes(ext, "big")
            key = r.need(4) if masked else b""
            payload = r.need(ln) if ln else b""
            if masked:
                payload = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
            if opcode == 0x8:
                break
            if opcode in (0x1, 0x0, 0x2):
                pending += payload
                if fin and opcode != 0x0 or (fin and opcode == 0x1):
                    txt = pending.decode("utf-8", "replace")
                    pending = b""
                    for m in re.finditer(r'https?://[^\s"\'\\,}]+', txt):
                        log("   [%s] 内含地址: %s" % (tag, m.group(0)), media=True)
                    if any(k in txt for k in ('"url"', "playURL", "currentPlayPath", "state", "high_id")):
                        log("   [%s] %s" % (tag, txt[:800]), media=True)
            # 原样转发（客户端帧保持掩码不变）
            raw = bytes([b0, b1]) + ext + key + (bytes(c ^ key[i % 4] for i, c in enumerate(payload)) if masked else payload)
            dst.sendall(raw)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


def handle(conn, addr, args):
    conn.settimeout(30)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < 131072:
            chunk = conn.recv(8192)
            if not chunk:
                return
            buf += chunk
    except Exception:
        conn.close()
        return

    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    if not lines or len(lines[0].split()) < 2:
        conn.close()
        return
    parts = lines[0].split()
    method, target = parts[0].upper(), parts[1]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    # ---------- HTTPS：只建隧道，不解密 ----------
    if method == "CONNECT":
        host, port = split_hostport(target, 443)
        try:
            up = connect(host, port, args)
        except Exception as e:
            log("[TUNNEL 失败] %s:%d  (%s)" % (host, port, e))
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
            conn.close()
            return
        try:
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception:
            conn.close()
            up.close()
            return
        log("[TUNNEL https] %s:%d" % (host, port))
        threading.Thread(target=pipe, args=(conn, up), daemon=True).start()
        pipe(up, conn)
        return

    # ---------- 明文 HTTP / WebSocket ----------
    if target.lower().startswith("http"):
        sp = urllib.parse.urlsplit(target)
        host, port = sp.hostname, sp.port or 80
        path = urllib.parse.urlunsplit(("", "", sp.path or "/", sp.query, ""))
        url = target
    else:
        host, port = split_hostport(headers.get("host", ""), 80)
        path = target
        url = "http://%s%s" % (headers.get("host", host), target)

    is_ws = headers.get("upgrade", "").lower() == "websocket"
    is_local = bool(re.match(r"^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", host or ""))
    media = bool(MEDIA_RE.search(url))
    if media or is_local or args.verbose:
        log("[%s] %s%s" % (method, url, "   <-- WebSocket" if is_ws else ""), media=media)

    try:
        up = connect(host, port, args)
    except Exception as e:
        log("[上游失败] %s:%s  %s" % (host, port, e), media=media)
        try:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
        conn.close()
        return

    fwd = [l for l in lines[1:] if not l.lower().startswith("proxy-connection")]
    fwd = [l for l in fwd if not l.lower().startswith("connection:")]
    fwd.append("Connection: close")
    req = ("%s %s %s" % (method, path, parts[2] if len(parts) > 2 else "HTTP/1.1")).encode() + b"\r\n" + \
          b"\r\n".join(l.encode("utf-8", "replace") for l in fwd) + b"\r\n\r\n"
    try:
        up.sendall(req + rest)
    except Exception as e:
        log("[转发失败] %s  %s" % (url, e))
        conn.close()
        up.close()
        return

    if is_ws:
        # 先转发 101 响应头，再按帧解析
        resp = b""
        try:
            while b"\r\n\r\n" not in resp and len(resp) < 65536:
                chunk = up.recv(4096)
                if not chunk:
                    break
                resp += chunk
            conn.sendall(resp)
            log("   [WS] 握手: %s" % resp.split(b"\r\n")[0].decode("utf-8", "replace"))
        except Exception:
            pass
        t_up = threading.Thread(target=ws_relay, args=(up, conn, "云->手机", False), daemon=True)
        t_dn = threading.Thread(target=ws_relay, args=(conn, up, "手机->云", True), daemon=True)
        t_dn.start()
        t_up.start()
        t_dn.join(timeout=args.ws_seconds)
        time.sleep(1)
        for s in (conn, up):
            try:
                s.close()
            except Exception:
                pass
        return

    threading.Thread(target=pipe, args=(conn, up), daemon=True).start()
    pipe(up, conn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--ws-seconds", type=int, default=120)
    ap.add_argument("--allow-ipv6", dest="ipv4_only", action="store_false", default=True,
                    help="默认只走 IPv4（PC 侧 IPv6 不通时避免超时）")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(128)
    log("=== 代理 v2 启动 %s:%d  (ipv4_only=%s) ===" % (args.bind, args.port, args.ipv4_only))
    log("媒体/WS 日志: %s" % URL_LOG)
    try:
        while True:
            c, a = srv.accept()
            threading.Thread(target=handle, args=(c, a, args), daemon=True).start()
    except KeyboardInterrupt:
        log("=== 停止 ===")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
