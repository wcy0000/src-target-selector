#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cookie_lab.py —— 本地隔离实验台：实测浏览器在**跨站**场景下是否发送某个 Cookie。

设计
----
两个"站点"跑在本机不同回环 IP 上，天然是不同 registrable domain，因此是**真跨站**，
不需要改 /etc/hosts，也不碰任何外部网络：

    受害站  https://127.0.0.2:8443   （HTTPS；set-cookie / api 两个端点）
    攻击者  http://127.0.0.1:8907    （HTTP；页面用 credentials:'include' 跨站请求受害站）

受害站 /api 会按当前请求是否带 Cookie 返回结果，并回显 ACAO + ACAC:true，
让攻击者页面能读到响应；页面把结论写进 DOM，供 headless chrome --dump-dom 抓取。

四种 Cookie 属性组合：
    none_insecure   SameSite=None;             （缺 Secure —— 现代 Chrome 应直接拒收）
    none_secure     SameSite=None; Secure
    lax             SameSite=Lax
    strict          SameSite=Strict

用法
    python3 cookie_lab.py serve          # 前台起两个服务（调试用）
    python3 cookie_lab.py run            # 起服务 → 驱动 chrome → 打印矩阵 → 收工
"""
import argparse
import http.server
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time

VICTIM_HOST = "127.0.0.2"
VICTIM_PORT = 8443
ATTACK_PORT = 8907
CERT_DIR = os.path.join(tempfile.gettempdir(), "cookielab_cert")

COMBOS = ["none_insecure", "none_secure", "lax", "strict"]


def cookie_attr(combo):
    return {
        "none_insecure": "SameSite=None",
        "none_secure": "SameSite=None; Secure",
        "lax": "SameSite=Lax",
        "strict": "SameSite=Strict",
    }[combo]


# ────────────────────────── 受害站 ──────────────────────────
class VictimHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):      # 静音
        pass

    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def do_GET(self):
        if self.path.startswith("/set"):
            m = re.search(r'combo=([a-z_]+)', self.path)
            combo = m.group(1) if m else "none_secure"
            self.send_response(200)
            # 第一方（顶层导航）下发 Cookie。
            # ★ 必须带 Max-Age：会话 Cookie 不会落盘，跨 chrome 进程就丢了，
            #   会导致"设置成功但下一步永远读不到"的假阴性（我们踩过）。
            self.send_header("Set-Cookie",
                             "session=SECRET123; Path=/; Max-Age=3600; %s" % cookie_attr(combo))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.startswith("/whoami"):
            # 测量自校验：第一方请求是否带上了 Cookie？
            # 若这里就是 NOT_SENT，说明"设置"步骤失败，后面的跨站结论无效。
            raw = self.headers.get("Cookie") or ""
            seen = "session=SECRET123" in raw
            body = ("<div id=r>FIRSTPARTY:%s|%s</div>"
                    % ("COOKIE_SENT" if seen else "COOKIE_NOT_SENT", raw)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/api"):
            raw = self.headers.get("Cookie") or ""
            seen = "session=SECRET123" in raw
            body = json.dumps({"cookie_seen": seen, "cookie_header": raw},
                              ensure_ascii=False).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class AttackerHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/poc"):
            html = ("""<!doctype html><html><head><meta charset="utf-8"><title>poc</title></head>
<body><div id="r">PENDING</div>
<script>
fetch("https://%s:%d/api", {method:"GET", credentials:"include"})
  .then(r => r.json())
  .then(j => { document.getElementById("r").textContent =
      "RESULT:" + (j.cookie_seen ? "COOKIE_SENT" : "COOKIE_NOT_SENT") + "|" + j.cookie_header; })
  .catch(e => { document.getElementById("r").textContent = "RESULT:BLOCKED|" + e; });
</script></body></html>""" % (VICTIM_HOST, VICTIM_PORT)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def make_cert():
    os.makedirs(CERT_DIR, exist_ok=True)
    crt, key = os.path.join(CERT_DIR, "v.crt"), os.path.join(CERT_DIR, "v.key")
    if not (os.path.exists(crt) and os.path.exists(key)):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "2", "-keyout", key, "-out", crt,
                        "-subj", "/CN=%s" % VICTIM_HOST,
                        "-addext", "subjectAltName=IP:%s" % VICTIM_HOST],
                       check=True, capture_output=True)
    return crt, key


def start_servers():
    crt, key = make_cert()
    v = http.server.ThreadingHTTPServer((VICTIM_HOST, VICTIM_PORT), VictimHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    v.socket = ctx.wrap_socket(v.socket, server_side=True)
    a = http.server.ThreadingHTTPServer(("127.0.0.1", ATTACK_PORT), AttackerHandler)
    threading.Thread(target=v.serve_forever, daemon=True).start()
    threading.Thread(target=a.serve_forever, daemon=True).start()
    return v, a


# ────────────────────────── 驱动 Chrome ──────────────────────────
def chrome_version(chrome):
    try:
        out = subprocess.run([chrome, "--version"], capture_output=True, text=True, timeout=20)
        return out.stdout.strip() or out.stderr.strip()
    except Exception as e:
        return "unknown (%s)" % e


def chrome_dom(chrome, url, profile, extra=(), budget_ms=0):
    cmd = [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
           "--ignore-certificate-errors", "--user-data-dir=" + profile,
           "--disable-background-networking", "--no-first-run", "--no-default-browser-check"]
    cmd += list(extra)
    if budget_ms:
        cmd += ["--virtual-time-budget=%d" % budget_ms]
    cmd += ["--dump-dom", url]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return out.stdout
    except subprocess.TimeoutExpired:
        return ""


def parse_result(dom):
    m = re.search(r'RESULT:([^<|]*)\|([^<]*)', dom)
    if not m:
        return None, ""
    return m.group(1), m.group(2).strip()


def run_matrix(chrome, extra_features=(), label="default"):
    """对四种组合各跑一次「第一方下发 → 第一方自校验 → 跨站请求」。"""
    print("\n=== %s ===" % label)
    print("chrome: %s" % chrome_version(chrome))
    rows = []
    for combo in COMBOS:
        profile = tempfile.mkdtemp(prefix="cl_%s_" % combo)
        # 步骤 1：顶层导航到受害站，第一方下发 Cookie（带 Max-Age，会落盘）
        chrome_dom(chrome, "https://%s:%d/set?combo=%s" % (VICTIM_HOST, VICTIM_PORT, combo),
                   profile, extra=extra_features)
        # 步骤 2：测量自校验 —— 第一方请求必须带得上，否则本组结论无效
        dom_fp = chrome_dom(chrome, "https://%s:%d/whoami" % (VICTIM_HOST, VICTIM_PORT),
                            profile, extra=extra_features)
        m = re.search(r'FIRSTPARTY:([A-Z_]+)', dom_fp)
        firstparty = m.group(1) if m else "无结果"
        # 步骤 3：跨站请求（攻击者源是另一个回环 IP = 真跨站）
        dom = chrome_dom(chrome, "http://127.0.0.1:%d/poc.html" % ATTACK_PORT, profile,
                         extra=extra_features, budget_ms=6000)
        verdict, detail = parse_result(dom)
        if verdict is None:
            verdict = "无结果（页面未完成/被拦）"
        rows.append((combo, cookie_attr(combo), firstparty, verdict, detail[:60]))
        print("  %-14s %-24s 第一方=%-18s 跨站=%s" % (combo, cookie_attr(combo), firstparty, verdict))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["serve", "run"])
    ap.add_argument("--chrome", default="google-chrome-stable")
    a = ap.parse_args()

    if a.action == "serve":
        start_servers()
        print("受害站 https://%s:%d ／ 攻击者 http://127.0.0.1:%d" % (VICTIM_HOST, VICTIM_PORT, ATTACK_PORT))
        while True:
            time.sleep(3600)

    start_servers()
    time.sleep(0.6)
    print("实验台已起：受害站 https://%s:%d ／ 攻击者 http://127.0.0.1:%d"
          % (VICTIM_HOST, VICTIM_PORT, ATTACK_PORT))

    r1 = run_matrix(a.chrome, extra_features=("--disable-features=TrackingProtection3pcd",),
                    label="A. 关闭 Chrome 第三方 Cookie 封锁（隔离 SameSite 语义）")
    r2 = run_matrix(a.chrome, extra_features=(), label="B. Chrome 默认设置")
    print("\n" + json.dumps({"A_samesite_isolated": r1, "B_chrome_default": r2},
                            ensure_ascii=False, indent=2))


if __name__ == "__main__":
    sys.exit(main())
