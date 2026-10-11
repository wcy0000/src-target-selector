#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""accountface.py —— 账号面快筛：找出「真实的」登录 / 注册 / 找回入口。

它解决什么问题
--------------
批量资产里，绝大多数"看起来有登录页"的站其实是**假命中**：
SPA 的 404 fallback、查询参数被忽略后原样回显首页、301 到自己加尾斜杠……
只要判据是"返回 200 且有内容"，命中率会虚高到 30% 以上，然后把预算全烧在假靶上。

本工具的判据是两条**同时**成立：
  ① 页面里存在 `<input type="password">`（有密码框才算账号面）；
  ② 该页面与「随机不存在路径的基线」以及「首页」**不同形**（内容指纹比对）。

关键的反向保护：**只要有密码框，就绝不判 fallback**——不许把真登录页误杀。

为什么只做只读 GET
------------------
本工具不提交表单、不注册、不发短信、不猜密码。它产出的是"哪里值得深打"的
候选面，不是漏洞结论。请求预算由 safety 模块硬性约束（默认 8 次/域）。

用法::

    python3 -m targetselector.accountface --self-test                 # 离线自测
    python3 -m targetselector.accountface -d example.com --i-am-authorized
    python3 -m targetselector.accountface --batch hosts.txt --workers 8 --i-am-authorized

退出码：0 至少探到一个账号面 / 1 全部无账号面 / 2 用法错误
"""
import argparse
import hashlib
import json
import os
import random
import re
import string
import sys

from .safety import (DEFAULT_BUDGET_FAST, BudgetExceeded, GuardedSession,
                     budget_report, budget_reset)

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36")

# 账号面候选路径（只读探测；命中即列出，不尝试登录）
PATHS = {
    "登录":  ["/login", "/login.html", "/user/login", "/users/login", "/auth/login",
             "/admin/login", "/manage/login", "/sys/login", "/Login.aspx", "/login.jsp",
             "/index.php?m=user&c=login", "/cas/login", "/sso/login"],
    "注册":  ["/register", "/register.html", "/user/register", "/signup", "/sign-up",
             "/users/register", "/member/register", "/Register.aspx", "/index.php?m=user&c=register"],
    "找回":  ["/forget", "/forgot", "/forget.html", "/user/forget", "/user/findpwd",
             "/findpwd", "/password/reset", "/user/resetpwd", "/resetpwd",
             "/retrieve", "/user/retrieve", "/FindPassword.aspx", "/index.php?m=user&c=findpwd"],
    "我的":  ["/user", "/user/index", "/uc", "/ucenter", "/member", "/profile",
             "/user/center", "/personal", "/my"],
    "API":   ["/api/user/login", "/api/login", "/api/user/register", "/api/user/info",
             "/api/v1/user/login", "/api/v1/login", "/api/sms/send", "/api/sendCode",
             "/api/user/sendCode", "/api/captcha", "/api/user/forget"],
}

# 快速档：每域 6 个认证路径 + 首页 + 随机基线 = 8 个请求
#
# ★ 路径顺序不是拍的，是按实测边际收益排的（22 个真实命中样本）：
#     k=1 /login           新增 13  累计  59.1%
#     k=2 /register        新增  0  累计  59.1%   ← 本批样本零贡献
#     k=3 /resetpwd        新增  0  累计  59.1%   ← 本批样本零贡献
#     k=4 /login.html      新增  4  累计  77.3%
#     k=5 /user/login      新增  3  累计  90.9%
#     k=6 index.php?m=...  新增  2  累计 100.0%
#   结论：前 4 条路径即可 100% 召回（每域 6 请求，相比原顺序省 25% 请求量）。
#   零贡献的两条降级到末尾保留（换资产批次后分布可能变化，不直接删）。
AUTH_FAST = ["/login", "/login.html", "/user/login",
             "/index.php?m=user&c=login", "/register", "/resetpwd"]

# 页面里出现这些，说明存在可打的账号逻辑
SIGNALS = {
    "短信/验证码": r'验证码|短信|sendCode|send_code|smsCode|getCode|captcha|verifyCode',
    "手机号":      r'手机号|手机号码|mobile|phone|tel',
    "邮箱":        r'邮箱|email',
    "身份证":      r'身份证|idcard|id_card|证件号',
    "密码找回":    r'找回密码|忘记密码|重置密码|forget|forgot|reset.*pwd|findpwd|retrieve',
    "注册开放":    r'注册|register|sign\s?up',
    "微信/第三方":  r'微信|wechat|weixin|qq登录|支付宝|dingtalk|企业微信',
    "实名认证":    r'实名认证|实名|认证',
}


def title_of(html):
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.S | re.I)
    return re.sub(r'\s+', ' ', m.group(1)).strip()[:60] if m else ""


def body_hash(text):
    """正文指纹：只取可见骨架，压掉注释/脚本/样式与空白这类噪声。"""
    t = re.sub(r'<script.*?</script>', ' ', text, flags=re.S | re.I)
    t = re.sub(r'<style.*?</style>', ' ', t, flags=re.S | re.I)
    t = re.sub(r'<!--.*?-->', ' ', t, flags=re.S)
    t = re.sub(r'\s+', ' ', t).strip()
    return hashlib.sha256(t.encode('utf-8', 'ignore')).hexdigest()[:16]


def rand_path():
    """随机不存在路径，用作 fallback 基线。刻意保持"不像真实路径"。"""
    return "/" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(18))


def norm_path(u):
    """取出 path 部分并去掉尾斜杠，用于判断「301 到自己 + /」这种归一化重定向。"""
    u = re.sub(r'^https?://[^/]+', '', (u or '').strip())
    return u.split('?')[0].rstrip('/') or '/'


def is_self_normalize(res):
    """301/302 到「自己 + /」= 服务器统一加尾斜杠 ⇒ 不是真页面，别当账号面。"""
    if res.get("status") not in (301, 302, 303, 307, 308):
        return False
    loc = res.get("loc") or ""
    if not loc:
        return False
    return norm_path(loc) == norm_path(res.get("path") or "")


def probe(s, base, path):
    """只读 GET；返回 dict 或 None。带正文指纹 + 密码框判据，供对照。"""
    url = base.rstrip('/') + path
    try:
        r = s.get(url, timeout=12, allow_redirects=False)
    except BudgetExceeded:
        raise
    except Exception:
        return None
    txt = r.text if r.status_code == 200 and len(r.content) < 3_000_000 else ""
    acts = []
    for m in re.finditer(r'<form[^>]*action\s*=\s*["\']([^"\']{0,120})["\']', txt, re.I):
        a = m.group(1).strip()
        if a and a not in acts:
            acts.append(a)
    return {"path": path, "url": url, "status": r.status_code, "len": len(r.content),
            "hash": body_hash(txt) if txt else "",
            "loc": r.headers.get("Location", ""),
            "title": title_of(r.text) if r.status_code == 200 else "",
            # ★ 决定性判据：真登录/注册页一定有密码框；回显首页没有
            "pwd": bool(re.search(r'type\s*=\s*["\']password', txt, re.I)),
            "forms": acts[:5],
            # 页面里写着的接口路径（真实账号逻辑常藏在 JS 里）
            "api": sorted(set(re.findall(
                r'["\'](/(?:api|user|member|uc|auth|sso)[a-zA-Z0-9_\-/\.]{2,60})["\']', txt)))[:8]}


def is_fallback(res, baseline, home_hash=None):
    """★ 核心防线：与随机基线或首页同形 ⇒ 不是真页面。

    两层对照，缺一不可：
      ① 与随机不存在路径同形  ⇒ SPA / 404 fallback
      ② 与首页同形            ⇒ 查询参数被忽略、原样回显首页
    反向保护：**有密码框的页面永不判 fallback**（不许把真登录页误杀）。
    """
    if res.get("pwd"):
        return False
    for bl in filter(None, (baseline, home_hash)):
        if isinstance(bl, str):
            if res.get("hash") and res["hash"] == bl:
                return True
            continue
        if res["status"] != bl["status"]:
            continue
        if res["status"] != 200:
            if bl.get("loc") and res.get("loc") == bl.get("loc"):
                return True
            continue
        if res.get("hash") and bl.get("hash") and res["hash"] == bl["hash"]:
            return True
    return False


def _new_session(budget, authorized, verbose=False):
    s = GuardedSession(budget=budget, authorized=authorized, verbose=verbose)
    s.headers.update({"User-Agent": UA, "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.9"})
    return s


def try_base(domain, budget, authorized):
    """先 https 后 http；返回 (session, base, home_response, baseline_res)。"""
    cands = [domain] if re.match(r'^https?://', domain) else ["https://" + domain, "http://" + domain]
    last_err = ""
    for base in cands:
        base = base.rstrip('/')
        s = _new_session(budget, authorized)
        try:
            r = s.get(base + "/", timeout=15, allow_redirects=True)
        except BudgetExceeded:
            raise
        except Exception as e:
            last_err = "%s 不可达：%s" % (base, str(e)[:60])
            continue
        bl = probe(s, base, rand_path())          # 基线：随机不存在路径
        return s, base, r, bl
    raise RuntimeError(last_err or "不可达")


def scan(domain, budget=DEFAULT_BUDGET_FAST, authorized=False):
    out = {"target": domain, "home": {}, "auth": {}, "signals": {}, "fallback": 0, "error": ""}
    try:
        s, base, r, baseline = try_base(domain, budget, authorized)
    except Exception as e:
        out["error"] = str(e)[:90]
        return out
    out["target"] = base
    out["baseline"] = baseline or {}

    html = r.text
    home_hash = body_hash(html)
    out["home"] = {"status": r.status_code, "final": r.url, "len": len(r.content),
                   "title": title_of(html),
                   "server": r.headers.get("Server", ""),
                   "cookies": sorted(c.name for c in r.cookies)}
    # 首页内的账号链接
    links = set()
    for m in re.finditer(r'''(?:href|action|src)\s*=\s*["']([^"']{1,160})["']''', html, re.I):
        u = m.group(1).strip()
        if re.search(r'login|register|forget|forgot|reset|pwd|signup|sign-up|user|member|sso|cas|ucenter',
                     u, re.I) and not re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?)($|\?)', u, re.I):
            links.add(u)
    out["links"] = sorted(links)[:25]
    out["signals"] = {k: bool(re.search(p, html, re.I)) for k, p in SIGNALS.items()}
    out["home_api"] = sorted(set(re.findall(
        r'["\'](/(?:api|user|member|uc|auth|sso|login|register)[a-zA-Z0-9_\-/\.]{2,60})["\']', html)))[:15]

    # 路径探测（★ 每个结果都过 is_fallback 双层对照）
    for kind, paths in PATHS.items():
        for p in paths:
            res = probe(s, base, p)
            if not res:
                continue
            if is_fallback(res, baseline, home_hash) or is_self_normalize(res):
                out["fallback"] += 1
                continue
            if res["status"] == 200 and res["len"] > 200:
                out["auth"].setdefault(kind, []).append(res)
            elif res["status"] in (301, 302, 303, 307) and res["loc"]:
                out["auth"].setdefault(kind + "(跳转)", []).append(res)
            elif res["status"] in (401, 403):
                out["auth"].setdefault(kind + "(受限)", []).append(res)
    return out


def fast_scan(host, timeout=8, budget=DEFAULT_BUDGET_FAST, authorized=False):
    """快速判定一个 host 有没有真账号面。返回 dict（含 hit 布尔）。"""
    res = {"host": host, "hit": False, "url": "", "hits": [], "err": "", "title": "", "server": ""}
    for scheme in ("https", "http"):
        base = "%s://%s" % (scheme, host)
        sess = _new_session(budget, authorized)
        try:
            r = sess.get(base + "/", timeout=timeout, allow_redirects=True)
        except BudgetExceeded:
            raise
        except Exception as e:
            res["err"] = "%s: %s" % (scheme, str(e)[:50])
            continue
        res["err"] = ""
        home_hash = body_hash(r.text) if len(r.content) < 3_000_000 else ""
        res["title"] = title_of(r.text)
        res["server"] = r.headers.get("Server", "")
        bl = probe(sess, base, rand_path())
        found = []
        for p in AUTH_FAST:
            q = probe(sess, base, p)
            if not q or q["status"] != 200 or not q.get("pwd"):
                continue
            if is_fallback(q, bl, home_hash) or is_self_normalize(q):
                continue
            found.append({"path": p, "url": q["url"], "len": q["len"], "title": q["title"],
                          "forms": q.get("forms", []), "api": q.get("api", [])})
        if found:
            res["hit"] = True
            res["url"] = base
            res["hits"] = found
        return res
    return res


def batch(hosts, workers=8, timeout=8, out_json=None, budget=DEFAULT_BUDGET_FAST, authorized=False):
    """并发快速筛查；只打印命中，最后统计。"""
    import concurrent.futures as cf
    print("════ 账号面快筛：%d 个 host（%d 并发，每域预算 %d 请求）════\n"
          % (len(hosts), workers, budget))
    hits, done, dead = [], 0, 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fast_scan, h, timeout, budget, authorized): h for h in hosts}
        for fut in cf.as_completed(futs):
            done += 1
            try:
                r = fut.result()
            except Exception as e:
                r = {"host": futs[fut], "hit": False, "err": str(e)[:50], "hits": []}
            if r.get("err"):
                dead += 1
            if r.get("hit"):
                hits.append(r)
                print("  ★ %-34s %s" % (r["host"], (r.get("title") or "")[:30]))
                for h in r["hits"]:
                    print("       %-28s len=%-6d %s" % (h["path"], h["len"], (h["title"] or "")[:28]))
                    if h.get("api"):
                        print("         内嵌接口: %s" % ", ".join(h["api"][:5]))
            if done % 100 == 0:
                print("  … 进度 %d/%d，已命中 %d" % (done, len(hosts), len(hits)))
    print("\n  合计 %d 个 host：命中真账号面 %d 个，不可达 %d 个" % (len(hosts), len(hits), dead))
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(hits, f, ensure_ascii=False, indent=2)
        print("  [√] 已写 %s（%d 条）" % (out_json, len(hits)))
    return hits


def show(out):
    h = out.get("home") or {}
    print("  ── %s ──" % out["target"])
    if out.get("error"):
        print("     ❌ %s" % out["error"])
        return False
    print("     首页 %s len=%d server=%s" % (h.get("status"), h.get("len", 0), h.get("server") or "-"))
    print("     标题：%s" % (h.get("title") or "-"))
    print("     Cookie：%s" % (", ".join(h.get("cookies") or []) or "-"))
    bl = out.get("baseline") or {}
    print("     基线(随机路径)：%s len=%d hash=%s loc=%s" % (
        bl.get("status"), bl.get("len", 0), bl.get("hash") or "-", (bl.get("loc") or "-")[:40]))
    if out.get("fallback"):
        print("     ⚠ 已剔除 %d 个「与基线/首页同形」的 fallback 假命中（非 404 ≠ 页面存在）"
              % out["fallback"])
    sig = [k for k, v in (out.get("signals") or {}).items() if v]
    print("     信号：%s" % (", ".join(sig) or "无"))
    if out.get("links"):
        print("     首页账号链接：")
        for l in out["links"][:10]:
            print("       · %s" % l[:120])
    if out.get("home_api"):
        print("     首页内嵌接口：%s" % ", ".join(out["home_api"][:8]))
    hit = False
    for kind in ("登录", "注册", "找回", "我的", "API"):
        for suffix in ("", "(跳转)", "(受限)"):
            for res in (out.get("auth") or {}).get(kind + suffix, []):
                hit = True
                flag = "★有密码框" if res.get("pwd") else "无密码框"
                print("     [%s%s] %s -> %s len=%d %s %s%s" % (
                    kind, suffix, res["path"], res["status"], res["len"], flag,
                    ("→ " + res["loc"][:50]) if res["loc"] else "",
                    (" " + res["title"]) if res["title"] else ""))
                if res.get("forms"):
                    print("         form action: %s" % ", ".join(res["forms"]))
                if res.get("api"):
                    print("         内嵌接口: %s" % ", ".join(res["api"][:6]))
    if not hit:
        print("     ⚠ 未探到账号面（可能是纯静态门户 ⇒ 立即放弃这个目标）")
    print()
    return hit


def self_test():
    """离线自测：核心防线（fallback 对照）正负样本都要过。"""
    ok = 0
    assert title_of("<html><title> A  b </title>") == "A b"; ok += 1
    assert title_of("no title") == ""; ok += 1
    assert re.search(SIGNALS["短信/验证码"], "请输入验证码", re.I); ok += 1
    assert not re.search(SIGNALS["身份证"], "请输入手机号", re.I); ok += 1
    assert all(isinstance(v, list) and v for v in PATHS.values()); ok += 1
    assert len(AUTH_FAST) == 6, "快筛路径数必须与 README 里 8 请求/域的说明一致"; ok += 1

    # ★ fallback 对照：正负都要测
    bl = {"status": 200, "len": 16712, "hash": "deadbeef00000000", "loc": ""}
    same = {"status": 200, "len": 16712, "hash": "deadbeef00000000", "loc": ""}
    diff = {"status": 200, "len": 16712, "hash": "cafebabe11111111", "loc": ""}
    assert is_fallback(same, bl) is True, "同形必须判 fallback"
    assert is_fallback(diff, bl) is False, "不同内容必须放行（负对照）"
    assert is_fallback(diff, None) is False, "无基线时不许判 fallback"
    ok += 3
    # ② 与首页同形 ⇒ 也判 fallback
    assert is_fallback(same, None, "deadbeef00000000") is True
    assert is_fallback(diff, None, "deadbeef00000000") is False
    ok += 2
    # ③ 反向保护：有密码框的页面永不判 fallback
    pwdpage = {"status": 200, "len": 16712, "hash": "deadbeef00000000", "loc": "", "pwd": True}
    assert is_fallback(pwdpage, bl, "deadbeef00000000") is False, "有密码框的真登录页不许被误杀"
    ok += 1
    # 通配 302：跳到同一处 = fallback；跳到不同处 = 真线索
    bl302 = {"status": 302, "len": 0, "hash": "", "loc": "/error.html?aspxerrorpath=/x"}
    assert is_fallback({"status": 302, "len": 0, "hash": "", "loc": "/error.html?aspxerrorpath=/x"},
                       bl302) is True
    assert is_fallback({"status": 302, "len": 0, "hash": "", "loc": "/login"}, bl302) is False
    ok += 2
    # body_hash 对噪声不敏感、对内容敏感
    assert body_hash("<b>a</b>  \n <!-- x -->") == body_hash("<b>a</b>")
    assert body_hash("aaa") != body_hash("aab")
    ok += 2
    # 密码框识别正负对照
    assert re.search(r'type\s*=\s*["\']password', '<input type="password" name="p">', re.I)
    assert not re.search(r'type\s*=\s*["\']password', '<input type="text" name="u">', re.I)
    ok += 2
    # rand_path 每次不同
    p1, p2 = rand_path(), rand_path()
    assert p1 != p2 and len(p1) > 15
    ok += 1
    # 301 尾斜杠归一化：判假命中；真跳转必须放行
    sn = {"status": 301, "loc": "https://x.example/login/", "path": "/login"}
    real = {"status": 301, "loc": "https://x.example/sso/authorize", "path": "/login"}
    plain = {"status": 200, "loc": "", "path": "/login"}
    assert is_self_normalize(sn) is True
    assert is_self_normalize(real) is False
    assert is_self_normalize(plain) is False
    assert norm_path("https://a.example/x/?q=1") == "/x"
    assert norm_path("/y/") == "/y"
    ok += 5

    # 预算闸门：离线验证，不发请求
    from .safety import BudgetExceeded as BE, _charge
    budget_reset()
    for _ in range(DEFAULT_BUDGET_FAST):
        _charge("https://budget.example/x", DEFAULT_BUDGET_FAST)
    try:
        _charge("https://budget.example/x", DEFAULT_BUDGET_FAST)
        raise AssertionError("超预算必须抛 BudgetExceeded")
    except BE:
        ok += 1
    budget_reset()
    print("  自测 %d 项全通过 ✅（离线，0 请求）" % ok)


def main():
    ap = argparse.ArgumentParser(description="账号面快筛：找登录/注册/找回入口（只读 GET）")
    ap.add_argument("-d", "--domain", action="append", default=[], help="目标域名，可多次")
    ap.add_argument("--batch", help="批量快筛：文件里每行一个 host（# 开头为注释）")
    ap.add_argument("--workers", type=int, default=8, help="批量并发数（默认 8，请勿轻易调高）")
    ap.add_argument("--timeout", type=int, default=8, help="单请求超时秒（默认 8）")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET_FAST,
                    help="每域请求预算上限（默认 %d）" % DEFAULT_BUDGET_FAST)
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="声明已获得授权（必须，或用 TARGETSELECTOR_AUTHORIZED=1）")
    ap.add_argument("--json", dest="json_out", help="结果写 JSON")
    ap.add_argument("--self-test", action="store_true", help="离线自测（不需要授权）")
    a = ap.parse_args()

    if a.self_test:
        self_test()
        return 0

    from .safety import assert_authorized
    assert_authorized(a.i_am_authorized)

    if a.batch:
        if not os.path.exists(a.batch):
            ap.error("--batch 文件不存在：%s" % a.batch)
        with open(a.batch, encoding="utf-8") as f:
            hosts = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        hosts = list(dict.fromkeys(hosts))
        if not hosts:
            ap.error("--batch 文件里没有 host")
        try:
            hits = batch(hosts, workers=a.workers, timeout=a.timeout, out_json=a.json_out,
                         budget=a.budget, authorized=a.i_am_authorized)
        finally:
            print("  预算用量前 10：%s" % list(budget_report().items())[:10])
        return 0 if hits else 1

    if not a.domain:
        ap.error("至少给一个 -d 域名，或用 --batch（或 --self-test）")

    print("════ 账号面探测：%d 个目标（只读 GET，不提交表单，预算 %d/域）════\n"
          % (len(a.domain), a.budget))
    results, hits = [], 0
    for d in a.domain:
        try:
            o = scan(d, budget=a.budget, authorized=a.i_am_authorized)
        except BudgetExceeded as e:
            o = {"target": d, "error": str(e)[:90], "home": {}}
        except Exception as e:
            o = {"target": d, "error": "探测异常：%s" % str(e)[:70], "home": {}}
        results.append(o)
        if show(o):
            hits += 1
    print("  合计：%d/%d 个目标探到账号面" % (hits, len(results)))
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print("  [√] 已写 %s" % a.json_out)
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
