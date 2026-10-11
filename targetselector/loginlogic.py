#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""loginlogic.py —— 登录逻辑探测：判断登录接口是否**真的校验口令**。

它解决什么问题
--------------
"认证绕过"最常见的实现缺陷不是加密被破，而是**登录逻辑本身没把关**：
服务端先建会话、再校验口令，或者口令参数压根没参与比对。

安全边界（决定了本脚本能做什么）
--------------------------------
**全程只用「不存在的用户名」**，绝不提交任何真实账号，也不猜密码。

理由很直接：若用真实用户名去测"空密码能否登录"，一旦命中就是**真的登录进他人账号**——
那是不可逆的影响。用不存在的用户名同样能判定缺陷：

  · 正常实现：无论口令是什么，都回「用户不存在」/`no_such_username`
  · 缺陷实现：**先建会话再校验口令** ⇒ 失败也会下发新的认证 Cookie / 返回 token

三条判据
--------
① 登录失败前后 **Cookie 集合发生变化**（多出非匿名 Cookie）→ 先建会话型缺陷
② 用"失败登录"换来的会话访问受保护页，**返回内容与纯匿名不同** → 鉴权与会话脱钩
③ **空口令 与 错口令 的响应显著不同** → 口令可能未参与判定

其中③的实战价值最高：典型坏味道是"任意口令都返回成功"。
注意：判据只产出**可疑**，不产出"漏洞结论"——可疑目标仍需人工用自注册的两个
账号做 A/B 对照，并按所属平台的口径取证。本工具不做那一步。

用法::

    python3 -m targetselector.loginlogic --self-test                      # 离线自测
    python3 -m targetselector.loginlogic -d example.com --i-am-authorized
    python3 -m targetselector.loginlogic --batch hosts.txt --i-am-authorized

退出码：0 有可疑目标 / 1 全部正常 / 2 用法错误
"""
import argparse
import json
import os
import random
import re
import string
import sys

from .safety import (DEFAULT_BUDGET_DEEP, BudgetExceeded, GuardedSession,
                     assert_authorized, budget_report, budget_reset)

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36")

# 常见登录入口（先在页面里找 form，找不到再按这张表猜）
LOGIN_PATHS = ["/login", "/login.html", "/user/login", "/api/login", "/admin/login",
               "/u.php/member-login", "/index.php?m=user&c=login", "/member/login"]

# 登录失败该出现的字眼（正常实现）
FAIL_WORDS = ("不存在", "错误", "失败", "不正确", "invalid", "wrong", "error", "fail",
              "no_such", "denied", "帐号或密码", "账号或密码", "请输入")
# 登录成功才会出现的字眼
SUCCESS_WORDS = ("token", "access_token", "登录成功", "success\":true", "\"code\":0",
                 "\"code\":200", "dashboard", "欢迎您", "welcome", "退出登录", "logout")
# 匿名 Cookie（出现这些说明还是游客，不算"新会话"）
ANON_COOKIE = re.compile(r'^(PHPSESSID|ASP\.NET_SessionId|JSESSIONID|ci_session|'
                         r'laravel_session|acw_tc|sl-session|server_session|__RequestVerificationToken|'
                         r'XSRF|csrf|Hm_|HMACCOUNT|_ga|_gid|BIGipServer|route|think_|Ss?ession)',
                         re.I)

# 受保护页候选（用来做"失败会话 vs 匿名"对照）
PROTECTED_HINT = ["/index.php/core/member-info", "/api/user/info", "/user/info",
                  "/member/info", "/api/me", "/profile", "/ucenter", "/user/center"]

# 探测用的用户名前缀（不存在，仅用于判定）
PROBE_PREFIX = "aprobe"


def rand_user():
    """生成一个必定不存在的用户名。"""
    return PROBE_PREFIX + "".join(random.choice(string.ascii_lowercase) for _ in range(10))


def title_of(h):
    m = re.search(r'<title[^>]*>(.*?)</title>', h, re.S | re.I)
    return re.sub(r'\s+', ' ', m.group(1)).strip()[:50] if m else ""


def find_login(sess, base):
    """找登录表单：返回 (action_url, method, field_names, path)。找不到返回 (None,None,[],None)。"""
    for p in LOGIN_PATHS:
        try:
            r = sess.get(base + p, timeout=12, allow_redirects=False)
        except BudgetExceeded:
            raise
        except Exception:
            continue
        if r.status_code != 200 or len(r.content) < 200:
            continue
        for m in re.finditer(r'<form[^>]*>(.*?)</form>', r.text, re.S | re.I):
            form = m.group(0)
            if not re.search(r'type\s*=\s*["\']password', form, re.I):
                continue
            act = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form, re.I)
            meth = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form, re.I)
            names = re.findall(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\']', form, re.I)
            url = act.group(1) if act and act.group(1) else p
            if url.startswith("/"):
                url = base + url
            elif not url.startswith("http"):
                url = base + "/" + url.lstrip("./")
            return url, (meth.group(1).upper() if meth else "POST"), names, p
    return None, None, [], None


def cookie_names(sess):
    return sorted(c.name for c in sess.cookies)


def looks_like_new_auth(before, after):
    """登录失败后是否多出「非匿名」Cookie —— 先建会话型缺陷的信号。"""
    return [c for c in after if c not in before and not ANON_COOKIE.match(c)]


def try_login(sess, url, method, fields, username, password):
    """提交一次登录（用户名固定为不存在的），返回 (resp, err)。"""
    ufield = next((f for f in fields if re.search(r'user|account|name|email|mobile|phone|login', f, re.I)), None)
    pfield = next((f for f in fields if re.search(r'pass|pwd|secret', f, re.I)), None)
    if not ufield or not pfield:
        ufield, pfield = "username", "password"      # 表单字段可能是 JS 拼的，退回常见组合
    data = {}
    for f in fields:
        if f.lower() in ("submit", "dosubmit", "login", "button"):
            data[f] = "登录"
        elif f.lower() in ("forward", "redirect", "url", "next"):
            data[f] = "/"
        else:
            data[f] = ""
    data[ufield] = username
    data[pfield] = password
    hdr = {"User-Agent": UA, "X-Requested-With": "XMLHttpRequest"}
    try:
        if method == "GET":
            r = sess.get(url, params=data, timeout=15, allow_redirects=False, headers=hdr)
        else:
            r = sess.post(url, data=data, timeout=15, allow_redirects=False, headers=hdr)
    except BudgetExceeded:
        raise
    except Exception as e:
        return None, str(e)[:60]
    return r, ""


def _new_session(budget, authorized):
    s = GuardedSession(budget=budget, authorized=authorized)
    s.headers.update({"User-Agent": UA, "Accept-Language": "zh-CN,zh;q=0.9"})
    return s


def scan(host, budget=DEFAULT_BUDGET_DEEP, authorized=False):
    base = host if host.startswith("http") else "https://" + host
    out = {"host": host, "login_url": "", "status": "未知", "notes": [], "suspect": False}
    s = _new_session(budget, authorized)
    try:
        s.get(base + "/", timeout=12, allow_redirects=True)
    except BudgetExceeded:
        raise
    except Exception as e:
        out["status"] = "不可达"
        out["notes"].append(str(e)[:60])
        return out

    url, method, fields, path = find_login(s, base)
    if not url:
        out["status"] = "未找到登录表单"
        return out
    out["login_url"] = url
    out["fields"] = fields

    user = rand_user()                     # ★ 全程只用不存在的用户名
    c0 = cookie_names(s)

    # R1 空口令 / R2 错口令 —— 同一个不存在的用户名
    r1, e1 = try_login(s, url, method, fields, user, "")
    c1 = cookie_names(s)
    if r1 is None:
        out["status"] = "登录请求失败"
        out["notes"].append(e1)
        return out
    r2, e2 = try_login(s, url, method, fields, user, "WrongPass_" + rand_user())
    c2 = cookie_names(s)
    if r2 is None:
        out["status"] = "登录请求失败"
        out["notes"].append(e2)
        return out

    b1, b2 = r1.text[:2000], r2.text[:2000]

    # 判据① 失败后多出非匿名 Cookie
    n1 = looks_like_new_auth(c0, c1)
    newck = n1 + [c for c in looks_like_new_auth(c0, c2) if c not in n1]
    if newck:
        out["suspect"] = True
        out["notes"].append("登录失败后下发非匿名 Cookie：%s" % newck)

    # 判据③ 空口令 vs 错口令 响应显著不同
    if b1 != b2:
        d1 = bool([w for w in SUCCESS_WORDS if w.lower() in b1.lower()])
        d2 = bool([w for w in SUCCESS_WORDS if w.lower() in b2.lower()])
        if d1 and not d2:
            out["suspect"] = True
            out["notes"].append("空口令像成功、错口令像失败（口令可能未参与判定）")
        elif abs(len(b1) - len(b2)) > 200 or r1.status_code != r2.status_code:
            out["notes"].append("空/错口令响应不同（%d vs %d 字节，状态 %s vs %s）"
                                % (len(b1), len(b2), r1.status_code, r2.status_code))
    else:
        out["notes"].append("空/错口令响应完全相同（正常）")

    # 判据② 失败登录后的会话能否访问受保护页（与纯匿名对照）
    anon = _new_session(budget, authorized)
    for pp in PROTECTED_HINT:
        try:
            ra = anon.get(base + pp, timeout=10, allow_redirects=False)
            rb = s.get(base + pp, timeout=10, allow_redirects=False)
            if (ra.status_code == 200 and rb.status_code == 200 and ra.text != rb.text
                    and len(rb.content) > 60 and "access_denied" not in rb.text[:200].lower()):
                out["suspect"] = True
                out["notes"].append("失败登录后的会话访问 %s 得到与匿名不同的内容（%d vs %d 字节）"
                                    % (pp, len(ra.content), len(rb.content)))
                break
        except BudgetExceeded:
            raise
        except Exception:
            continue

    if bool([w for w in SUCCESS_WORDS if w.lower() in b2.lower()]):
        out["suspect"] = True
        out["notes"].append("错口令也出现成功字样")

    if any(w.lower() in b1.lower() or w.lower() in b2.lower() for w in FAIL_WORDS):
        out["notes"].append("响应含失败关键字（正常）")

    out["status"] = "★可疑" if out["suspect"] else "正常"
    out["r1"] = {"status": r1.status_code, "len": len(r1.content),
                 "body": re.sub(r'\s+', ' ', b1[:160])}
    out["r2"] = {"status": r2.status_code, "len": len(r2.content),
                 "body": re.sub(r'\s+', ' ', b2[:160])}
    return out


def show(o):
    print("  ── %s ──" % o["host"])
    print("     状态：%s   登录端点：%s" % (o["status"], o.get("login_url") or "-"))
    if o.get("fields"):
        print("     字段：%s" % o["fields"])
    for n in o.get("notes", []):
        print("     · %s" % n)
    for k in ("r1", "r2"):
        if o.get(k):
            print("     %s: %s len=%d %s" % ("空口令" if k == "r1" else "错口令",
                                             o[k]["status"], o[k]["len"], o[k]["body"][:110]))
    print()


def self_test():
    """离线自测（0 请求）。"""
    ok = 0
    u = rand_user()
    assert u.startswith(PROBE_PREFIX) and len(u) == len(PROBE_PREFIX) + 10; ok += 1
    assert rand_user() != rand_user(), "每次必须不同"; ok += 1
    assert looks_like_new_auth(["PHPSESSID"], ["PHPSESSID", "auth_token"]) == ["auth_token"]; ok += 1
    assert looks_like_new_auth(["PHPSESSID"], ["PHPSESSID", "JSESSIONID"]) == [], "匿名 cookie 不算新会话"; ok += 1
    assert ANON_COOKIE.match("__RequestVerificationToken"); ok += 1
    assert not ANON_COOKIE.match("remember_me_auth_token"); ok += 1
    assert title_of("<title> A </title>") == "A"; ok += 1
    # FAIL/SUCCESS 词表必须互不重叠（否则判据自相矛盾）
    assert not (set(FAIL_WORDS) & set(SUCCESS_WORDS)), "失败词与成功词不许重叠"; ok += 1
    # try_login 字段推断（离线，不联网）
    class _S:                                   # 最小替身：只记录提交内容
        def __init__(self): self.data = None
        def post(self, url, data=None, **kw): self.data = data; return self
        def get(self, url, params=None, **kw): self.data = params; return self
    s = _S()
    try_login(s, "http://x.example/login", "POST", ["username", "password", "submit"],
              "someuser", "")
    assert s.data["username"] == "someuser" and s.data["password"] == ""; ok += 1
    assert s.data["submit"] == "登录", "提交按钮要有值"; ok += 1
    # 预算闸门（离线）
    budget_reset()
    from .safety import _charge
    for _ in range(DEFAULT_BUDGET_DEEP):
        _charge("https://budget.example/x", DEFAULT_BUDGET_DEEP)
    try:
        _charge("https://budget.example/x", DEFAULT_BUDGET_DEEP)
        raise AssertionError("超预算必须抛 BudgetExceeded")
    except BudgetExceeded:
        ok += 1
    budget_reset()
    print("  自测 %d 项全通过 ✅（离线，0 请求）" % ok)


def main():
    ap = argparse.ArgumentParser(
        description="登录逻辑探测：判登录接口是否真的校验口令（只用不存在的用户名）")
    ap.add_argument("-d", "--domain", action="append", default=[], help="目标 host，可多次")
    ap.add_argument("--batch", help="文件，每行一个 host")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET_DEEP,
                    help="每域请求预算上限（默认 %d）" % DEFAULT_BUDGET_DEEP)
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="声明已获得授权（必须，或用 TARGETSELECTOR_AUTHORIZED=1）")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--self-test", action="store_true", help="离线自测（不需要授权）")
    a = ap.parse_args()

    if a.self_test:
        self_test()
        return 0

    assert_authorized(a.i_am_authorized)

    hosts = list(a.domain)
    if a.batch:
        if not os.path.exists(a.batch):
            ap.error("--batch 文件不存在：%s" % a.batch)
        with open(a.batch, encoding="utf-8") as f:
            hosts += [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        ap.error("至少给一个 -d，或用 --batch（或 --self-test）")

    print("════ 登录逻辑探测：%d 个目标（全程只用不存在的用户名，预算 %d/域）════\n"
          % (len(hosts), a.budget))
    res, sus = [], 0
    for h in hosts:
        try:
            o = scan(h, budget=a.budget, authorized=a.i_am_authorized)
        except BudgetExceeded as e:
            o = {"host": h, "status": "超预算中止", "notes": [str(e)[:70]]}
        except Exception as e:
            o = {"host": h, "status": "异常", "notes": [str(e)[:70]]}
        res.append(o)
        if o.get("suspect"):
            sus += 1
        show(o)
    print("  合计 %d 个：★可疑 %d 个" % (len(res), sus))
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print("  [√] 已写 %s" % a.json_out)
    print("  预算用量前 10：%s" % list(budget_report().items())[:10])
    return 0 if sus else 1


if __name__ == "__main__":
    sys.exit(main())
