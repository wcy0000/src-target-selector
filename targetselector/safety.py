#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""safety.py —— 请求预算闸门 + 授权门禁（本项目的第一原则，写进代码而不是文档）

为什么要有这个模块
------------------
目标筛选类工具最大的风险不是"不好用"，而是**被用在不该用的地方**。
所以两条硬约束做成代码级的，而不是靠文档里一句"请遵守法律"：

1. **授权门禁**：任何发起网络请求的操作，必须显式声明已获授权
   （命令行 `--i-am-authorized`，或环境变量 `TARGETSELECTOR_AUTHORIZED=1`）。
   未声明时只允许 `--dry-run` / `--self-test` 这类离线模式。

2. **请求预算闸门**：按**主机**计数（跨 Session 共享同一计数器），超预算立即抛
   `BudgetExceeded` 并中止。默认：账号面快筛 **8** 次/域，登录逻辑深测 **32** 次/域
   （深测只对"已确认存在账号面"的目标执行，即二级漏斗，故预算更高；其最坏路径为
   首页 1 + 找表单 ≤7 + 两次登录提交 + 受保护页对照 ≤8×2 = 26 次）。
   调高预算必须显式传参，并会在日志里留痕。

这不是形式主义。主流平台的通用行为规范普遍禁止"大流量扫描"与"业务扰动"，
超预算扫描既可能违反平台规则，也可能对目标系统造成实际影响。
把预算做成硬上限，是为了让"手滑"在代码层就不可能发生。

诚实说明一处限制
----------------
计数器只统计**显式发起的请求**。`requests` 跟随 3xx 重定向时内部的跳转不计入，
因此实际网络包数可能略高于计数。若你的场景对此敏感，把 `allow_redirects=False`
显式传入（本项目两个探测脚本都已是这么做的）。
"""
import os
import threading
from urllib.parse import urlparse

import requests

# 默认预算（次/主机）
DEFAULT_BUDGET_FAST = 8     # 账号面快筛：首页 + 随机基线 + 6 个候选路径
DEFAULT_BUDGET_DEEP = 32    # 登录逻辑深测：最坏 1+7+2+8×2 = 26，留出余量

# 跨 Session 共享的按主机计数器 —— 保证"每域预算"这个语义是真的
_COUNT = {}
_LOCK = threading.Lock()


class NotAuthorized(RuntimeError):
    """未声明授权，拒绝发起网络请求。"""


class BudgetExceeded(RuntimeError):
    """单个主机的请求数超过预算。"""


def assert_authorized(flag=False):
    """网络操作前的门禁。

    flag=True（命令行显式声明）或环境变量 TARGETSELECTOR_AUTHORIZED=1 时放行。
    """
    if flag or os.environ.get("TARGETSELECTOR_AUTHORIZED") == "1":
        return True
    raise NotAuthorized(
        "未声明授权。请先确认你已获得目标资产所有者或所属平台在书面/公开规则层面的"
        "明确授权，再执行：\n"
        "  · 加参数 --i-am-authorized，或\n"
        "  · export TARGETSELECTOR_AUTHORIZED=1\n"
        "离线模式（--self-test / --dry-run）不需要授权。"
    )


def budget_reset():
    """清空全局计数（测试用）。"""
    with _LOCK:
        _COUNT.clear()


def budget_report():
    """返回 {host: 已用次数}，按用量降序。"""
    with _LOCK:
        return dict(sorted(_COUNT.items(), key=lambda kv: -kv[1]))


def _charge(url, budget, verbose=False):
    host = urlparse(url).netloc.lower()
    with _LOCK:
        n = _COUNT.get(host, 0) + 1
        _COUNT[host] = n
    if verbose:
        print("    [budget] %-34s %d/%d" % (host, n, budget))
    if n > budget:
        raise BudgetExceeded(
            "主机 %s 已达请求预算 %d 次，已中止。"
            "（确有必要请显式传 --budget N；请先确认这不会违反授权范围与平台规则）"
            % (host, budget)
        )
    return n


class GuardedSession(requests.Session):
    """带预算闸门的 Session：所有实例共享同一个按主机计数器。

    用法::

        s = GuardedSession(budget=8, authorized=True)
        s.get("https://example.com/login")   # 计数 +1；超预算抛 BudgetExceeded
        s.spent("https://example.com/")      # -> 已用次数
    """

    def __init__(self, budget=DEFAULT_BUDGET_FAST, authorized=False, verbose=False, **kw):
        super().__init__(**kw)
        assert_authorized(authorized)
        self.budget = int(budget)
        self.verbose = verbose

    def request(self, method, url, **kw):  # noqa: D102  (requests 钩子)
        _charge(url, self.budget, self.verbose)
        kw.setdefault("timeout", 12)
        return super().request(method, url, **kw)

    def spent(self, url):
        """该 URL 所属主机已用掉的预算。"""
        return _COUNT.get(urlparse(url).netloc.lower(), 0)
