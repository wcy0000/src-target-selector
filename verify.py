#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify.py —— 零能力验证：一条命令，不需要联网、不需要授权、不需要读懂架构。

设计目标
--------
读者不需要相信作者，也不需要具备评估这套架构的能力。他只需要：

    python3 verify.py

然后看到最后一行是不是 `VERIFIED:`。

为什么这很重要
--------------
"你能不能验证我"不应该取决于"你有多强"。**可验证性是可以被设计出来的**：

  1. 把需要判断的结论，改造成**机械可判定**的断言（自测）
  2. 把依赖直觉的输出，固化成**黄金样例**（golden），让程序 diff 而不是让人看
  3. 把"合规承诺"也变成**可被证伪的行为**（门禁必须拒绝、闸门必须拦停）

验证分四层，全部离线：

  L1 单元断言   三个模块的 self_test()（53 项）
  L2 黄金样例   hostextract 在 examples 上的输出必须逐字段等于 tests/golden/
  L3 门禁行为   未声明授权时必须拒绝；声明后必须放行
  L4 预算行为   按主机计数，超预算必须抛 BudgetExceeded

用法::

    python3 verify.py            # 全跑，最后打印 VERIFIED: n/n
    python3 verify.py --quiet    # 只打印结论
"""
import argparse
import json
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# 门禁测试需要确定的环境：先清掉可能被外部设置的环境变量
os.environ.pop("TARGETSELECTOR_AUTHORIZED", None)


class Checker:
    def __init__(self, quiet=False):
        self.passed = 0
        self.failed = []
        self.quiet = quiet

    def check(self, name, fn):
        try:
            fn()
            self.passed += 1
            if not self.quiet:
                print("  ✓ %s" % name)
        except Exception as e:
            self.failed.append((name, "%s: %s" % (type(e).__name__, e)))
            if not self.quiet:
                print("  ✗ %s" % name)
                if not isinstance(e, AssertionError):
                    traceback.print_exc()

    def summary(self):
        total = self.passed + len(self.failed)
        print()
        for name, err in self.failed:
            print("  失败项：%s\n         %s" % (name, err))
        if self.failed:
            print("\nFAILED: %d/%d 通过" % (self.passed, total))
            return 1
        print("VERIFIED: %d/%d 全部通过（离线，0 请求，无需授权）" % (self.passed, total))
        return 0


def layer1_self_tests(c):
    """L1：三个模块的离线自测。"""
    from targetselector import hostextract, accountface, loginlogic
    c.check("hostextract 自测（17 项断言）", hostextract.self_test)
    c.check("accountface 自测（25 项断言）", accountface.self_test)
    c.check("loginlogic 自测（11 项断言）", loginlogic.self_test)


def layer2_golden(c):
    """L2：黄金样例逐字段比对。"""
    from targetselector import hostextract
    gp = os.path.join(ROOT, "tests", "golden", "hostextract_example.json")
    golden = json.load(open(gp, encoding="utf-8"))
    inp = os.path.join(ROOT, golden["input"])
    lines = open(inp, encoding="utf-8").read().splitlines()
    hosts, stats, submap, dropped = hostextract.extract(lines)

    def stats_match():
        assert stats == golden["expected_stats"], \
            "stats 不一致\n  实际: %s\n  期望: %s" % (stats, golden["expected_stats"])
    c.check("黄金样例 · 统计字段完全一致", stats_match)

    def hosts_match():
        assert hosts == golden["expected_hosts"], \
            "hosts 不一致\n  实际: %s\n  期望: %s" % (hosts, golden["expected_hosts"])
    c.check("黄金样例 · host 列表完全一致（含排序）", hosts_match)

    def dropped_match():
        assert dropped == golden["expected_dropped"], \
            "dropped 不一致\n  实际: %s\n  期望: %s" % (dropped, golden["expected_dropped"])
    c.check("黄金样例 · 被丢弃条目一致", dropped_match)

    def submap_match():
        assert sorted(submap) == golden["expected_submap_keys"], \
            "二级域映射键不一致: %s" % sorted(submap)
    c.check("黄金样例 · 二级域映射键一致", submap_match)

    def determinism():
        """同一输入跑两次必须完全一致（否则不能做黄金样例）。"""
        h2, s2, _, _ = hostextract.extract(lines)
        assert (h2, s2) == (hosts, stats), "同一输入两次结果不一致"
    c.check("黄金样例 · 同输入两次结果一致（确定性）", determinism)


def layer3_auth_gate(c):
    """L3：授权门禁必须能被证伪。"""
    from targetselector.safety import NotAuthorized, assert_authorized

    def must_refuse():
        try:
            assert_authorized(False)
        except NotAuthorized:
            return
        raise AssertionError("未声明授权时居然放行了 —— 门禁失效")
    c.check("授权门禁 · 未声明授权必须拒绝", must_refuse)

    def must_allow_flag():
        assert assert_authorized(True) is True
    c.check("授权门禁 · 显式声明后放行", must_allow_flag)

    def must_allow_env():
        os.environ["TARGETSELECTOR_AUTHORIZED"] = "1"
        try:
            assert assert_authorized(False) is True
        finally:
            os.environ.pop("TARGETSELECTOR_AUTHORIZED", None)
    c.check("授权门禁 · 环境变量放行", must_allow_env)

    def no_network_on_refuse():
        """门禁必须在**发出请求之前**生效：这个测试只允许发往必然失败的地址。"""
        import socket
        from targetselector.safety import GuardedSession
        try:
            GuardedSession(budget=8, authorized=False)   # 构造即应拒绝
        except NotAuthorized:
            return
        raise AssertionError("GuardedSession 在未授权时居然构造成功")
    c.check("授权门禁 · Session 构造阶段即拒绝（请求前生效）", no_network_on_refuse)


def layer4_budget_gate(c):
    """L4：请求预算闸门必须能被证伪。"""
    from targetselector.safety import BudgetExceeded, _charge, budget_report, budget_reset

    def trips_at_limit():
        budget_reset()
        for _ in range(3):
            _charge("https://budget-gate.example/x", 3)
        try:
            _charge("https://budget-gate.example/x", 3)
        except BudgetExceeded:
            return
        finally:
            budget_reset()
        raise AssertionError("超过预算居然没抛 BudgetExceeded —— 闸门失效")
    c.check("预算闸门 · 超预算必须抛 BudgetExceeded", trips_at_limit)

    def counts_per_host():
        budget_reset()
        for _ in range(5):
            _charge("https://a.example/x", 8)
        for _ in range(2):
            _charge("https://b.example/x", 8)
        rep = budget_report()
        assert rep.get("a.example") == 5 and rep.get("b.example") == 2, rep
        budget_reset()
    c.check("预算闸门 · 按主机独立计数", counts_per_host)

    def shared_across_sessions():
        """跨 Session 共享计数器 —— 否则'每域预算'这个承诺是假的。"""
        from targetselector.safety import GuardedSession
        budget_reset()
        s1 = GuardedSession(budget=4, authorized=True)
        s2 = GuardedSession(budget=4, authorized=True)
        url = "https://shared.example/x"
        _charge(url, 4)
        _charge(url, 4)
        assert s1.spent(url) == 2 and s2.spent(url) == 2, \
            "两个 Session 各自计数 —— 每域预算的承诺不成立（实际 %s / %s）" \
            % (s1.spent(url), s2.spent(url))
        budget_reset()
    c.check("预算闸门 · 跨 Session 共享同一计数器", shared_across_sessions)


def main():
    ap = argparse.ArgumentParser(description="零能力验证：一条命令确认本仓库可信")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    print("════════ targetselector · 零能力验证 ════════")
    print("离线运行：不联网、不需要授权、不需要读懂架构")
    print("（L1 单元断言 / L2 黄金样例 / L3 门禁行为 / L4 预算行为）\n")

    c = Checker(quiet=a.quiet)
    print("[L1] 单元断言")
    layer1_self_tests(c)
    print("[L2] 黄金样例（逐字段比对，非人工目测）")
    layer2_golden(c)
    print("[L3] 授权门禁行为")
    layer3_auth_gate(c)
    print("[L4] 请求预算闸门行为")
    layer4_budget_gate(c)
    return c.summary()


if __name__ == "__main__":
    sys.exit(main())
