#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hostextract.py —— 资产清单 → 归一化 host 列表（**完全离线，0 个网络请求**）

它在流水线里的位置
------------------
选靶的第一步不是"扫"，而是"把一堆杂乱的资产条目变成一个干净、去重、可枚举的
host 列表"。这一步应当是纯本地的——不产生任何流量，因此没有授权风险，
也不消耗请求预算。

三个真实的坑（都是踩出来的）
--------------------------
1. **协议/端口/通配符混在一条记录里**：`https://*.example.com:8443/path`。
   剥掉协议与路径容易，难的是决定通配符 `*.` 要不要保留。
   本工具的做法：默认**去掉通配符并列出去重后的裸域**，因为你要探测的是
   "这个资产上有没有登录入口"，而通配符不是一个可探测的对象。
2. **同一套系统部署在多个子域**：`www.example.edu.cn` 与 `xx.example.edu.cn`
   会被抽成两条，重复投入。默认按**二级域去重**（`--keep-subdomains` 可关闭），
   同时保留"二级域 → 子域列表"的映射，供后续"同款产品多部署"分析使用。
3. **脏数据混入**：内网 IP、单标签主机名、邮箱、URL 片段、中文备注。
   一律丢弃并**计数**——丢弃数量本身是数据质量信号，别静默吞掉。

用法::

    python3 -m targetselector.hostextract --input assets.txt --output hosts.txt
    python3 -m targetselector.hostextract --input assets.txt --keep-subdomains --json map.json
    python3 -m targetselector.hostextract --self-test
"""
import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict

# 合法的可注册/可探测域名：至少两段，顶级域 2-24 个字母
DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
TLD_RE = re.compile(r'\.[a-z]{2,24}$')

# 常见公共后缀的简化处理：用于"二级域"归并时避免把 co.uk 这类当成注册域
MULTI_PART_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.cn", "net.cn", "org.cn", "gov.cn",
    "edu.cn", "ac.cn", "com.hk", "com.tw", "co.jp", "com.au", "com.sg",
}


def normalize_host(raw):
    """把一个资产条目归一化成裸 host（小写、无协议/端口/路径/通配符）。

    返回 None 表示应当丢弃（空、IP、单标签、明显不是域名）。
    """
    if not raw:
        return None
    s = raw.strip().lower()
    if not s or s.startswith("#"):
        return None
    # 去掉注释尾巴与空白
    s = s.split()[0]
    # 去协议
    s = re.sub(r'^[a-z][a-z0-9+.-]*://', '', s)
    # 去 userinfo
    s = s.split('@')[-1]
    # 去路径/查询/锚点
    s = re.split(r'[/?#]', s)[0]
    # 去端口
    s = s.split(':')[0]
    # 去通配符与结尾点
    s = s.lstrip('*.').rstrip('.')
    if not s or '.' not in s:
        return None
    # 丢弃 IP（v4/v6）——内网地址不在选靶范围，也避免误测
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass
    if not DOMAIN_RE.match(s) or not TLD_RE.search(s):
        return None
    return s


def registrable(host):
    """取"二级域"（注册域）：用于把同一站点的多个子域归并。

    简化实现：处理 co.uk / com.cn 这类多段后缀，其余取最后两段。
    """
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    last2 = '.'.join(parts[-2:])
    if last2 in MULTI_PART_SUFFIX and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return last2


def extract(lines, keep_subdomains=False):
    """主入口：返回 (hosts, stats, submap)。"""
    kept, dropped, seen = [], [], set()
    submap = defaultdict(set)
    for raw in lines:
        h = normalize_host(raw)
        if not h:
            if raw.strip() and not raw.strip().startswith('#'):
                dropped.append(raw.strip()[:80])
            continue
        seen.add(h)
        submap[registrable(h)].add(h)

    if keep_subdomains:
        hosts = sorted(seen)
    else:
        hosts = sorted({registrable(h) for h in seen})

    stats = {
        "输入行数": len(lines),
        "去重后 host 数（含子域）": len(seen),
        "最终 host 数": len(hosts),
        "丢弃条数": len(dropped),
        "二级域数": len(submap),
        "多子域站点数": sum(1 for v in submap.values() if len(v) > 1),
    }
    return hosts, stats, {k: sorted(v) for k, v in submap.items()}, dropped


def self_test():
    ok = 0
    assert normalize_host("https://*.Example.com:8443/a/b?c=1") == "example.com"; ok += 1
    assert normalize_host("  WWW.Example.CN  ") == "www.example.cn"; ok += 1
    assert normalize_host("user@host.example.com/x") == "host.example.com"; ok += 1
    assert normalize_host("192.168.1.1") is None, "内网 IP 必须丢弃"; ok += 1
    assert normalize_host("10.0.0.1:8080") is None; ok += 1
    assert normalize_host("localhost") is None, "单标签主机名必须丢弃"; ok += 1
    assert normalize_host("") is None and normalize_host("# 注释") is None; ok += 1
    assert normalize_host("not a domain") is None; ok += 1
    # 二级域归并
    assert registrable("a.b.example.com") == "example.com"; ok += 1
    assert registrable("example.com") == "example.com"; ok += 1
    assert registrable("a.b.example.co.uk") == "example.co.uk", "多段后缀要正确处理"; ok += 1
    assert registrable("mail.example.com.cn") == "example.com.cn"; ok += 1
    # 归并行为 + 去重
    hosts, stats, submap, dropped = extract([
        "https://www.example.com", "http://mail.example.com", "*.example.com",
        "10.1.1.1", "example.com", "other.org",
    ])
    assert hosts == ["example.com", "other.org"], hosts; ok += 1
    assert stats["最终 host 数"] == 2; ok += 1
    assert stats["丢弃条数"] == 1; ok += 1
    assert submap["example.com"] == ["example.com", "mail.example.com", "www.example.com"]; ok += 1
    # --keep-subdomains 保留子域
    hosts2, _, _, _ = extract(["www.example.com", "mail.example.com"], keep_subdomains=True)
    assert hosts2 == ["mail.example.com", "www.example.com"]; ok += 1
    print("  自测 %d 项全通过 ✅（离线，0 请求）" % ok)


def main():
    ap = argparse.ArgumentParser(description="资产清单 → 归一化 host 列表（离线，不发任何请求）")
    ap.add_argument("--input", help="输入文件：每行一个资产条目（域名/URL/通配符）")
    ap.add_argument("--output", help="输出文件：每行一个 host")
    ap.add_argument("--keep-subdomains", action="store_true",
                    help="保留子域（默认按二级域归并去重）")
    ap.add_argument("--json", dest="json_out", help="把统计与二级域映射写 JSON")
    ap.add_argument("--show-dropped", type=int, default=0, metavar="N",
                    help="打印前 N 条被丢弃的条目（用于排查数据质量）")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        self_test()
        return 0

    if not a.input:
        ap.error("需要 --input（或用 --self-test）")
    with open(a.input, encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()

    hosts, stats, submap, dropped = extract(lines, keep_subdomains=a.keep_subdomains)

    print("════ host 抽取（离线，未发起任何网络请求）════")
    for k, v in stats.items():
        print("  %-26s %s" % (k + "：", v))
    if a.show_dropped:
        print("  被丢弃样例：")
        for d in dropped[:a.show_dropped]:
            print("    · %s" % d)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write("\n".join(hosts) + "\n")
        print("  [√] 已写 %s（%d 个 host）" % (a.output, len(hosts)))
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump({"stats": stats, "subdomains": submap}, f, ensure_ascii=False, indent=2)
        print("  [√] 已写 %s" % a.json_out)
    return 0 if hosts else 1


if __name__ == "__main__":
    sys.exit(main())
