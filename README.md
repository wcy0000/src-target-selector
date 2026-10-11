# targetselector

> **授权范围内的资产选靶工具集。**
> 把"几百上千条杂乱资产"收窄成"值得花时间精测的少数几个靶"——用一个可复现、
> 有请求预算上限、可离线自测的流水线。

[![self-test](https://img.shields.io/badge/self--test-53%20assertions%20offline-brightgreen)](#自测与验证)
[![budget](https://img.shields.io/badge/request%20budget-8%20%2F%20domain-blue)](#请求预算)

---

## ⚠️ 先读这一节

本项目**只应被用于你已获得明确授权**的资产（自有资产、或平台/厂商公开授权范围内的资产）。
两条硬约束写在代码里，不是文档里的口号：

1. **授权门禁**：任何发起网络请求的操作，必须显式声明已授权
   （`--i-am-authorized` 或 `export TARGETSELECTOR_AUTHORIZED=1`），否则直接抛 `NotAuthorized`。
2. **请求预算闸门**：按主机计数，超预算立即抛 `BudgetExceeded` 并中止。
   默认 **8 次/域**（快筛）、**32 次/域**（深测）。

请先读 [COMPLIANCE.md](COMPLIANCE.md)。

---

## 它解决什么问题

批量资产里，绝大多数"看起来有登录页"的站其实是**假命中**：

| 假命中的形态 | 后果 |
|---|---|
| SPA / 404 fallback：任意路径都返回同一页 | 只看"200 且有内容"会把它们全记成账号面，命中率虚高到 30%+ |
| 查询参数被忽略、原样回显首页 | `index.php?m=user&c=login` 返回的其实是首页 |
| 301 到"自己 + 尾斜杠" | 服务器统一加斜杠，不是真页面 |
| 已知指纹/公开组件 | 平台普遍"网上已公开的漏洞无奖励"，投入即浪费 |

真问题不是"扫不到"，而是**把 98% 的时间花在没有人入口的资产上**。

---

## 流水线：三层漏斗 + 请求预算

```
 资产清单（厂商/项目公开范围）
        │
        ├─ ① hostextract   归一化 / 去重 / 丢弃脏数据      0 请求（纯离线）
        │
        ├─ ② accountface   账号面快筛                      ≤8 请求/域
        │      判据：有 <input type=password> 且与「随机基线」「首页」不同形
        │
        └─ ③ loginlogic    登录逻辑探测                    ≤32 请求/域
               判据：①失败也下发非匿名 Cookie ②失败会话能访问受保护页
                     ③空口令与错口令响应显著不同
```

**为什么这样分配预算**：②是"要不要深打"的唯一判据，所以要求极快的否决；
③只对"已确认存在账号面"的目标执行（即二级漏斗，收敛后只剩 2% 左右），
所以允许更深的探测。

### 请求预算一览

| 阶段 | 默认预算 | 组成 |
|---|---|---|
| ① `hostextract` | **0** | 纯本地文本处理，不发任何请求 |
| ② `accountface`（快筛） | **8 / 域** | 首页 1 + 随机基线 1 + 候选路径 6 |
| ② `accountface`（全量） | **8 / 域** | 首页 1 + 随机基线 1 + 候选路径 6（全量模式请自行调 `--budget`） |
| ③ `loginlogic` | **32 / 域** | 首页 1 + 找表单 ≤7 + 登录提交 2 + 受保护页对照 ≤8×2 = 最坏 26 |

---

## 安装

```bash
git clone https://github.com/wcy0000/src-target-selector && cd src-target-selector
python3 -m pip install -r requirements.txt   # 只需要 requests
```

Python ≥ 3.8。无其他依赖、无外部服务、无数据库。

---

## 快速开始

### 0) 离线自测（不需要授权，不联网）

```bash
python3 -m targetselector.hostextract --self-test
python3 -m targetselector.accountface --self-test
python3 -m targetselector.loginlogic  --self-test
```

### 1) 资产清单 → 归一化 host（0 请求）

```bash
python3 -m targetselector.hostextract --input examples/hosts.example.txt \
        --output hosts.txt --json hostmap.json --show-dropped 5
```

输出示例（**实测输出，可直接复现**：`examples/hosts.example.txt` 共 11 行）：

```
════ host 抽取（离线，未发起任何网络请求）════
  输入行数：                      11
  去重后 host 数（含子域）：           5
  最终 host 数：                 3
  丢弃条数：                      2
  二级域数：                      3
  多子域站点数：                    1
  被丢弃样例：
    · 192.168.1.10
    · localhost
  [√] 已写 hosts.txt（3 个 host）
```

`--json` 会额外产出「二级域 → 子域列表」的映射，用于识别**同一套系统部署在多个子域**的情况
（一组指纹打穿一个等于打穿一组）。

### 2) 账号面快筛（≤8 请求/域）

```bash
# 单目标
python3 -m targetselector.accountface -d example.com --i-am-authorized

# 批量（并发默认 8，请勿轻易调高）
python3 -m targetselector.accountface --batch hosts.txt --workers 8 \
        --json faces.json --i-am-authorized
```

输出示例（命中）：

```
  ★ www.example.com          XX 管理系统
       /login                       len=11411  登录
       /register                    len=9860   注册
```

输出示例（假命中被剔除）：

```
     ⚠ 已剔除 12 个「与基线/首页同形」的 fallback 假命中（非 404 ≠ 页面存在）
```

### 3) 登录逻辑探测（≤32 请求/域，只用不存在的用户名）

```bash
python3 -m targetselector.loginlogic -d www.example.com --i-am-authorized
python3 -m targetselector.loginlogic --batch faces_hosts.txt --json logic.json --i-am-authorized
```

输出示例：

```
  ── www.example.com ──
     状态：★可疑   登录端点：http://www.example.com/index.php?m=user&c=login
     字段：['username', 'password', 'submit']
     · 登录失败后下发非匿名 Cookie：['auth_token']
     · 空口令像成功、错口令像失败（口令可能未参与判定）
     空口令: 200 len=142 (JSON) …
     错口令: 200 len=67  (JSON) …
```

> ⚠️ `★可疑` **不是漏洞结论**。可疑目标仍需人工用**自注册的两个账号**做 A/B 对照，
> 并按所属平台的取证口径留证。本工具刻意不做这一步。

---

## 方法原理

### 账号面判定：双层基线对照

```python
def is_fallback(res, baseline, home_hash=None):
    if res["pwd"]:          # ★ 反向保护：有密码框的真登录页永不误杀
        return False
    ...                     # 与随机路径基线同形 → fallback
    ...                     # 与首页同形         → fallback
```

两层缺一不可：
- **与随机不存在路径同形** ⇒ SPA/404 fallback
- **与首页同形** ⇒ 查询参数被忽略、原样回显首页

指纹用可见正文骨架的 SHA-256 前 16 位，压掉 `<script>`/`<style>`/注释/空白等噪声。

### 登录逻辑判定：三判据

| # | 判据 | 命中含义 |
|---|---|---|
| ① | 登录**失败**后是否下发**非匿名** Cookie | 先建会话型缺陷 |
| ② | 该"失败会话"能否访问受保护页 | 鉴权与会话状态脱钩 |
| ③ | **空口令** vs **错口令** 响应是否显著不同 | 口令可能未参与判定 |

**为什么只用不存在的用户名**：若用真实用户名测"空口令能否登录"，一旦命中就是真的
登录进他人账号——不可逆。用不存在的用户名同样能判定缺陷，因为正常实现会回
"用户不存在"，而缺陷实现会先建会话、再（不）校验口令。

---

## 实测结果（一次真实批量运行的摘要）

| 指标 | 数值 |
|---|---|
| 候选资产条目 | 1165 |
| 归一化去重后 host | 1134 |
| **命中真账号面** | **22（2.0%）** |
| 不可达（DNS/TCP/TLS 失败） | 256 |
| 未授权 API 面有效候选 | **0** |

三点值得记下来的结论：

1. **2% 是真实的命中率**。用"200 且有内容"做判据会得到虚高十几倍的假命中。
2. **阴性结果同样要记录**。未授权 API 那一层全军覆没——记下来，下次不在同一层浪费预算。
3. **部署指纹高度集中**：命中集中在高校、医院、政务门户、继续教育平台
   （Server 指纹多为 nginx / Tengine / IIS / openresty）。

### 候选路径的边际收益（22 个真实命中样本）

按"只跑前 k 个候选路径"统计首次命中位置（每域固定 2 请求 = 首页 + 随机基线）：

| k | 路径 | 本轮新增命中 | 累计命中 | 累计命中率 | 每域请求数 |
|---|---|---|---|---|---|
| 1 | `/login` | **13** | 13 | **59.1%** | 3 |
| 2 | `/register` | **0** | 13 | 59.1% | 4 |
| 3 | `/resetpwd` | **0** | 13 | 59.1% | 5 |
| 4 | `/login.html` | 4 | 17 | 77.3% | 6 |
| 5 | `/user/login` | 3 | 20 | 90.9% | 7 |
| 6 | `/index.php?m=user&c=login` | 2 | 22 | **100%** | 8 |

**由这张表得出的优化（已落进代码）**：`/register` 与 `/resetpwd` 在本批样本中
**零贡献**，而前 4 条路径已能 100% 召回 ⇒ **重排后每域 6 请求即可全覆盖，
请求量降低 25%，召回零损失**。零贡献的两条降级到末尾保留（换资产批次后分布可能变化，
不直接删除）。

> 这就是"记录阴性结果"的价值：**你不知道哪两条路径没用，就无法把预算压到 6 请求。**

---

## 自测与验证

```bash
$ python3 -m targetselector.hostextract --self-test
  自测 17 项全通过 ✅（离线，0 请求）
$ python3 -m targetselector.accountface --self-test
  自测 25 项全通过 ✅（离线，0 请求）
$ python3 -m targetselector.loginlogic --self-test
  自测 11 项全通过 ✅（离线，0 请求）
```

**共 53 项断言，全部离线**（不发一个包）。每条核心判据都做**正负对照**：

- `is_fallback`：同形必须判 fallback；**不同内容必须放行**（防止"一律判 fallback"）；无基线时不许判
- 反向保护：**有密码框的页面永不判 fallback**（防止误杀真登录页）
- 通配 302：跳到同一处 = fallback；**跳到不同处必须放行**
- 词表自检：`FAIL_WORDS` 与 `SUCCESS_WORDS` 不允许重叠（否则判据自相矛盾）

### 合规闸门实测

```bash
# ① 不声明授权 → 拒绝
$ python3 -m targetselector.accountface -d http://127.0.0.1:8899
NotAuthorized: 未声明授权。请先确认你已获得……明确授权

# ② 声明授权 + budget=3 → 中途干净中止（不是崩溃）
$ python3 -m targetselector.accountface -d http://127.0.0.1:8899 \
      --i-am-authorized --budget 3
     ❌ 主机 127.0.0.1:8899 已达请求预算 3 次，已中止。
```

---

## 局限与未做的事（诚实清单）

- **不判断漏洞**：只产出"可疑"与"值得深打"的候选，取证与定级由人工完成。
- **不做越权 A/B 测试**：需要自注册双账号与人工判断，刻意不自动化。
- **不做子域枚举 / 端口扫描 / 目录爆破**：超出本项目范围，也更容易越界。
- **重定向跳转不计入预算**：计数器只统计显式请求（探测脚本均已 `allow_redirects=False`）。
- **二级域归并用简化后缀表**：`co.uk`/`com.cn` 等已处理，但公共后缀表并非完整实现。
- **不内置任何目标清单**：`examples/` 里全是保留域名（`example.com` 等）。

---

## 文件结构

```
targetselector/
├── safety.py        请求预算闸门 + 授权门禁（先读这个）
├── hostextract.py   资产清单 → 归一化 host（离线）
├── accountface.py   账号面快筛（≤8 请求/域）
└── loginlogic.py    登录逻辑探测（≤32 请求/域）
tools/
└── cookie_lab.py    跨站 Cookie 属性组合实测台（隔离回环双站 + 第一方自校验）
examples/
├── hosts.example.txt
└── scope.example.json
COMPLIANCE.md        使用边界与合规要求（必读）
```

---

## 附：跨站 Cookie 实测台（`tools/cookie_lab.py`）

用来回答一个很具体的问题：**某个 Cookie 属性组合，在真实浏览器下会不会被跨站携带？**

它在**本机两个回环 IP** 上分别起"受害站（HTTPS）"与"攻击者源（HTTP）"——
天然属于不同 registrable domain，因此是**真跨站**，不需要改 hosts，也不碰任何外部网络。

```bash
python3 tools/cookie_lab.py run      # 跑 4 组合 × 2 种 Chrome 设置，打印矩阵
```

实测结果（Chrome 152.0.7977.64）：

| Cookie 属性 | 第一方请求 | 跨站（关闭 3PC 封锁） | 跨站（Chrome 默认） |
|---|---|---|---|
| `SameSite=None`（无 `Secure`） | **❌ 没存上** | ❌ | ❌ |
| `SameSite=None; Secure` | ✅ | **✅ 发送** | **✅ 发送** |
| `SameSite=Lax` | ✅ | ❌ | ❌ |
| `SameSite=Strict` | ✅ | ❌ | ❌ |

**它内置了一个关键的自校验步骤**：每组实验都会先确认"第一方请求真的带上了这个 Cookie"。
没有这一步，你无法区分"Cookie 没存上"与"存上了但跨站不发送"——
而这两者的根因和修复方案完全不同。（这个坑我们在开发时就踩过一次：
Cookie 没写 `Max-Age` 时会话 Cookie 不落盘，直接导致全组假阴性。）

**局限（写在这里而不是藏起来）**：受害站是回环 IP，Chrome 对 localhost 的第三方 Cookie
策略可能存在豁免，因此本结果**不能外推**到公网域名；也只测了 Chrome 一个内核。

---

## 许可

MIT，见 [LICENSE](LICENSE)。**许可不构成对任何目标系统的访问授权。**
