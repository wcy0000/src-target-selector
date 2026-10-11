"""targetselector —— 授权范围内的资产选靶工具集。

模块
----
hostextract  资产清单 → 归一化 host（离线，0 请求）
accountface  账号面快筛：找出真实的登录/注册/找回入口（默认 8 请求/域）
loginlogic   登录逻辑探测：判断登录接口是否真的校验口令（默认 20 请求/域）
safety       请求预算闸门 + 授权门禁

先读 COMPLIANCE.md 再动手。
"""
__version__ = "1.0.0"
