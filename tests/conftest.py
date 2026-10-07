"""pytest 全局: 时序拟真默认关闭 — 测试不能变慢; 时序用例自行 monkeypatch 打开"""
import os

os.environ["HONEYPOT_TIMING_FAKE"] = "0"
