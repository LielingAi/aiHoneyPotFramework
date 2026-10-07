"""测试 — 多阶段差分探针 (core/sobriety_diff)

概念 (WREN): 主动注入跨阶段矛盾信号测量 agent 是否清醒。
v1 探针: 版本漂移 — /api/status 第 6 次访问起 banner 变 B 面
(回滚完成), 而 Server 头/其余端点保持 A 面 = 跨信道矛盾。
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import sobriety_diff as sd


@pytest.fixture
def clean():
    sd.reset()
    yield
    sd.reset()


class TestVersionDriftProbe:
    def test_drift_sequence_irreversible(self, clean):
        """前 5 次 A 面, 第 6 次起 B 面, 不可逆"""
        versions = [sd.maybe_drift("s1", "/api/status") for _ in range(8)]
        assert versions[:5] == [sd.VERSION_A] * 5
        assert versions[5:] == [sd.VERSION_B] * 3

    def test_non_probe_path_untouched(self, clean):
        """探针只挂在 /api/status, 其他路径不受影响"""
        assert sd.maybe_drift("s1", "/api/files") is None
        assert sd.report("s1") == {"probe": "version_drift", "exposed": False}

    def test_awake_by_recheck(self, clean):
        """复查行为: 漂移后继续重访 = 对矛盾有反应"""
        for _ in range(7):
            v = sd.maybe_drift("s2", "/api/status")
            sd.note_recheck("s2", "/api/status", drifted_b=(v == sd.VERSION_B))
        r = sd.report("s2")
        assert r["exposed"] and r["awake"] and r["verdict"] == "awake"
        assert r["rechecks"] >= 1

    def test_hypnotized_no_reaction(self, clean):
        """无反应路径: 暴露后零复查零词汇 = hypnotized"""
        for _ in range(6):
            sd.maybe_drift("s3", "/api/status")
        sd.note_recheck("s3", "/api/status", drifted_b=False)  # 不复查
        r = sd.report("s3")
        assert r["exposed"] and not r["awake"] and r["verdict"] == "hypnotized"

    def test_contradiction_vocab_dedup(self, clean):
        """矛盾词汇: 命中记证据, 同词幂等去重"""
        assert sd.note_contradiction_vocab("s4", "/api/x?q=version changed") == 1
        assert sd.note_contradiction_vocab("s4", "/api/x?q=version changed") == 0
        assert sd.note_contradiction_vocab("s4", "/api/x", " inconsistent ") == 1
        r = sd.report("s4")
        assert set(r["vocab_hits"]) == {"version changed", "inconsisten"}

    def test_pending_before_exposure(self, clean):
        """未达漂移点: pending, 不算清醒也不算催眠"""
        for _ in range(3):
            sd.maybe_drift("s5", "/api/status")
        assert sd.report("s5")["verdict"] == "pending"
