"""
测试文件 - AI 渗透反制蜜罐系统 (纯 CLI 版)
四层流水线集成测试
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.discovery import DiscoveryLayer, AgentType
from core.monitoring import AttackClassifier, AttackFamily
from core.analysis import AnalysisLayer
from core.countermeasure import CountermeasureService
from core.auth_bait import AuthBaitEngine


class TestDiscoveryLayer:
    """L1 发现层测试"""

    def test_ai_tool_detection(self):
        """测试 AI 工具 User-Agent 检测"""
        layer = DiscoveryLayer()
        result = layer.analyze(
            client_ip="192.168.1.100",
            headers={"X-OpenAI-Client": "GPT-4"},
            user_agent="Mozilla/5.0 (OpenAI GPT-4)",
            timing_ms=45
        )
        assert result.is_ai_agent is True
        assert result.agent_type == AgentType.OPENAI_GPT
        assert result.confidence > 0.5

    def test_human_browser_ignored(self):
        """测试正常浏览器请求不被误报"""
        layer = DiscoveryLayer()
        result = layer.analyze(
            client_ip="172.16.0.10",
            headers={"Accept": "text/html"},
            user_agent="Mozilla/5.0 Firefox/115.0",
            timing_ms=250
        )
        assert result.is_ai_agent is False
        # 250ms 属于脚本/Bot延迟范畴，agent_type 应为 SCRIPT_BOT
        assert result.agent_type == AgentType.SCRIPT_BOT

    def test_deepseek_ua(self):
        """测试 DeepSeek User-Agent 识别"""
        layer = DiscoveryLayer()
        result = layer.analyze(
            client_ip="10.0.0.5",
            headers={},
            user_agent="DeepSeek-Agent/1.0",
            timing_ms=30
        )
        assert result.is_ai_agent is True
        assert result.agent_type == AgentType.DEEPSEEK


class TestMonitoringLayer:
    """L2 监控层测试"""

    def test_sqli_detection(self):
        """测试 SQL 注入识别"""
        classifier = AttackClassifier()
        result = classifier.classify(
            method="GET",
            path="/api/users?id=1' UNION SELECT username,password FROM users--",
            query="id=1' UNION SELECT username,password FROM users--",
            body=""
        )
        assert result.is_attack is True
        assert AttackFamily.SQLI in result.families
        assert result.confidence > 0.0

    def test_xss_detection(self):
        """测试 XSS 攻击识别"""
        classifier = AttackClassifier()
        result = classifier.classify(
            method="POST",
            path="/api/comments",
            query="",
            body='<script>alert("XSS")</script>'
        )
        assert result.is_attack is True
        assert AttackFamily.XSS in result.families

    def test_path_traversal_detection(self):
        """测试路径遍历识别"""
        classifier = AttackClassifier()
        result = classifier.classify(
            method="GET",
            path="/api/download?file=../../../etc/passwd",
            query="file=../../../etc/passwd",
            body=""
        )
        assert result.is_attack is True
        assert AttackFamily.PATH_TRAVERSAL in result.families

    def test_normal_request_safe(self):
        """测试正常请求不触发攻击检测"""
        classifier = AttackClassifier()
        result = classifier.classify(
            method="GET",
            path="/index.html",
            query="",
            body=""
        )
        assert result.is_attack is False
        assert result.families == []


class TestAnalysisLayer:
    """L3 分析层测试"""

    def test_high_threat_ai_sqli(self):
        """测试 AI + SQL 注入产生高威胁评分"""
        layer = AnalysisLayer()
        session_distribution = {AttackFamily.SQLI: 1.0}
        result = layer.analyze(
            session_distribution=session_distribution,
            agent_type=AgentType.OPENAI_GPT,
            mcp_triggered=False,
            timing_ms=50
        )
        assert result.threat_score >= 60
        assert result.trigger_countermeasure is True
        assert result.attributed_model in ("openai_gpt", "kimi_k2.5", "gemini_2.5_pro", "unknown")

    def test_low_threat_human(self):
        """测试人类正常请求低威胁评分"""
        layer = AnalysisLayer()
        result = layer.analyze(
            session_distribution={},
            agent_type=AgentType.HUMAN,
            mcp_triggered=False,
            timing_ms=300
        )
        assert result.threat_score < 40
        assert result.trigger_countermeasure is False

    def test_mcp_boosts_score(self):
        """测试 MCP 诱饵触发提升威胁评分"""
        layer = AnalysisLayer()
        result = layer.analyze(
            session_distribution={},
            agent_type=AgentType.LLM_AGENT,
            mcp_triggered=True,
            timing_ms=80
        )
        assert result.threat_score >= 45
        # MCP 单独触发不足以达到 L3 阈值（60），但显著提升了评分


class TestCountermeasureLayer:
    """L4 反制层测试"""

    def test_l3_countermeasure_triggered(self):
        """测试高威胁触发 L3 反制"""
        service = CountermeasureService(level=3)
        result = service.execute(
            threat_score=85,
            agent_type=AgentType.OPENAI_GPT,
            attack_family=[AttackFamily.SQLI],
            mcp_triggered=False,
            path="/api/users"
        )
        assert result.success is True
        assert len(result.applied_actions) > 0
        assert result.total_risk_score > 0

    def test_l1_only_for_low_threat(self):
        """测试低威胁仅触发 L1"""
        service = CountermeasureService(level=1)
        result = service.execute(
            threat_score=25,
            agent_type=AgentType.HUMAN,
            attack_family=[],
            mcp_triggered=False,
            path="/"
        )
        assert result.success is True
        # L1 资源耗尽应被触发
        assert any("resource" in a.action_type.lower() or "token" in a.action_type.lower()
                   for a in result.applied_actions)

    def test_cve_plugin_loaded(self):
        """测试 CVE 插件已加载且默认启用"""
        service = CountermeasureService(level=3)
        plugins = service.cve_loader.get_loaded_plugins()
        assert len(plugins) > 0
        for p in plugins:
            assert p.enabled is True


class TestAuthBaitEngine:
    """渐进式授权诱导测试"""

    def test_level0_payload(self):
        """测试 Level 0 诱导话术生成"""
        engine = AuthBaitEngine()
        payload = engine.get_bait_payload(session_level=0, session_data={})
        assert len(payload) > 0
        assert "<your_hostname>" in payload
        assert "Unlocks" in payload

    def test_auth_progression(self):
        """测试授权逐级升级"""
        engine = AuthBaitEngine()
        session_auth = {"level": 0, "data": {}}

        # 提交 hostname → Level 1
        new_level, collected = engine.process_auth_request(
            {"hostname": "test-server"}, session_auth
        )
        assert new_level == 1
        assert collected.get("hostname") == "test-server"
        session_auth["level"] = new_level
        session_auth["data"] = collected

        # 继续提交 user + os → Level 2
        new_level, collected = engine.process_auth_request(
            {"user": "admin", "os": "Linux"}, session_auth
        )
        assert new_level == 2

    def test_suspicious_data_detection(self):
        """测试可疑数据检测"""
        engine = AuthBaitEngine()
        session_auth = {"level": 0, "data": {}}
        new_level, collected = engine.process_auth_request(
            {"hostname": "test; rm -rf /"}, session_auth
        )
        # 命令注入应被检测到
        assert "suspicious" in collected or new_level == 0


class TestFullPipeline:
    """端到端流水线测试"""

    def test_ai_sqli_pipeline(self):
        """测试 AI SQL 注入完整流水线"""
        discovery = DiscoveryLayer()
        monitoring = AttackClassifier()
        analysis = AnalysisLayer()
        countermeasure = CountermeasureService(level=3)

        # 模拟 AI 工具 SQL 注入请求
        d_result = discovery.analyze(
            "192.168.1.100",
            {"X-OpenAI-Client": "GPT-4"},
            "Mozilla/5.0 (OpenAI GPT-4)",
            50
        )
        m_result = monitoring.classify(
            "GET",
            "/api/users?id=1' UNION SELECT * FROM users--",
            "id=1' UNION SELECT * FROM users--",
            ""
        )
        a_result = analysis.analyze(
            {f: 1.0 for f in m_result.families},
            d_result.agent_type,
            False,
            d_result.timing_ms
        )
        c_result = countermeasure.execute(
            a_result.threat_score,
            d_result.agent_type,
            m_result.families,
            False,
            "/api/users"
        )

        assert d_result.is_ai_agent is True
        assert m_result.is_attack is True
        assert a_result.trigger_countermeasure is True
        assert c_result.success is True
        assert len(c_result.applied_actions) >= 1

    def test_normal_request_pipeline(self):
        """测试正常请求完整流水线"""
        discovery = DiscoveryLayer()
        monitoring = AttackClassifier()
        analysis = AnalysisLayer()
        countermeasure = CountermeasureService(level=3)

        d_result = discovery.analyze(
            "172.16.0.10",
            {"Accept": "text/html"},
            "Mozilla/5.0 Firefox/115.0",
            250
        )
        m_result = monitoring.classify("GET", "/index.html", "", "")
        a_result = analysis.analyze(
            {}, d_result.agent_type, False, d_result.timing_ms
        )
        c_result = countermeasure.execute(
            a_result.threat_score,
            d_result.agent_type,
            m_result.families,
            False,
            "/index.html"
        )

        assert d_result.is_ai_agent is False
        assert m_result.is_attack is False
        assert a_result.trigger_countermeasure is False
        assert c_result.success is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
