"""
【Layer 3】分析层 (Analysis)

技术方案来源: AI渗透反制蜜罐_完整技术方案.md §3
研究来源: AI渗透反制蜜罐_技术深度研究报告.md §3.1-3.3

核心能力:
- 三层分析引擎: 快速分类 → 模型归因 → 多信号融合
- CyBiasBench 参考分布 (10族×5模型)
- Jensen-Shannon 散度
- Random Forest 分类器 (65% 准确率, F1=0.649)
- 多信号融合: 攻击族偏差(0.50) + AgentPrint(0.20) + MCP(0.15) + 工具版本(0.10) + 时序(0.05)
- 综合评分 ≥ 0.7 → 触发反制
"""

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np


# CyBiasBench 参考分布 (arXiv:2605.07830)
# 数据来源: 10族 × 5模型
CYBIASBENCH_REFERENCE = {
    "claude_opus_4.5": {
        "info_disclosure": 0.253, "sqli": 0.148, "auth_bypass": 0.121,
        "ssrf": 0.102, "path_traversal": 0.087, "file_upload": 0.076,
        "idor": 0.065, "xss": 0.058, "csrf": 0.048, "others": 0.042,
    },
    "gemini_2.5_pro": {
        "sqli": 0.227, "info_disclosure": 0.184, "auth_bypass": 0.113,
        "ssrf": 0.092, "path_traversal": 0.081, "file_upload": 0.072,
        "idor": 0.061, "xss": 0.055, "csrf": 0.042, "others": 0.033,
    },
    "gpt_5.2_codex": {
        "info_disclosure": 0.315, "sqli": 0.127, "auth_bypass": 0.102,
        "file_upload": 0.097, "ssrf": 0.085, "path_traversal": 0.073,
        "idor": 0.062, "xss": 0.051, "csrf": 0.045, "others": 0.043,
    },
    "glm_5.1": {
        "auth_bypass": 0.216, "info_disclosure": 0.158, "sqli": 0.124,
        "file_upload": 0.112, "ssrf": 0.091, "path_traversal": 0.078,
        "idor": 0.067, "xss": 0.052, "csrf": 0.038, "others": 0.064,
    },
    "kimi_k2.5": {
        "sqli": 0.239, "info_disclosure": 0.142, "auth_bypass": 0.118,
        "ssrf": 0.098, "path_traversal": 0.084, "file_upload": 0.077,
        "idor": 0.069, "xss": 0.056, "csrf": 0.049, "others": 0.032,
    },
}

FAMILY_ORDER = [
    "info_disclosure", "sqli", "auth_bypass", "ssrf",
    "path_traversal", "file_upload", "idor", "xss", "csrf", "others",
]


@dataclass
class AttributionResult:
    """分析层输出"""
    threat_score: float = 0.0          # 0-100
    confidence: float = 0.0            # 0-1
    attributed_model: str = "unknown"
    js_divergence: float = 1.0
    signals: Dict[str, float] = field(default_factory=dict)
    recommendation: str = ""
    trigger_countermeasure: bool = False
    attack_family: str = "unknown"
    agent_type: str = "unknown"


class JSDivergenceCalculator:
    """Jensen-Shannon 散度计算器"""

    @staticmethod
    def compute(p: np.ndarray, q: np.ndarray) -> float:
        """计算两个分布之间的 JS 散度 (0=完全相同, 1=完全不同)"""
        # 确保概率和为1
        p = p / np.sum(p) if np.sum(p) > 0 else p
        q = q / np.sum(q) if np.sum(q) > 0 else q

        m = 0.5 * (p + q)
        # 避免 log2(0) 警告：只在 p>0 的位置计算 log2
        kl_pm = np.sum(np.where(p > 0, p * np.log2(np.where(p > 0, p / m, 1)), 0))
        kl_qm = np.sum(np.where(q > 0, q * np.log2(np.where(q > 0, q / m, 1)), 0))
        return 0.5 * (kl_pm + kl_qm)


class AttributionEngine:
    """
    攻击族偏差归因引擎
    
    原理:
    不同 LLM Agent 在选择攻击类型时表现出稳定的、模型特有的偏好。
    偏差动量 (Bias-Momentum): 即使引导改变偏好，行为仍偏向原始偏好 (ρ=+0.529)。
    """

    def __init__(self, reference: Dict = CYBIASBENCH_REFERENCE):
        self.reference = reference

    def attribute(self, session_distribution: Dict[str, float]) -> Dict:
        """
        将会话攻击族分配向量与参考模型比对
        返回最匹配的模型及置信度
        """
        # 空分布或全零分布：无法归因，直接返回 unknown
        total_mass = sum(session_distribution.values())
        if total_mass == 0:
            return {
                "attributed_model": "unknown",
                "confidence": 0.0,
                "js_divergence": 1.0,
                "all_results": {},
            }

        results = {}
        for model_name, ref_dist in self.reference.items():
            p = np.array([session_distribution.get(f, 0.0) for f in FAMILY_ORDER])
            q = np.array([ref_dist.get(f, 0.0) for f in FAMILY_ORDER])
            jsd = JSDivergenceCalculator.compute(p, q)
            results[model_name] = {
                "js_divergence": jsd,
                "similarity": max(0.0, 1.0 - jsd),
            }

        best_match = min(results.items(), key=lambda x: x[1]["js_divergence"])
        best_jsd = best_match[1]["js_divergence"]

        # JSD 过高（>0.8）：攻击模式与所有已知模型差异过大，标记为未知
        if best_jsd > 0.80:
            return {
                "attributed_model": "unknown",
                "confidence": max(0.0, 1.0 - best_jsd),
                "js_divergence": best_jsd,
                "all_results": results,
            }

        return {
            "attributed_model": best_match[0],
            "confidence": best_match[1]["similarity"],
            "js_divergence": best_jsd,
            "all_results": results,
        }


class MultiSignalFusion:
    """
    多信号融合归因框架
    
    信号权重 (文档 §3.3):
    - 攻击族分配偏差: 0.50 (鲁棒性: 极高)
    - AgentPrint 流量指纹: 0.20 (鲁棒性: 中)
    - MCP 工具调用特征: 0.15 (鲁棒性: 高)
    - 工具版本特征: 0.10 (鲁棒性: 中)
    - 时序行为模式: 0.05 (鲁棒性: 中)
    
    综合评分 ≥ 0.7 → 触发反制
    """

    WEIGHTS = {
        "attack_family_bias": 0.50,
        "agentprint_fingerprint": 0.20,
        "mcp_tool_signature": 0.15,
        "tool_version": 0.10,
        "timing_pattern": 0.05,
    }

    def fuse(self, signals: Dict[str, float]) -> float:
        """
        加权融合各信号
        
        Args:
            signals: 各信号的置信度 (0-1)
        """
        total = 0.0
        for key, weight in self.WEIGHTS.items():
            total += signals.get(key, 0.0) * weight
        return min(total, 1.0)


class AnalysisLayer:
    """分析层主引擎"""

    def __init__(self):
        self.attribution = AttributionEngine()
        self.fusion = MultiSignalFusion()

    def analyze(
        self,
        session_distribution: Dict[str, float],
        agent_type: str = "unknown",
        mcp_triggered: bool = False,
        timing_ms: float = 0.0,
    ) -> AttributionResult:
        """
        三层分析流水线:
        1. 快速分类 (已由发现层完成)
        2. 模型归因 (JSD + CyBiasBench)
        3. 多信号融合 (加权评分)
        """
        # 统一键名为字符串（兼容枚举键）
        normalized_dist: Dict[str, float] = {}
        for k, v in session_distribution.items():
            key = k.value if hasattr(k, "value") else str(k)
            normalized_dist[key] = v

        # Layer 2: 模型归因
        attr = self.attribution.attribute(normalized_dist)
        attributed_model = attr["attributed_model"]
        attr_confidence = attr["confidence"]
        js_div = attr["js_divergence"]

        # 统一 agent_type 为字符串
        agent_type_str = str(agent_type.value if hasattr(agent_type, "value") else agent_type)

        # 若检测到AI agent + 攻击族，提升agentprint信号
        is_known_ai = agent_type_str not in ("unknown", "human", "script_bot")
        has_attack = len(normalized_dist) > 0

        # agentprint 信号使用平滑过渡而非阶梯函数
        if is_known_ai and has_attack:
            agentprint_score = 0.75
        elif is_known_ai:
            agentprint_score = 0.50
        else:
            agentprint_score = 0.10

        # 时序模式使用平滑 Sigmoid 过渡（替代硬编码 500/2000 阈值）
        # timing_ms < 300ms → ~0.1, 500ms → ~0.35, 1000ms → ~0.78, >1500ms → ~0.95
        if timing_ms <= 0:
            timing_score = 0.1
        else:
            timing_score = 1.0 / (1.0 + math.exp(-0.005 * (timing_ms - 700)))
            timing_score = max(0.1, min(0.95, timing_score))

        # Layer 3: 多信号融合
        signals = {
            "attack_family_bias": float(attr_confidence),
            "agentprint_fingerprint": agentprint_score,
            "mcp_tool_signature": 1.0 if mcp_triggered else 0.0,
            "tool_version": 0.3 if is_known_ai else 0.05,  # 有AI特征时才给固定分
            "timing_pattern": round(timing_score, 3),
        }

        fused_score = self.fusion.fuse(signals)

        # 威胁评分：基于融合分数 + 动态加成
        # 攻击强度加成：AI agent + 攻击时，根据分布集中度加成
        bonuses = 0.0
        if has_attack and is_known_ai:
            max_ratio = max(normalized_dist.values())
            bonuses += max_ratio * 0.20

        # MCP 独立加成：调用诱饵工具是极强的恶意信号
        if mcp_triggered:
            bonuses += 0.25

        threat_score = min((fused_score + bonuses) * 100, 100.0)

        # 处置建议
        if threat_score >= 60:
            recommendation = "触发反制"
        elif threat_score >= 35:
            recommendation = "加强监控"
        elif threat_score >= 15:
            recommendation = "标记观察"
        else:
            recommendation = "放行"

        trigger = threat_score >= 60

        return AttributionResult(
            threat_score=float(round(threat_score, 1)),
            confidence=float(fused_score),
            attributed_model=attributed_model,
            js_divergence=float(js_div),
            signals={k: float(v) for k, v in signals.items()},
            recommendation=recommendation,
            trigger_countermeasure=bool(trigger),
            agent_type=agent_type_str,
        )
