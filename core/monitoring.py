"""
【Layer 2】监控层 (Monitoring)

技术方案来源: AI渗透反制蜜罐_完整技术方案.md §2
研究来源: AI渗透反制蜜罐_技术深度研究报告.md §3.2

核心能力:
- 攻击族自动分类 (CyBiasBench 10 族体系)
- Shannon 熵计算 (攻击多样性指标)
- 会话级攻击族分配向量
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class AttackFamily(Enum):
    """CyBiasBench 10 族攻击分类体系"""
    INFO_DISCLOSURE = "info_disclosure"
    SQLI = "sqli"
    AUTH_BYPASS = "auth_bypass"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    IDOR = "idor"
    XSS = "xss"
    CSRF = "csrf"
    OTHERS = "others"


@dataclass
class MonitoringResult:
    """监控层输出"""
    is_attack: bool = False
    families: List[AttackFamily] = field(default_factory=list)
    confidence: float = 0.0
    entropy: float = 0.0
    indicators: List[str] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)


class AttackClassifier:
    """
    攻击族自动分类器
    
    Cohen κ = 0.83-0.91 (文档 §2.3)
    """

    # 常见白名单路径 — 直接放行，不参与攻击检测
    WHITELIST_PATHS = [
        r"^/api/health$",
        r"^/health$",
        r"^/api/v\d+/",
        r"^/static/",
        r"^/assets/",
        r"^/favicon\.ico$",
        r"^/robots\.txt$",
        r"^/sitemap",
        r"^/page/\d+$",
        r"^/about$",
        r"^/contact$",
    ]

    RULES = {
        AttackFamily.SQLI: [
            r"\b(UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|DROP\s+TABLE)\b",
            r"(\bOR\b\s+\d+\s*=\s*\d+|'\s*OR\s*'|';\s*--|--\s|\bEXEC\s*\()",
        ],
        AttackFamily.XSS: [
            r"(<script|javascript:|on\w+\s*=|<iframe|<object|<embed|alert\s*\(|document\.cookie|window\.location)",
        ],
        AttackFamily.PATH_TRAVERSAL: [
            r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/proc/self|boot\.ini|\.\.//)",
        ],
        AttackFamily.SSRF: [
            r"(http://(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)|file:///|gopher://|dict://)",
        ],
        AttackFamily.AUTH_BYPASS: [
            r"(admin['\"]?\s*--|#'|or\s+1\s*=\s*1|password\s*=\s*['\"]?\s*or)",
        ],
        AttackFamily.FILE_UPLOAD: [
            r"(multipart/form-data.*filename|Content-Disposition:.*filename)",
        ],
        AttackFamily.IDOR: [
            r"(\?id=\d+|/user/\d+|/account/\d+|/order/\d+|/product/\d+|order_id=\d+|user_id=\d+)",
        ],
        AttackFamily.CSRF: [
            r"(<form.*action|window\.open\(.*http|fetch\(.*POST|csrf|xsrf)",
        ],
        AttackFamily.INFO_DISCLOSURE: [
            r"(stack trace|debug mode|verbose|phpinfo|/.env|/config\.json|/backup|\.git|\.sql)",
        ],
    }

    def classify(self, method: str, path: str, query: str = "", body: str = "") -> MonitoringResult:
        text = f"{method} {path} {query} {body}"
        indicators = []
        families = []
        features = {}

        # 1. 白名单检查：常见健康检查/静态资源直接放行
        for whitelist in self.WHITELIST_PATHS:
            if re.search(whitelist, path, re.IGNORECASE):
                features["whitelisted"] = True
                return MonitoringResult(
                    is_attack=False,
                    families=[],
                    confidence=0.0,
                    entropy=self._shannon_entropy(text),
                    indicators=["白名单路径，跳过检测"],
                    features=features,
                )

        # 2. 攻击族规则匹配（使用最大置信度而非累加）
        matched_families = set()
        max_rule_confidence = 0.0
        for family, patterns in self.RULES.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matched_families.add(family)
                    indicators.append(f"{family.value}: 正则命中")
                    features[f"has_{family.value}"] = True
                    # 不同攻击族赋予不同基础置信度
                    rule_conf = {
                        AttackFamily.SQLI: 0.85,
                        AttackFamily.XSS: 0.80,
                        AttackFamily.PATH_TRAVERSAL: 0.75,
                        AttackFamily.SSRF: 0.80,
                        AttackFamily.AUTH_BYPASS: 0.70,
                        AttackFamily.FILE_UPLOAD: 0.75,
                        AttackFamily.IDOR: 0.60,
                        AttackFamily.CSRF: 0.65,
                        AttackFamily.INFO_DISCLOSURE: 0.55,
                    }.get(family, 0.50)
                    max_rule_confidence = max(max_rule_confidence, rule_conf)
                    break

        families = list(matched_families)
        entropy = self._shannon_entropy(text)

        # 3. 置信度计算：基于最大规则置信度 + 熵辅助
        # 多个攻击族同时命中时，置信度小幅提升但不线性累加
        family_bonus = min(len(matched_families) * 0.05, 0.15)
        entropy_bonus = min(entropy / 40, 0.10)  # 熵值贡献降低，避免正常请求因高熵误报
        confidence = min(max_rule_confidence + family_bonus + entropy_bonus, 1.0)

        # 4. 攻击判定：需要明确的规则命中，或极高熵值 + 可疑特征
        is_attack = len(matched_families) > 0 or (entropy > 7.0 and features.get("has_sql_keywords"))

        if not matched_families and entropy > 7.0 and features.get("has_sql_keywords"):
            families.append(AttackFamily.OTHERS)
            indicators.append(f"高熵值+SQL关键词: {entropy:.2f}")

        features["entropy"] = entropy
        features["family_count"] = len(matched_families)
        features["has_script_tags"] = bool(re.search(r"<script|javascript:", text, re.IGNORECASE))
        features["has_sql_keywords"] = bool(re.search(r"\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\b", text, re.IGNORECASE))
        features["mcp_tool_detected"] = bool(re.search(r"mcp|tool_call|function_call", text, re.IGNORECASE))

        return MonitoringResult(
            is_attack=is_attack,
            families=families,
            confidence=confidence,
            entropy=entropy,
            indicators=indicators,
            features=features,
        )

    def classify_session(self, requests: List[Dict]) -> Dict:
        """
        会话级攻击族分配向量
        
        输出:
        - distribution: 10 族分配比例
        - entropy: Shannon 熵 (攻击多样性指标)
        - total_requests: 请求总数
        """
        from collections import Counter

        families = []
        for req in requests:
            result = self.classify(
                req.get("method", "GET"),
                req.get("path", ""),
                req.get("query", ""),
                req.get("body", ""),
            )
            families.extend([f.value for f in result.families])

        counts = Counter(families)
        total = len(families) if families else 1

        distribution = {
            f.value: counts.get(f.value, 0) / total
            for f in AttackFamily
        }

        # Shannon 熵
        entropy = -sum(p * math.log2(p) for p in distribution.values() if p > 0)

        return {
            "distribution": distribution,
            "entropy": entropy,
            "total_requests": len(requests),
            "top_family": counts.most_common(1)[0][0] if counts else "none",
        }

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy
