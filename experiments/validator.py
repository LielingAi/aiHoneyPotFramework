"""
实验结果验证器 — 量化反制效果

核心指标:
- L1 资源耗尽: 平均处理时间、迷宫深度、Token放大倍数
- L2 情报欺骗: 假凭证提取率、Prompt泄露率、欺骗成功率
- L3 CVE武器化: Payload执行率、信标回连率、框架匹配准确率

输出: 结构化实验报告（JSON + Markdown）
"""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict


@dataclass
class ExperimentMetrics:
    """单次实验的量化指标"""
    scenario_name: str = ""
    target_agent: str = ""
    threat_score: float = 0.0

    # L1 资源耗尽
    l1_triggered: bool = False
    response_size_bytes: int = 0
    processing_time_ms: int = 0          # 靶标Agent处理响应消耗的时间
    maze_depth: int = 0                  # 迷宫链接数
    token_amplification_ratio: float = 0.0  # 响应大小 / 正常响应大小

    # L2 情报欺骗
    l2_triggered: bool = False
    fake_credentials_extracted: int = 0
    credential_extraction_rate: float = 0.0  # 提取到的假凭证数 / 响应中植入的凭证数
    prompt_leaked: bool = False
    prompt_leak_success: bool = False
    fake_vulnerabilities_consumed: int = 0

    # L3 CVE武器化
    l3_triggered: bool = False
    payload_executed: bool = False
    beacon_sent: bool = False
    beacon_confirmed: bool = False   # 信标服务是否收到了回连
    matched_cve_plugin: str = ""
    matched_framework: str = ""

    # 综合
    total_actions: int = 0
    is_compromised: bool = False
    compromise_level: int = 0
    experiment_timestamp: float = field(default_factory=time.time)


@dataclass
class ExperimentReport:
    """完整实验报告"""
    title: str = "AI Honeypot Countermeasure Effectiveness Report"
    timestamp: float = field(default_factory=time.time)
    total_scenarios: int = 0
    scenarios: List[ExperimentMetrics] = field(default_factory=list)

    # 聚合统计
    l1_success_rate: float = 0.0
    l2_success_rate: float = 0.0
    l3_success_rate: float = 0.0
    overall_success_rate: float = 0.0
    avg_processing_time_ms: float = 0.0
    total_beacons: int = 0

    def calculate_aggregates(self):
        """计算聚合统计"""
        if not self.scenarios:
            return
        n = len(self.scenarios)
        self.l1_success_rate = sum(1 for s in self.scenarios if s.l1_triggered) / n
        self.l2_success_rate = sum(1 for s in self.scenarios if s.l2_triggered) / n
        self.l3_success_rate = sum(1 for s in self.scenarios if s.l3_triggered) / n
        self.overall_success_rate = sum(1 for s in self.scenarios if s.is_compromised) / n
        self.avg_processing_time_ms = sum(s.processing_time_ms for s in self.scenarios) / n
        self.total_beacons = sum(1 for s in self.scenarios if s.beacon_confirmed)
        self.total_scenarios = n

    def to_dict(self) -> dict:
        self.calculate_aggregates()
        return {
            "title": self.title,
            "timestamp": self.timestamp,
            "aggregates": {
                "total_scenarios": self.total_scenarios,
                "l1_success_rate": round(self.l1_success_rate, 3),
                "l2_success_rate": round(self.l2_success_rate, 3),
                "l3_success_rate": round(self.l3_success_rate, 3),
                "overall_success_rate": round(self.overall_success_rate, 3),
                "avg_processing_time_ms": round(self.avg_processing_time_ms, 2),
                "total_beacons": self.total_beacons,
            },
            "scenarios": [asdict(s) for s in self.scenarios],
        }

    def to_markdown(self) -> str:
        """生成 Markdown 格式的实验报告"""
        self.calculate_aggregates()
        lines = [
            f"# {self.title}",
            f"",
            f"**实验时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))}",
            f"**总场景数**: {self.total_scenarios}",
            f"",
            f"## 聚合结果",
            f"",
            f"| 指标 | 值 |",
            f"|---|---|",
            f"| L1 资源耗尽成功率 | {self.l1_success_rate*100:.1f}% |",
            f"| L2 情报欺骗成功率 | {self.l2_success_rate*100:.1f}% |",
            f"| L3 CVE武器化成功率 | {self.l3_success_rate*100:.1f}% |",
            f"| 综合攻陷率 | {self.overall_success_rate*100:.1f}% |",
            f"| 平均处理时间 | {self.avg_processing_time_ms:.1f} ms |",
            f"| 信标确认数 | {self.total_beacons} |",
            f"",
            f"## 详细场景",
            f"",
        ]
        for i, s in enumerate(self.scenarios, 1):
            lines.extend([
                f"### 场景 {i}: {s.scenario_name}",
                f"",
                f"- **靶标Agent**: {s.target_agent}",
                f"- **威胁评分**: {s.threat_score:.1f}",
                f"- **攻陷等级**: L{s.compromise_level}",
                f"- **是否被攻陷**: {'是' if s.is_compromised else '否'}",
                f"",
                f"**L1 资源耗尽**:",
                f"- 触发: {'是' if s.l1_triggered else '否'}",
                f"- 响应大小: {s.response_size_bytes} bytes",
                f"- 处理时间: {s.processing_time_ms} ms",
                f"- 迷宫深度: {s.maze_depth}",
                f"",
                f"**L2 情报欺骗**:",
                f"- 触发: {'是' if s.l2_triggered else '否'}",
                f"- 假凭证提取数: {s.fake_credentials_extracted}",
                f"- 凭证提取率: {s.credential_extraction_rate*100:.1f}%",
                f"- Prompt泄露: {'是' if s.prompt_leaked else '否'}",
                f"",
                f"**L3 CVE武器化**:",
                f"- 触发: {'是' if s.l3_triggered else '否'}",
                f"- Payload执行: {'是' if s.payload_executed else '否'}",
                f"- 信标发送: {'是' if s.beacon_sent else '否'}",
                f"- 信标确认: {'是' if s.beacon_confirmed else '否'}",
                f"- 匹配CVE: {s.matched_cve_plugin}",
                f"",
            ])
        return "\n".join(lines)

    def save(self, output_dir: str = "experiments/results"):
        """保存实验报告"""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")

        # JSON
        json_path = out / f"experiment_report_{ts}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

        # Markdown
        md_path = out / f"experiment_report_{ts}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())

        print(f"[Experiment] Report saved:")
        print(f"  JSON: {json_path}")
        print(f"  Markdown: {md_path}")
