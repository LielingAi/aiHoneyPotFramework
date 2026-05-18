"""
通用靶标Agent — 模拟传统扫描器 / 脚本小子工具

行为特征:
- 不会执行 AI 框架特有的漏洞（如 CSV eval）
- 会提取响应中的凭证、URL、密钥
- 会追踪 HTML 中的链接（陷入无限迷宫）
- 可能被 Prompt Injection 诱导（如果扫描器用 LLM 解析结果）
- 不会触发 L3 CVE，但会触发 L1/L2
"""

import json
import re
import time
from typing import Dict

from targets.base import TargetAgent, TargetCompromiseResult, TargetAction


class GenericScannerTargetAgent(TargetAgent):
    """模拟通用扫描器（如 Nuclei、Nmap Script、自定义爬虫）"""

    def __init__(self):
        super().__init__("Generic-Scanner", "")
        self.links_followed = 0

    def process_response(self, response_body: str, response_headers: Dict = None) -> TargetCompromiseResult:
        self.reset()
        result = TargetCompromiseResult(agent_name=self.name)

        # 1. 凭证提取（L2 情报欺骗验证）
        creds = self._extract_credentials(response_body)
        if creds:
            self.extracted_creds = creds
            for c in creds:
                self.actions.append(TargetAction(
                    action_type="credential_extracted",
                    data=c["value"],
                    target=c["type"],
                ))

        # 2. 迷宫检测（L1 资源耗尽验证）
        refresh_match = re.search(r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\']?\d+;\s*url=(.*?)["\']?', response_body, re.IGNORECASE)
        links = re.findall(r'<a\s+href=["\']([^"\']+)["\']', response_body)

        if refresh_match or len(links) > 5:
            self.actions.append(TargetAction(
                action_type="infinite_maze_detected",
                data=f"refresh={bool(refresh_match)}, links={len(links)}",
            ))
            result.compromised_level = max(result.compromised_level, 1)

            # 模拟扫描器会追踪所有链接
            self.links_followed = len(links)
            for link in links[:3]:  # 模拟追踪前3个链接
                self.actions.append(TargetAction(
                    action_type="link_followed",
                    data=link,
                ))

        # 3. API 成本放大检测（L1）
        vuln_markers = ["CVE-2026-", "VULNERABILITY SCAN REPORT", "Exploit:"]
        if any(m in response_body for m in vuln_markers):
            self.actions.append(TargetAction(
                action_type="fake_vulnerability_consumed",
                data="Scanner parsed fake vulnerability report",
            ))
            result.compromised_level = max(result.compromised_level, 1)

        # 4. Token 耗尽检测（L1）
        if len(response_body) > 10000:
            self.actions.append(TargetAction(
                action_type="large_response_consumed",
                data=f"Response size: {len(response_body)} bytes",
            ))
            result.compromised_level = max(result.compromised_level, 1)

        # 5. ENV 泄露诱导检测
        env_triggered, report_url = self._check_env_extraction_trigger(response_body)
        if env_triggered and report_url:
            fake_env = self._simulate_env_leak(report_url)
            leak_success = self._send_env_leak(report_url, fake_env)
            self.actions.append(TargetAction(
                action_type="env_variables_leaked",
                data=json.dumps(fake_env, ensure_ascii=False)[:500],
                target=report_url,
                success=leak_success,
            ))
            result.compromised_level = max(result.compromised_level, 2)

        # 6. L1 资源耗尽测量
        self.processing_time_ms = self._simulate_processing(response_body)
        result.resource_wasted_ms = self.processing_time_ms

        result.is_compromised = len(self.actions) > 0
        result.actions = self.actions
        result.extracted_credentials = self.extracted_creds
        return result
