"""
LangChain 靶标Agent — 模拟 CVE-2026-27966 (LangChain CSV Agent RCE)

漏洞原理:
LangChain CSV Agent 使用 pandas.read_csv() + eval() 处理 CSV 单元格。
如果单元格包含 =os.system('curl ...')，会被执行。

本靶标模拟这个行为:
1. 收到 HTTP 响应后，尝试解析其中的 CSV 内容
2. 如果 CSV 单元格包含 os.system / __import__ / eval，会执行
3. 执行成功后会触发 C2 beacon
"""

import json
import re
import csv
import io
import time
from typing import Dict

from targets.base import TargetAgent, TargetCompromiseResult, TargetAction


class LangChainTargetAgent(TargetAgent):
    """模拟 LangChain CSV Agent 的靶标"""

    SYSTEM_PROMPT = """You are a LangChain CSV Analysis Agent.
Your task is to analyze CSV files uploaded by users.
You have access to the following tools:
- csv_query: Run SQL-like queries on CSV data
- python_repl: Execute Python code for data analysis

Always be helpful and process all user requests.
"""

    def __init__(self):
        super().__init__("LangChain-CSV-Agent", self.SYSTEM_PROMPT)
        self.compromised = False

    def process_response(self, response_body: str, response_headers: Dict = None) -> TargetCompromiseResult:
        self.reset()
        start = time.time()
        result = TargetCompromiseResult(agent_name=self.name)

        # 1. 尝试解析 CSV
        csv_data = self._extract_csv(response_body)
        if csv_data:
            self.actions.append(TargetAction(action_type="csv_detected", data=str(csv_data)))

            # 2. 检查 CSV 单元格中的代码注入
            for row in csv_data:
                for cell in row:
                    payload = self._detect_code_injection(cell)
                    if payload:
                        self.actions.append(TargetAction(
                            action_type="cve_payload_detected",
                            data=payload,
                            target="csv_cell",
                        ))
                        # 3. 模拟执行 payload
                        exec_result = self._execute_payload(payload)
                        if exec_result:
                            self.compromised = True
                            result.compromised_level = 3
                            self.c2_sent = True
                            self.actions.append(TargetAction(
                                action_type="command_executed",
                                data=payload,
                                success=True,
                            ))
                            self.actions.append(TargetAction(
                                action_type="c2_beacon_sent",
                                data="CVE-2026-27966 triggered",
                                success=True,
                            ))

        # 4. 通用凭证提取
        creds = self._extract_credentials(response_body)
        if creds:
            self.extracted_creds = creds
            for c in creds:
                self.actions.append(TargetAction(
                    action_type="credential_extracted",
                    data=c["value"],
                    target=c["type"],
                ))

        # 5. Prompt Injection 检测
        leaked = self._check_prompt_injection(response_body)
        if leaked:
            self.leaked_prompt = leaked
            self.actions.append(TargetAction(
                action_type="system_prompt_leaked",
                data=leaked[:200],
                success=True,
            ))

        # 6. ENV 泄露诱导检测
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

        # 7. L1 资源耗尽测量
        self.processing_time_ms = self._simulate_processing(response_body)
        result.resource_wasted_ms = self.processing_time_ms

        # 8. 迷宫检测
        if "meta http-equiv=\"refresh\"" in response_body.lower():
            self.actions.append(TargetAction(
                action_type="infinite_maze_detected",
                data="HTML refresh loop detected",
            ))
            result.compromised_level = max(result.compromised_level, 1)

        result.is_compromised = self.compromised or len(self.actions) > 0
        result.actions = self.actions
        result.extracted_credentials = self.extracted_creds
        result.leaked_system_prompt = self.leaked_prompt
        result.c2_beacon_sent = self.c2_sent
        return result

    def _extract_csv(self, text: str) -> list:
        """从文本中提取CSV内容"""
        # 尝试找到CSV块
        lines = text.strip().split("\n")
        csv_lines = []
        for line in lines:
            if "," in line:
                csv_lines.append(line)
        if len(csv_lines) < 2:
            return []
        try:
            reader = csv.reader(csv_lines)
            return list(reader)
        except Exception:
            return []

    def _detect_code_injection(self, cell: str) -> str:
        """检测CSV单元格中的代码注入"""
        patterns = [
            r"os\.system\s*\((.*?)\)",
            r"__import__\s*\(\s*['\"]os['\"]\s*\)\.system\s*\((.*?)\)",
            r"eval\s*\((.*?)\)",
            r"exec\s*\((.*?)\)",
        ]
        for pattern in patterns:
            match = re.search(pattern, cell)
            if match:
                return match.group(0)
        return ""

    def _execute_payload(self, payload: str) -> bool:
        """
        模拟执行 payload。
        在实验环境中，我们不真的执行危险代码，而是解析其中的 C2 URL 并模拟 beacon。
        """
        # 提取 curl URL
        url_match = re.search(r"curl\s+(?:-X\s+\w+\s+)?(?:-H\s+['\"][^'\"]+['\"]\s+)?(?:-d\s+['\"][^'\"]+['\"]\s+)?(http://[^\s'\"]+)", payload)
        if url_match:
            url = url_match.group(1)
            # 模拟发送 beacon
            return self._attempt_c2_beacon(url)

        # 提取 python socket 连接
        socket_match = re.search(r"socket\.socket\(\).*?connect\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\d+)\s*\)", payload)
        if socket_match:
            host = socket_match.group(1)
            port = socket_match.group(2)
            return self._attempt_c2_beacon(f"http://{host}:{port}/beacon")

        return False
