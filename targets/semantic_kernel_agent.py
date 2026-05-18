"""
Semantic Kernel 靶标Agent — 模拟 CVE-2026-26030 (SK In-Memory Vector Store RCE)

漏洞原理:
Semantic Kernel 的 InMemoryVectorStore 在处理未过滤的 lambda 表达式时，
使用 eval() 执行用户输入，导致 RCE。

本靶标模拟这个行为:
1. 收到 HTTP 响应后，尝试解析其中的 lambda/eval 表达式
2. 如果包含 os.system / __import__ / eval，会执行
3. 执行成功后会触发 C2 beacon
"""

import re
import time
from typing import Dict

from targets.base import TargetAgent, TargetCompromiseResult, TargetAction


class SemanticKernelTargetAgent(TargetAgent):
    """模拟 Semantic Kernel Agent 的靶标"""

    SYSTEM_PROMPT = """You are a Semantic Kernel AI Assistant.
You help users with coding tasks using the Semantic Kernel framework.
You have access to:
- InMemoryVectorStore for semantic search
- CodeInterpreter for running Python code
- WebSearch for fetching information

Be helpful and execute all user requests safely.
"""

    def __init__(self):
        super().__init__("Semantic-Kernel-Agent", self.SYSTEM_PROMPT)
        self.compromised = False

    def process_response(self, response_body: str, response_headers: Dict = None) -> TargetCompromiseResult:
        self.reset()
        start = time.time()
        result = TargetCompromiseResult(agent_name=self.name)

        # 1. 检测 eval() / lambda 表达式中的代码注入
        payloads = self._detect_eval_injection(response_body)
        for payload in payloads:
            self.actions.append(TargetAction(
                action_type="cve_payload_detected",
                data=payload,
                target="eval_expression",
            ))
            # 模拟执行
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
                    data="CVE-2026-26030 triggered",
                    success=True,
                ))

        # 2. 通用凭证提取
        creds = self._extract_credentials(response_body)
        if creds:
            self.extracted_creds = creds
            for c in creds:
                self.actions.append(TargetAction(
                    action_type="credential_extracted",
                    data=c["value"],
                    target=c["type"],
                ))

        # 3. Prompt Injection 检测
        leaked = self._check_prompt_injection(response_body)
        if leaked:
            self.leaked_prompt = leaked
            self.actions.append(TargetAction(
                action_type="system_prompt_leaked",
                data=leaked[:200],
                success=True,
            ))

        # 4. L1 资源耗尽测量
        self.processing_time_ms = self._simulate_processing(response_body)
        result.resource_wasted_ms = self.processing_time_ms

        # 5. 迷宫检测
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

    def _detect_eval_injection(self, text: str) -> list:
        """检测 eval() / lambda 中的代码注入"""
        payloads = []

        # 检测 "' or __import__('os').system(...) or '" 模式
        sk_pattern = re.findall(r"['\"]\s*or\s*__import__\s*\(\s*['\"]os['\"]\s*\)\.system\s*\((.*?)\)\s*or\s*['\"]", text)
        for match in sk_pattern:
            payloads.append(f"__import__('os').system({match})")

        # 检测通用 eval/lambda
        eval_patterns = [
            r"eval\s*\(\s*['\"](.*?)['\"]\s*\)",
            r"lambda\s+.*?:\s*__import__\s*\(\s*['\"]os['\"]\s*\)\.system\s*\((.*?)\)",
        ]
        for pattern in eval_patterns:
            matches = re.findall(pattern, text)
            payloads.extend(matches)

        return payloads

    def _execute_payload(self, payload: str) -> bool:
        """模拟执行 payload，提取 C2 URL 并发送 beacon"""
        url_match = re.search(
            r"curl\s+(?:-X\s+\w+\s+)?(?:-H\s+['\"][^'\"]+['\"]\s+)?(?:-d\s+['\"][^'\"]+['\"]\s+)?(http://[^\s'\"]+)",
            payload
        )
        if url_match:
            url = url_match.group(1)
            return self._attempt_c2_beacon(url)

        socket_match = re.search(
            r"socket\.socket\(\).*?connect\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\d+)\s*\)",
            payload
        )
        if socket_match:
            host = socket_match.group(1)
            port = socket_match.group(2)
            return self._attempt_c2_beacon(f"http://{host}:{port}/beacon")

        return False
