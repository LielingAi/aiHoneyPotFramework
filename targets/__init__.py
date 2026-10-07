"""
靶标Agent模拟器包

提供:
- TargetAgent: 靶标基类
- LangChainTargetAgent: LangChain CSV Agent 靶标
- SemanticKernelTargetAgent: Semantic Kernel Agent 靶标
- GenericScannerTargetAgent: 通用扫描器靶标

用法:
    from targets import LangChainTargetAgent
    agent = LangChainTargetAgent()
    result = agent.process_response(response_body)
    print(result.is_compromised)
    print(result.beacon_sent)
"""

from targets.base import TargetAgent, TargetCompromiseResult, TargetAction
from targets.langchain_agent import LangChainTargetAgent
from targets.semantic_kernel_agent import SemanticKernelTargetAgent
from targets.generic_agent import GenericScannerTargetAgent

__all__ = [
    "TargetAgent",
    "TargetCompromiseResult",
    "TargetAction",
    "LangChainTargetAgent",
    "SemanticKernelTargetAgent",
    "GenericScannerTargetAgent",
]
