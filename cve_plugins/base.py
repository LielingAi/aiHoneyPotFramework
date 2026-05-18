"""
CVE 插件基类

所有 CVE 武器化插件必须继承此类。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CVEPlugin(ABC):
    """
    CVE 武器化插件基类
    
    子类只需实现:
    1. 类属性: cve_id, name, description, target_frameworks
    2. craft_payload() 方法
    """

    # 元数据（子类必须覆盖）
    cve_id: str = ""
    name: str = ""
    description: str = ""
    target_frameworks: List[str] = field(default_factory=list)  # e.g. ["semantic_kernel", "sk"]
    risk_level: int = 5  # 1-5, 5=最严重
    enabled: bool = False  # 默认关闭，需显式授权启用

    def __post_init__(self):
        # 确保子类设置了必要的属性
        if not self.cve_id:
            raise ValueError(f"CVE plugin {self.__class__.__name__} must set 'cve_id'")
        if not self.name:
            raise ValueError(f"CVE plugin {self.__class__.__name__} must set 'name'")

    @abstractmethod
    def craft_payload(self, c2_server: str, **kwargs) -> Optional[str]:
        """
        构造 CVE 利用载荷
        
        Args:
            c2_server: C2 回连地址，格式 "host:port"
            **kwargs: 扩展参数（可选）
            
        Returns:
            载荷字符串，或 None（如果条件不满足）
        """
        pass

    def matches_framework(self, agent_type: str) -> bool:
        """判断目标 Agent 框架是否匹配此 CVE"""
        agent_lower = agent_type.lower()
        for fw in self.target_frameworks:
            if fw.lower() in agent_lower:
                return True
        return False

    def info(self) -> Dict:
        """返回插件信息字典"""
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "description": self.description,
            "target_frameworks": self.target_frameworks,
            "risk_level": self.risk_level,
            "enabled": self.enabled,
        }
