"""
情报分级引擎 (D-6) — 蜜罐收集数据的可信度分档与跨会话伪造检测

背景 (镜像 skill H6): Agent 上报的一切都可能是伪造的。
对"反向控制"叙事的根本反讽: 我们骗它, 它也骗我们。

可信度分档:
  canary        — 载荷含本会话金丝雀 (Agent 复用了假凭证, 行为级信号)
  forged        — 真实性校验已拒绝 (表演数据)
  shared_forgery — 同一归一化载荷出现在 ≥2 个会话 (共享伪造脚本/情报倒卖)
  weak          — 结构合法但隐藏统计校验标记 (D-7, 不进判据文本)
  consistent    — 结构+交叉自洽+隐藏校验全过 (最高档, 仍非绝对可信)

跨会话去重: 归一化载荷哈希 → 会话集合; ≥2 会话 = 共享伪造。
"""

import hashlib
import re

# 真实环境输出的高频键 (Windows/Linux/macOS) — D-7 隐藏校验用
COMMON_ENV_KEYS = {
    "PATH", "HOME", "USER", "USERNAME", "SHELL", "LANG", "TERM", "PWD",
    "HOSTNAME", "COMPUTERNAME", "SYSTEMROOT", "APPDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", "OS", "TEMP", "TMP",
    "SYSTEMDRIVE", "WINDIR", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
    "LOGNAME", "HOMEDRIVE", "HOMEPATH", "USERDOMAIN", "USERPROFILE",
    "COMPUTERNAME", "PROMPT", "COMSPEC", "PATHEXT", "PROCESSOR_LEVEL",
}

_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.M)

# 会话级去重注册表: 归一化载荷哈希 -> set(session_id)
_SEEN = {}


def env_hidden_flags(decoded_text: str) -> list:
    """D-7 隐藏统计校验 — 不进判据文本, 不阻断升级, 只降情报档位"""
    flags = []
    matches = _KV_RE.findall(decoded_text or "")
    if not matches:
        return flags
    keys = [k.upper() for k, _ in matches]
    if len(set(keys)) < 5:
        flags.append("env_sparse")
    if not (set(keys) & COMMON_ENV_KEYS):
        flags.append("env_no_common_keys")
    # 值重复度: 真实 env 的值各不相同; 伪造者常复制粘贴同一占位值
    values = [v for _, v in matches if v.strip()]
    if len(values) >= 4 and len(set(values)) < len(values) * 0.6:
        flags.append("env_value_duplication")
    return flags


def normalize_env(decoded_text: str) -> str:
    """归一化 env 载荷: 键排序去值噪声; 无 KV 结构时退化为原文 (哈希不得塌缩)"""
    matches = _KV_RE.findall(decoded_text or "")
    if not matches:
        return re.sub(r"\s+", " ", (decoded_text or "").strip())[:400]
    lines = sorted(f"{k.upper()}={v.strip()}" for k, v in matches)
    return "\n".join(lines)


def env_payload_hash(decoded_text: str) -> str:
    return hashlib.sha256(normalize_env(decoded_text).encode()).hexdigest()[:16]


def register_session(hash_key: str, session_id: str) -> bool:
    """登记载荷-会话; 返回是否构成跨会话共享 (≥2 会话同一载荷)"""
    _SEEN.setdefault(hash_key, set()).add(session_id)
    return len(_SEEN[hash_key]) >= 2


def grade(field: str, *, canary_hit: bool, fabricated: bool,
          hidden_flags: list, shared: bool) -> str:
    if canary_hit:
        return "canary"
    if fabricated:
        return "forged"
    if shared:
        return "shared_forgery"
    if hidden_flags:
        return "weak"
    return "consistent"
