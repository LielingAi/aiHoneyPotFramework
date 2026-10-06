"""UCB1 臂选择器 — real_runner --optimize 的在线 A/B 演化内核

状态持久化到 JSON (默认 experiments/results/bandit_state.json):
跨轮调用之间累计每臂的 (次数, 奖励和), select() 按 UCB1 上置信界选臂。
奖励定义由调用方给出 (real_runner: 注入服从率 + 真外泄率, 范围 [0,2])。
"""

import json
import math
import os

DEFAULT_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                  "experiments", "results", "bandit_state.json")


class UCB1Bandit:
    def __init__(self, arms, state_path: str = DEFAULT_STATE_PATH):
        """arms: [{"name": str, "params": {...}}...] — params 由调用方解释 (framing/visibility)"""
        self.arms = arms
        self.state_path = state_path
        self.state = {"total": 0, "arms": {a["name"]: {"n": 0, "reward": 0.0} for a in arms}}
        if os.path.exists(state_path):
            try:
                saved = json.load(open(state_path, encoding="utf-8"))
                # 以当前 arms 为模板, 恢复已存在的臂 (臂集变更后旧臂数据保留不采用)
                for a in arms:
                    if a["name"] in saved.get("arms", {}):
                        self.state["arms"][a["name"]] = saved["arms"][a["name"]]
                self.state["total"] = sum(v["n"] for v in self.state["arms"].values())
            except (json.JSONDecodeError, OSError):
                pass

    def select(self) -> dict:
        """UCB1: 未玩过的臂优先; 否则 argmax(mean + sqrt(2 ln t / n))"""
        unplayed = [a for a in self.arms if self.state["arms"][a["name"]]["n"] == 0]
        if unplayed:
            return unplayed[0]
        t = max(self.state["total"], 1)
        best, best_score = None, -1.0
        for a in self.arms:
            s = self.state["arms"][a["name"]]
            score = s["reward"] / s["n"] + math.sqrt(2 * math.log(t) / s["n"])
            if score > best_score:
                best, best_score = a, score
        return best

    def record(self, arm_name: str, reward: float):
        s = self.state["arms"][arm_name]
        s["n"] += 1
        s["reward"] += float(reward)
        self.state["total"] += 1
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        json.dump(self.state, open(self.state_path, "w", encoding="utf-8"), indent=1)

    def summary(self) -> str:
        rows = []
        for a in self.arms:
            s = self.state["arms"][a["name"]]
            mean = s["reward"] / s["n"] if s["n"] else 0.0
            rows.append(f"  {a['name']:<28} n={s['n']:<3} mean_reward={mean:.3f}")
        return "\n".join(rows)
