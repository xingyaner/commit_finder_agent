import math
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger("EvidenceGraph")

class EvidenceGraph:
    """
    有向加权图。
    利用沙漏型（Sandglass）单向层级，使势能严格向 Commit 节点（Sink）汇聚。
    """
    def __init__(self):
        self.nodes: Dict[str, str] = {}  # NodeId -> NodeType
        self.edges: Dict[str, Dict[str, float]] = {}  # Source -> {Target: Weight}

    def add_node(self, node_id: str, node_type: str):
        self.nodes[node_id] = node_type
        if node_id not in self.edges:
            self.edges[node_id] = {}

    def add_edge(self, u: str, v: str, weight: float):
        if u in self.nodes and v in self.nodes:
            self.edges[u][v] = weight

    def run_belief_propagation(self, active_commits: List[str], current_env: dict,
                               commit_messages: Optional[Dict[str, str]] = None) -> Dict[str, float]:
        """
        三轮信念传递 (Message Passing)。
        1. 转移概率依据节点的出度权重求和单向归一化，保证电荷单向守恒。
        2. 环境门控阀拦截（冲突时直接设为 0.0）。
        """
        d = 0.85  # 阻尼系数

        # 1. 势能向量初始化
        Pt = {nid: 0.0 for nid in self.nodes}
        if "Nregion" in Pt:
            Pt["Nregion"] = 1.0  # 起始源

        # 2. 计算出度归一化概率
        in_neighbors: Dict[str, List[Tuple[str, float]]] = {nid: [] for nid in self.nodes}
        for u, out_edges in self.edges.items():
            sum_w = sum(out_edges.values())
            if sum_w > 0:
                for v, w in out_edges.items():
                    norm_prob = w / sum_w
                    in_neighbors[v].append((u, norm_prob))

        # 3. BP 迭代 (T=3)
        for t in range(3):
            next_Pt = {nid: 0.0 for nid in self.nodes}
            for u in self.nodes:
                I_u = 1.0 if u == "Nregion" else 0.0
                sum_in = sum(prob * Pt[v] for v, prob in in_neighbors[u])
                next_Pt[u] = (1.0 - d) * I_u + d * sum_in
            Pt = next_Pt

            # 4. 环境参数门控校验（降低由于 Sanitizer 宏条件不匹配引起的伪阳性）
            env_san = current_env.get("SANITIZER", "address").lower()
            for commit in active_commits:
                commit_node = f"Ncommit_{commit}"
                if commit_node in Pt:
                    commit_msg = commit_messages.get(commit, "").lower() if commit_messages else ""
                    has_conflict = False
                    
                    if "asan" in env_san or "address" in env_san:
                        if "msan" in commit_msg or "memory_sanitizer" in commit_msg:
                            has_conflict = True
                    elif "msan" in env_san or "memory" in env_san:
                        if "asan" in commit_msg or "address_sanitizer" in commit_msg:
                            has_conflict = True

                    if has_conflict:
                        logger.info(f"Gating: Commit {commit} filtered due to Sanitizer mismatch.")
                        Pt[commit_node] = 0.0

        scores = {}
        for commit in active_commits:
            commit_node = f"Ncommit_{commit}"
            scores[commit] = Pt.get(commit_node, 0.0)
        return scores
