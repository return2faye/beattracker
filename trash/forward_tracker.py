# tracker/forward_tracker.py
from __future__ import annotations

import datetime
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .backtracker import Backtracker, EventIdx, parse_iso

class ForwardTracker(Backtracker):
    """Track how data flows forward from a suspicious node."""
    
    def __init__(self, events: Iterable[Dict]):
        # 复用 Backtracker 的初始化，但我们需要正序事件
        super().__init__(events)
        # Re-sort to chronological order (Oldest first)
        self.events.sort(key=lambda x: x.ts if x.ts else datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))

        self.parent_map: Dict[int, int] = {}
        self.proc_activity: Dict[int, List[EventIdx]] = defaultdict(list)
        for ev in self.events:
            if ev.pid is not None:
                pid = int(ev.pid)
                self.proc_activity[pid].append(ev)
                if ev.ppid is not None:
                    self.parent_map[pid] = int(ev.ppid)

    def forward(
        self,
        start_type: str,
        start_id: Any,
        *,
        start_timestamp: Optional[str] = None,
        max_hops: int = 20,
        time_cutoff: Optional[datetime.datetime] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        
        # 1. 确定起点
        if start_type == "inode":
            start_key = ("file", str(start_id))
        elif start_type == "pid":
            start_key = ("proc", int(start_id))
        elif start_type == "socket":
            start_key = ("sock", str(start_id))
        else:
            raise ValueError("start_type must be inode/pid/socket")

        start_time_obj = parse_iso(start_timestamp)

        # 2. 初始化状态
        # tainted_nodes: 我们已知的被污染节点集合
        tainted_nodes: Set[Tuple[str, Any]] = {start_key}
        node_depths: Dict[Tuple[str, Any], int] = {start_key: 0}
        
        nodes_meta: Dict[Tuple[str, Any], Dict[str, Any]] = {}
        edges_out: List[Dict[str, Any]] = []
        edges_seen: Set[Tuple] = set()
        
        self._record_node_attrs(nodes_meta, start_key, None)
        self._propagate_parent(
            start_key, tainted_nodes, node_depths, nodes_meta, edges_out, edges_seen, max_hops
        )
        
        # 3. 遍历事件 (正序)
        edge_counter = 1
        
        for ev in self.events:
            event_time = ev.ts
            
            # 4. 时间过滤逻辑 (Critical Fix)
            # 通常我们忽略早于 start_time 的事件。
            # 但是！对于 "Connect" (process->socket) 或 "Fork" (parent->child)，
            # 这些动作建立了一个持久的通道。如果通道在 start_time 之前就建立了，
            # 当进程在 start_time 被污染后，它依然可以通过这个旧通道传数据。
            
            is_persistence_edge = (ev.edge_dir in ["process->socket", "socket->process"]) or (ev.action in ["fork", "clone"])
            
            if start_time_obj and event_time and event_time < start_time_obj:
                if not is_persistence_edge:
                    continue
                # 如果是持久化边，我们继续检查 source 是否已经被污染
            
            if time_cutoff and event_time and event_time > time_cutoff:
                break

            # 5. 检查该事件的所有边
            # 注意：这里不仅是 parse 出来的边，还要看是否隐含父子关系
            current_edges = self._edges_from_event(ev) # 复用 Backtracker 的解析
            
            # 额外：Forward Tracking 中，Fork 代表父进程污染子进程
            # Backtracker 只加了 parent->child (action=fork)，这对 forward 也是适用的
            # (Parent tainted -> Child tainted)
            
            for src, dst, label in current_edges:
                # 核心逻辑：只有当 Source 已经被污染，Taint 才会流向 Dst
                if src not in tainted_nodes:
                    continue
                
                # 防止回流 (例如 Child -> Parent 通常不传播 Taint)
                # Backtracker 的 _edges_from_event 会生成 file->proc (read) 和 proc->file (write)
                # 这里的流向由 parser 的 edge_dir 决定，理论上都是正确的 Taint 流向。
                
                # 深度限制
                next_depth = node_depths[src] + 1
                if next_depth > max_hops:
                    continue
                
                # 记录数据
                self._record_node_attrs(nodes_meta, src, ev)
                self._record_node_attrs(nodes_meta, dst, ev)
                
                edge_key = (src, dst, label, ev.eid)
                if edge_key not in edges_seen:
                    edges_seen.add(edge_key)
                    edges_out.append({
                        "src": {"type": src[0], "id": src[1]},
                        "dst": {"type": dst[0], "id": dst[1]},
                        "action": label,
                        "timestamp": ev.raw.get("timestamp"),
                        "order": edge_counter
                    })
                    edge_counter += 1
                    
                    # 扩散污染
                    if dst not in tainted_nodes:
                        tainted_nodes.add(dst)
                        node_depths[dst] = next_depth
                        self._propagate_parent(
                            dst, tainted_nodes, node_depths, nodes_meta, edges_out, edges_seen, max_hops
                        )

        # 6. 增强显示：给进程节点添加 Activity Label (做了什么坏事)
        for node_key, attrs in nodes_meta.items():
            if attrs["type"] == "proc":
                pid = attrs["pid"]
                # 找一下这个进程在 start_time 之后干了啥
                acts = []
                if pid in self.proc_activity:
                    count = 0
                    for ev in self.proc_activity[pid]:
                        if start_time_obj and ev.ts and ev.ts < start_time_obj:
                            continue
                        # 简单的描述
                        target = ev.file_path or (ev.socket and f"{ev.socket.get('dst_ip')}:{ev.socket.get('dst_port')}") or ""
                        if target:
                            acts.append(f"{ev.action} {Path(str(target)).name}")
                            count += 1
                        if count >= 3: # 只显示前3个动作
                            acts.append("...")
                            break
                if acts:
                    attrs["activity_label"] = "\\n".join(acts)

        return self._format_output(nodes_meta, edges_out)

    def _propagate_parent(
        self,
        child_key: Tuple[str, Any],
        tainted_nodes: Set[Tuple[str, Any]],
        node_depths: Dict[Tuple[str, Any], int],
        nodes_meta: Dict[Tuple[str, Any], Dict[str, Any]],
        edges_out: List[Dict[str, Any]],
        edges_seen: Set[Tuple[Any, ...]],
        max_hops: int,
    ) -> None:
        if child_key[0] != "proc":
            return
        child_pid = int(child_key[1])
        parent_pid = self.parent_map.get(child_pid)
        if parent_pid is None:
            return
        parent_key = ("proc", parent_pid)
        parent_depth = node_depths[child_key] + 1
        if parent_depth > max_hops:
            return

        self._record_node_attrs(nodes_meta, parent_key, None)
        edge_key = (child_key, parent_key, "proc_tree_up", None)
        if edge_key not in edges_seen:
            edges_seen.add(edge_key)
            edges_out.append(
                {
                    "src": {"type": child_key[0], "id": child_key[1]},
                    "dst": {"type": parent_key[0], "id": parent_key[1]},
                    "action": "proc_tree_up",
                    "timestamp": None,
                    "order": None,
                }
            )

        if parent_key not in tainted_nodes:
            tainted_nodes.add(parent_key)
            node_depths[parent_key] = parent_depth
            self._propagate_parent(
                parent_key, tainted_nodes, node_depths, nodes_meta, edges_out, edges_seen, max_hops
            )