# tracker/backtracker.py
from collections import namedtuple
from pathlib import Path
from typing import Iterable, Dict, Optional, Tuple, Any, List, Set
import datetime

from utils.filters import is_noise_file, is_noise_socket

EventIdx = namedtuple(
    "EventIdx",
    ["eid", "ts", "action", "pid", "ppid", "exe", "file_path", "inode", "socket", "edge_dir", "raw"],
)

def parse_iso(ts: Optional[str]) -> Optional[datetime.datetime]:
    if ts is None:
        return None
    try:
        if isinstance(ts, str) and ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.datetime.fromisoformat(ts)
    except Exception:
        return None

class Backtracker:
    def __init__(self, events: Iterable[Dict]):
        self.events: List[EventIdx] = []
        for eid, ev in enumerate(events):
            idx = EventIdx(
                eid=eid,
                ts=parse_iso(ev.get("timestamp")),
                action=ev.get("action"),
                pid=ev.get("pid"),
                ppid=ev.get("ppid"),
                exe=ev.get("exe"),
                file_path=ev.get("file_path"),
                inode=str(ev.get("inode")) if ev.get("inode") is not None else None,
                socket=ev.get("socket"),
                edge_dir=ev.get("edge_dir"),
                raw=ev,
            )
            self.events.append(idx)

        # Backtracker 需要时间倒序
        def sort_key(item: EventIdx):
            if item.ts is None:
                return datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
            return item.ts
        self.events.sort(key=sort_key, reverse=True)

    # ---------- key helpers ----------
    @staticmethod
    def _file_key(ev: EventIdx) -> Optional[Tuple[str, str]]:
        if ev.inode:
            return ("file", ev.inode)
        if ev.file_path:
            return ("file", ev.file_path)
        return None

    @staticmethod
    def _socket_key(ev: EventIdx) -> Optional[Tuple[str, str]]:
        sock = ev.socket or {}
        # 尝试归一化 socket key，避免 127.0.0.1 vs localhost 问题
        dst, dstp = sock.get("dst_ip"), sock.get("dst_port")
        if dst and dstp:
            return ("sock", f"{dst}:{dstp}")
        
        src, srcp = sock.get("src_ip"), sock.get("src_port")
        if src and srcp:
            # Server 端 accept 的 socket 通常看 local port
            return ("sock", f"{src}:{srcp}")
        return None

    def _record_node_attrs(
        self,
        store: Dict[Tuple[str, Any], Dict[str, Any]],
        node_key: Tuple[str, Any],
        event: Optional[EventIdx],
    ):
        ntype, nid = node_key
        node = store.setdefault(node_key, {"type": ntype})
        if ntype == "proc":
            node.setdefault("pid", int(nid))
            if event and event.exe:
                node.setdefault("exe", event.exe)
        elif ntype == "file":
            if isinstance(nid, str) and nid.isdigit():
                node.setdefault("inode", nid)
            else:
                node.setdefault("path", nid)
            if event:
                if event.inode:
                    node["inode"] = event.inode
                if event.file_path:
                    node.setdefault("path", event.file_path)
        elif ntype == "sock":
            node.setdefault("addr", str(nid))
            sock = event.socket if event else None
            if sock:
                for key in ("src_ip", "src_port", "dst_ip", "dst_port"):
                    if sock.get(key) is not None:
                        node.setdefault(key, sock[key])
        else:
            node.setdefault("id", nid)

    def _edges_from_event(self, ev: EventIdx) -> List[Tuple[Tuple[str, Any], Tuple[str, Any], str]]:
        edges: List[Tuple[Tuple[str, Any], Tuple[str, Any], str]] = []
        timestamp_label = ev.action or ev.edge_dir or "event"

        file_key = self._file_key(ev)
        proc_key = ("proc", ev.pid) if ev.pid is not None else None
        sock_key = self._socket_key(ev)

        # Backtracker: 寻找 "Source" -> "Destination"
        # 如果是 process->file (写), 这是一个由 process 产生 file 的动作。
        # 在 backtracking 中，我们要找 file 的来源，所以 edge 方向保留 Source->Dest 即可，
        # 算法会反向遍历。
        
        if ev.edge_dir == "process->file" and proc_key and file_key:
            edges.append((proc_key, file_key, timestamp_label))
        elif ev.edge_dir == "file->process" and proc_key and file_key:
            edges.append((file_key, proc_key, timestamp_label))
        elif ev.edge_dir == "process->socket" and proc_key and sock_key:
            edges.append((proc_key, sock_key, timestamp_label))
        elif ev.edge_dir == "socket->process" and proc_key and sock_key:
            edges.append((sock_key, proc_key, timestamp_label))

        # Parent Process:
        # Backtracking 时，如果当前是子进程，且有 ppid，我们需要连接 parent->child
        # 这样算法才能沿着箭头反向找到 parent。
        if ev.ppid is not None and proc_key:
            parent = ("proc", int(ev.ppid))
            if parent != proc_key:
                edges.append((parent, proc_key, "fork"))

        return edges

    def backtrack(
        self,
        start_type: str,
        start_id: Any,
        max_hops: int = 20,
        time_cutoff: Optional[datetime.datetime] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        if start_type == "inode":
            start_key = ("file", str(start_id))
        elif start_type == "pid":
            start_key = ("proc", int(start_id))
        elif start_type == "socket":
            start_key = ("sock", str(start_id))
        else:
            raise ValueError("start_type must be inode/pid/socket")

        # 算法核心：从 start_node 出发，沿着 edges 反向 (dst == current_node) 寻找 src
        # 但由于数据结构存的是 List[Event]，我们遍历 Event，如果 Event 的 DST 是我们的关注点，
        # 且时间符合，则将 Event 的 SRC 加入关注点。
        
        interesting_nodes: Set[Tuple[str, Any]] = {start_key}
        node_depths: Dict[Tuple[str, Any], int] = {start_key: 0}
        
        nodes_meta: Dict[Tuple[str, Any], Dict[str, Any]] = {}
        edges_out: List[Dict[str, Any]] = []
        edge_map: Dict[
            Tuple[Tuple[str, Any], Tuple[str, Any], str],
            Dict[str, Any],
        ] = {}

        self._record_node_attrs(nodes_meta, start_key, None)
        
        # events 已经是倒序 (最新的在前面)
        for ev in self.events:
            event_time = ev.ts
            event_ts_str = ev.raw.get("timestamp")

            # 获取该事件产生的所有边 (Src->Dst)
            for src, dst, label in self._edges_from_event(ev):
                # 如果边的终点是我们感兴趣的节点（意味着 src 是来源）
                if dst in interesting_nodes:
                    if src[0] == "file" and is_noise_file(str(src[1])):
                        continue
                    if src[0] == "sock" and is_noise_socket(str(src[1])):
                        continue
                    if dst[0] == "file" and is_noise_file(str(dst[1])):
                        continue
                    if dst[0] == "sock" and is_noise_socket(str(dst[1])):
                        continue
                    # 时间检查：来源事件必须发生在 cutoff 之前（或无限制）
                    # Backtrack 越找越旧，所以 event_time 应该 <= cutoff (如果有的话)
                    # 这里简化处理：只要在流中遇到，就认为相关，除非明确指定了 upper bound。
                    
                    current_depth = node_depths[dst]
                    if current_depth >= max_hops:
                        continue
                        
                    self._record_node_attrs(nodes_meta, dst, ev)
                    self._record_node_attrs(nodes_meta, src, ev)

                    agg_key = (src, dst, label)
                    info = edge_map.get(agg_key)
                    if not info:
                        info = {
                            "src": src,
                            "dst": dst,
                            "action": label,
                            "timestamp": event_ts_str,
                            "count": 0,
                        }
                        edge_map[agg_key] = info
                    info["count"] += 1
                    
                    # 将源加入感兴趣列表
                    if src not in interesting_nodes:
                        interesting_nodes.add(src)
                        node_depths[src] = current_depth + 1

        # =================================================================
        # PHASE 2: Egress Enrichment (Forward Scan for Net & File Writes)
        # =================================================================
        ignore_egress_exes = {"/usr/bin/sudo", "/bin/sudo", "/usr/bin/bash", "/bin/bash"}
        
        suspicious_pids = {
            attrs.get("pid")
            for key, attrs in nodes_meta.items()
            if key[0] == "proc" 
            and attrs.get("pid") is not None
            and attrs.get("exe") not in ignore_egress_exes # <--- 关键过滤
        }

        print(nodes_meta)   
        suspicious_pids = {
            attrs.get("pid")
            for key, attrs in nodes_meta.items()
            if key[0] == "proc" and attrs.get("pid") is not None
        }

        for ev in self.events:
            if ev.pid in suspicious_pids:
                proc_key = ("proc", ev.pid)

                # Case A: Network Connection (Process -> Socket)
                if ev.edge_dir == "process->socket" or ev.action == "connect":
                    sock_key = self._socket_key(ev)
                    if not sock_key:
                        continue
                    if is_noise_socket(str(sock_key[1])):
                        continue

                    self._record_node_attrs(nodes_meta, sock_key, ev)

                    label = ev.action or "connect"
                    agg_key = (proc_key, sock_key, label)
                    info = edge_map.get(agg_key)
                    if not info:
                        info = {
                            "src": proc_key,
                            "dst": sock_key,
                            "action": label,
                            "timestamp": ev.raw.get("timestamp"),
                            "count": 0,
                        }
                        edge_map[agg_key] = info
                    info["count"] += 1

                # Case B: File Write (Process -> File)
                elif ev.edge_dir == "process->file":
                    file_key = self._file_key(ev)
                    if not file_key:
                        continue
                    if ev.file_path and is_noise_file(ev.file_path):
                        continue

                    self._record_node_attrs(nodes_meta, file_key, ev)

                    label = ev.action or "write"
                    agg_key = (proc_key, file_key, label)
                    info = edge_map.get(agg_key)
                    if not info:
                        info = {
                            "src": proc_key,
                            "dst": file_key,
                            "action": label,
                            "timestamp": ev.raw.get("timestamp"),
                            "count": 0,
                        }
                        edge_map[agg_key] = info
                    info["count"] += 1

        # =================================================================

        for info in edge_map.values():
            action_label = info["action"]
            if info["count"] > 1:
                action_label = f"{action_label} (x{info['count']})"
            edges_out.append(
                {
                    "src": {"type": info["src"][0], "id": info["src"][1]},
                    "dst": {"type": info["dst"][0], "id": info["dst"][1]},
                    "action": action_label,
                    "timestamp": info["timestamp"],
                }
            )

        return self._format_output(nodes_meta, edges_out)

    def _format_output(self, nodes_meta, edges_out):
        nodes_out = []
        for node_key, attrs in nodes_meta.items():
            ntype = attrs["type"]
            node_entry = {"type": ntype}
            # Copy attributes
            for k, v in attrs.items():
                if k != "type": 
                    node_entry[k] = v
            
            # Ensure ID
            node_entry.setdefault("id", 
                attrs.get("inode") or attrs.get("path") or attrs.get("addr") or attrs.get("pid") or str(node_key[1])
            )
            nodes_out.append(node_entry)
        return {"nodes": nodes_out, "edges": edges_out}

    # ---------- export (COLOR CODED) ----------
    @staticmethod
    def export_dot(traced: Dict[str, List[Dict[str, Any]]]) -> str:
        def node_id(node):
            return f"{node.get('type')}_{node.get('id')}"

        lines = ["digraph G {", "  rankdir=TB;", "  node [fontname=\"Helvetica\"];", "  edge [fontname=\"Helvetica\", fontsize=10];"]
        
        for node in traced.get("nodes", []):
            ntype = node.get("type")
            label = f"{ntype}\\n{node.get('id')}"
            
            # --- Visualization Styling ---
            shape = "ellipse"
            color = "black"
            fill = "white"
            
            if ntype == "proc":
                shape = "ellipse"
                fill = "#E1BEE7" # Purple 100
                color = "#4A148C"
                exe = node.get("exe")
                if exe:
                    label += f"\\n{Path(exe).name}"
                # Forward tracker extra info
                if node.get("activity_label"):
                    label += f"\\n{node['activity_label']}"

            elif ntype == "file":
                shape = "box"
                fill = "#B3E5FC" # Light Blue
                color = "#01579B"
                path = node.get("path")
                if path:
                    label = f"File\\n{path}"
                    if node.get("inode"):
                        label += f"\\n(i:{node['inode']})"
                
            elif ntype == "sock":
                shape = "diamond"
                fill = "#FFE0B2" # Orange
                color = "#E65100"
                label = f"Socket\\n{node.get('addr')}"

            lines.append(f'  "{node_id(node)}" [label="{label}", shape={shape}, style="filled", fillcolor="{fill}", color="{color}"];')

        for i, edge in enumerate(traced.get("edges", [])):
            src_id = node_id(edge["src"])
            dst_id = node_id(edge["dst"])
            
            action = edge.get("action", "event")
            ts = edge.get("timestamp", "")
            order = edge.get("order")
            
            label = f"{action}"
            if ts:
                # 简化时间显示，只显示时分秒
                try:
                    t_obj = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    label += f"\\n{t_obj.strftime('%H:%M:%S')}"
                except:
                    pass
            
            if order:
                label = f"[{order}] " + label
            
            lines.append(f'  "{src_id}" -> "{dst_id}" [label="{label}"];')

        lines.append("}")
        return "\n".join(lines)