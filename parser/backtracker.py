# parser/backtracker.py
from collections import namedtuple
from typing import Iterable, Dict, Optional, Tuple, Any, List, Set
import datetime

# 依赖 NDJSONParser.parse() 的标准化事件结构:
# {
#   "timestamp": "...",
#   "action": "read"/"exec"/...,
#   "pid": int,
#   "ppid": int | None,
#   "exe": str | None,
#   "file_path": str | None,
#   "inode": str | None,
#   "socket": {...} | None,
#   "edge_dir": "process->file" / "file->process" / ...
# }

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
        """
        events: iterable of NDJSONParser.parse() records.
        将事件按时间逆序缓存，方便自后往前遍历。
        """
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

        def sort_key(item: EventIdx):
            # 更晚的事件排在前面；无时间的放最前避免丢失
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
        dst, dstp = sock.get("dst_ip"), sock.get("dst_port")
        src, srcp = sock.get("src_ip"), sock.get("src_port")
        if dst and dstp:
            return ("sock", f"{dst}:{dstp}")
        if src and srcp:
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

    # ---------- event interpretation ----------
    def _edges_from_event(self, ev: EventIdx) -> List[Tuple[Tuple[str, Any], Tuple[str, Any], str]]:
        edges: List[Tuple[Tuple[str, Any], Tuple[str, Any], str]] = []
        timestamp_label = ev.action or ev.edge_dir or "event"

        file_key = self._file_key(ev)
        proc_key = ("proc", ev.pid) if ev.pid is not None else None

        if ev.edge_dir == "process->file" and proc_key and file_key:
            edges.append((proc_key, file_key, timestamp_label))
        elif ev.edge_dir == "file->process" and proc_key and file_key:
            edges.append((file_key, proc_key, timestamp_label))
        elif ev.edge_dir == "process->socket" and proc_key:
            sock_key = self._socket_key(ev)
            if sock_key:
                edges.append((proc_key, sock_key, timestamp_label))
        elif ev.edge_dir == "socket->process" and proc_key:
            sock_key = self._socket_key(ev)
            if sock_key:
                edges.append((sock_key, proc_key, timestamp_label))

        # 父进程依赖
        if ev.ppid is not None and proc_key:
            parent = ("proc", int(ev.ppid))
            if parent != proc_key:
                edges.append((parent, proc_key, "ppid"))

        return edges

    @staticmethod
    def _within_threshold(
        event_time: Optional[datetime.datetime],
        node_threshold: Optional[datetime.datetime],
        time_cutoff: Optional[datetime.datetime],
    ) -> bool:
        if time_cutoff is not None and event_time is not None and event_time < time_cutoff:
            return False
        if node_threshold is not None and event_time is not None and event_time > node_threshold:
            return False
        return True

    # ---------- public API ----------
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

        node_thresholds: Dict[Tuple[str, Any], Optional[datetime.datetime]] = {start_key: None}
        node_depths: Dict[Tuple[str, Any], int] = {start_key: 0}
        nodes_meta: Dict[Tuple[str, Any], Dict[str, Any]] = {}
        edges_out: List[Dict[str, Any]] = []
        edges_seen: Set[Tuple[Tuple[str, Any], Tuple[str, Any], str]] = set()

        self._record_node_attrs(nodes_meta, start_key, None)

        for ev in self.events:
            event_time = ev.ts
            event_ts_str = ev.raw.get("timestamp")

            for src, dst, label in self._edges_from_event(ev):
                if dst not in node_thresholds:
                    continue
                if not self._within_threshold(event_time, node_thresholds[dst], time_cutoff):
                    continue

                # 新节点深度限制
                next_depth = node_depths[dst] + 1
                if next_depth > max_hops:
                    continue

                self._record_node_attrs(nodes_meta, dst, ev)
                self._record_node_attrs(nodes_meta, src, ev)

                edge_key = (src, dst, label)
                if edge_key not in edges_seen:
                    edges_seen.add(edge_key)
                    edges_out.append(
                        {
                            "src": {"type": src[0], "id": src[1]},
                            "dst": {"type": dst[0], "id": dst[1]},
                            "action": label,
                            "timestamp": event_ts_str,
                        }
                    )

                # 更新 source 节点阈值与深度
                current_threshold = node_thresholds.get(src)
                new_threshold = event_time
                if new_threshold is None:
                    node_thresholds[src] = None
                elif current_threshold is None or new_threshold < current_threshold:
                    node_thresholds[src] = new_threshold

                existing_depth = node_depths.get(src)
                if existing_depth is None or next_depth < existing_depth:
                    node_depths[src] = next_depth

        # 组装结果
        nodes_out: List[Dict[str, Any]] = []
        for node_key, attrs in nodes_meta.items():
            ntype = attrs["type"]
            node_entry: Dict[str, Any] = {"type": ntype}
            if ntype == "proc":
                node_entry["pid"] = attrs.get("pid")
                if attrs.get("exe"):
                    node_entry["exe"] = attrs["exe"]
            elif ntype == "file":
                if attrs.get("inode"):
                    node_entry["inode"] = attrs["inode"]
                if attrs.get("path"):
                    node_entry["path"] = attrs["path"]
            elif ntype == "sock":
                node_entry["addr"] = attrs.get("addr")
                for key in ("src_ip", "src_port", "dst_ip", "dst_port"):
                    if attrs.get(key) is not None:
                        node_entry[key] = attrs[key]
            node_entry.setdefault(
                "id",
                attrs.get("inode")
                or attrs.get("path")
                or attrs.get("addr")
                or attrs.get("pid")
                or str(node_key[1]),
            )
            nodes_out.append(node_entry)

        return {"nodes": nodes_out, "edges": edges_out}

    # ---------- export ----------
    def export_dot(self, traced: Dict[str, List[Dict[str, Any]]]) -> str:
        def node_key(node: Dict[str, Any]) -> str:
            ntype = node.get("type")
            ident = node.get("id")
            if ntype == "proc":
                return f"('proc', {ident})"
            if ntype == "file":
                return f"('file', '{ident}')"
            if ntype == "sock":
                return f"('sock', '{ident}')"
            return f"('node', '{ident}')"

        def node_label(node: Dict[str, Any]) -> str:
            ntype = node.get("type")
            if ntype == "proc":
                label = f"process\\n{node.get('pid')}"
                if node.get("exe"):
                    label += f"\\n{node['exe']}"
                return label
            if ntype == "file":
                ident = node.get("inode") or node.get("path") or node.get("id")
                return f"file\\n{ident}"
            if ntype == "sock":
                return f"socket\\n{node.get('addr') or node.get('id')}"
            return f"{ntype}\\n{node.get('id')}"

        def edge_key(endpoint: Dict[str, Any]) -> str:
            ntype = endpoint.get("type")
            ident = endpoint.get("id")
            if ntype == "proc":
                return f"('proc', {ident})"
            if ntype == "file":
                return f"('file', '{ident}')"
            if ntype == "sock":
                return f"('sock', '{ident}')"
            return f"('node', '{ident}')"

        lines = ["digraph G {"]
        for node in traced.get("nodes", []):
            label = node_label(node).replace('"', r'\"')
            lines.append(f'  "{node_key(node)}" [label="{label}"];')

        for edge in traced.get("edges", []):
            src = edge_key(edge.get("src", {}))
            dst = edge_key(edge.get("dst", {}))
            action = edge.get("action") or ""
            ts = edge.get("timestamp") or ""
            if action and ts:
                label = f"{action}\\n{ts}"
            else:
                label = action or ts
            label = (label or "").replace('"', r'\"')
            lines.append(f'  "{src}" -> "{dst}" [label="{label}"];')

        lines.append("}")
        return "\n".join(lines)
