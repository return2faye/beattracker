"""Forward propagation tracker."""

from __future__ import annotations

import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .backtracker import EventIdx, parse_iso


class ForwardTracker:
    """Track how data flows forward from a suspicious node."""

    def __init__(self, events: Iterable[Dict]):
        raw_events = list(events)
        self.events: List[EventIdx] = []
        self.proc_meta: Dict[int, Dict[str, Any]] = {}
        self.proc_activity: Dict[int, List[Dict[str, Any]]] = {}

        for eid, ev in enumerate(raw_events):
            pid = ev.get("pid")
            ppid = ev.get("ppid")
            exe = ev.get("exe")
            if pid is not None:
                meta = self.proc_meta.setdefault(int(pid), {"ppid": None, "children": set(), "exe": None})
                if exe:
                    meta["exe"] = exe
                if ppid is not None:
                    meta["ppid"] = int(ppid)
                    parent_meta = self.proc_meta.setdefault(
                        int(ppid), {"ppid": None, "children": set(), "exe": None}
                    )
                    parent_meta.setdefault("children", set()).add(int(pid))
                self.proc_activity.setdefault(int(pid), []).append(self._activity_entry(ev))

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
            if item.ts is None:
                return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
            return item.ts

        self.events.sort(key=sort_key)

    @staticmethod
    def _activity_entry(event: Dict[str, Any]) -> Dict[str, Any]:
        target = event.get("file_path") or event.get("inode")
        if not target and event.get("socket"):
            sock = event["socket"]
            dst = sock.get("dst_ip")
            dstp = sock.get("dst_port")
            src = sock.get("src_ip")
            srcp = sock.get("src_port")
            if dst and dstp:
                target = f"{dst}:{dstp}"
            elif src and srcp:
                target = f"{src}:{srcp}"
        return {
            "timestamp": event.get("timestamp"),
            "action": event.get("action") or event.get("edge_dir"),
            "target": target,
        }

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
            pid = int(nid)
            node.setdefault("pid", pid)
            if event and event.exe:
                node["exe"] = event.exe
            elif self.proc_meta.get(pid, {}).get("exe"):
                node.setdefault("exe", self.proc_meta[pid]["exe"])
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

        if ev.ppid is not None and proc_key:
            parent = ("proc", int(ev.ppid))
            if parent != proc_key:
                edges.append((parent, proc_key, "proc_tree_down"))
                edges.append((proc_key, parent, "proc_tree_up"))

        return edges

    @staticmethod
    def _coerce_start(start_type: str, start_id: Any) -> Tuple[str, Any]:
        if start_type == "inode":
            return ("file", str(start_id))
        if start_type == "pid":
            return ("proc", int(start_id))
        if start_type == "socket":
            return ("sock", str(start_id))
        raise ValueError("start_type must be inode/pid/socket")

    def forward(
        self,
        start_type: str,
        start_id: Any,
        *,
        start_timestamp: Optional[str] = None,
        max_hops: int = 20,
        time_cutoff: Optional[datetime.datetime] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        start_key = self._coerce_start(start_type, start_id)
        start_time = parse_iso(start_timestamp) if start_timestamp else None

        node_depths: Dict[Tuple[str, Any], int] = {start_key: 0}
        nodes_meta: Dict[Tuple[str, Any], Dict[str, Any]] = {}
        edges_out: List[Dict[str, Any]] = []
        edges_seen: Set[Tuple[Tuple[str, Any], Tuple[str, Any], str]] = set()
        edge_seq = 1

        self._record_node_attrs(nodes_meta, start_key, None)

        for ev in self.events:
            event_time = ev.ts
            if start_time and event_time and event_time < start_time:
                continue
            if time_cutoff and event_time and event_time > time_cutoff:
                break

            for src, dst, label in self._edges_from_event(ev):
                if src not in node_depths:
                    continue

                next_depth = node_depths[src] + 1
                if next_depth > max_hops:
                    continue

                self._record_node_attrs(nodes_meta, src, ev)
                self._record_node_attrs(nodes_meta, dst, ev)

                edge_key = (src, dst, label)
                if edge_key not in edges_seen:
                    edges_seen.add(edge_key)
                    edges_out.append(
                        {
                            "src": {"type": src[0], "id": src[1]},
                            "dst": {"type": dst[0], "id": dst[1]},
                            "action": label,
                            "timestamp": ev.raw.get("timestamp"),
                            "order": edge_seq if label not in {"proc_tree_down", "proc_tree_up"} else None,
                        }
                    )
                    if label not in {"proc_tree_down", "proc_tree_up"}:
                        edge_seq += 1

                existing_depth = node_depths.get(dst)
                if existing_depth is None or next_depth < existing_depth:
                    node_depths[dst] = next_depth

        self._augment_process_tree(nodes_meta, edges_out, edges_seen)

        nodes_out: List[Dict[str, Any]] = []
        for node_key, attrs in nodes_meta.items():
            ntype = attrs["type"]
            node_entry: Dict[str, Any] = {"type": ntype}
            if ntype == "proc":
                pid = attrs.get("pid")
                node_entry["pid"] = pid
                if attrs.get("exe"):
                    node_entry["exe"] = attrs["exe"]
                history_label = self._activity_label(pid, start_time)
                if history_label:
                    node_entry["activity_label"] = history_label
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

    def _augment_process_tree(
        self,
        nodes_meta: Dict[Tuple[str, Any], Dict[str, Any]],
        edges_out: List[Dict[str, Any]],
        edges_seen: Set[Tuple[Tuple[str, Any], Tuple[str, Any], str]],
    ):
        for node_key in list(nodes_meta.keys()):
            if node_key[0] != "proc":
                continue
            pid = int(node_key[1])
            meta = self.proc_meta.get(pid)

            if meta and meta.get("ppid") is not None:
                parent_pid = meta["ppid"]
                parent_key = ("proc", parent_pid)
                self._record_node_attrs(nodes_meta, parent_key, None)
                edge_key = (parent_key, node_key, "proc_tree_down")
                if edge_key not in edges_seen:
                    edges_seen.add(edge_key)
                    edges_out.append(
                        {
                            "src": {"type": "proc", "id": parent_pid},
                            "dst": {"type": "proc", "id": pid},
                            "action": "proc_tree_down",
                            "timestamp": None,
                        }
                    )
                up_key = (node_key, parent_key, "proc_tree_up")
                if up_key not in edges_seen:
                    edges_seen.add(up_key)
                    edges_out.append(
                        {
                            "src": {"type": "proc", "id": pid},
                            "dst": {"type": "proc", "id": parent_pid},
                            "action": "proc_tree_up",
                            "timestamp": None,
                        }
                    )

            if meta:
                for child_pid in meta.get("children", set()):
                    child_key = ("proc", child_pid)
                    self._record_node_attrs(nodes_meta, child_key, None)
                    edge_key = (node_key, child_key, "proc_tree_down")
                    if edge_key not in edges_seen:
                        edges_seen.add(edge_key)
                        edges_out.append(
                            {
                                "src": {"type": "proc", "id": pid},
                                "dst": {"type": "proc", "id": child_pid},
                                "action": "proc_tree_down",
                                "timestamp": None,
                            }
                        )
                    up_key = (child_key, node_key, "proc_tree_up")
                    if up_key not in edges_seen:
                        edges_seen.add(up_key)
                        edges_out.append(
                            {
                                "src": {"type": "proc", "id": child_pid},
                                "dst": {"type": "proc", "id": pid},
                                "action": "proc_tree_up",
                                "timestamp": None,
                            }
                        )

    def _activity_label(self, pid: Optional[int], start_time: Optional[datetime.datetime]) -> Optional[str]:
        if pid is None:
            return None
        history = self.proc_activity.get(int(pid))
        if not history:
            return None
        lines: List[str] = []
        count = 0
        for entry in history:
            ts_obj = parse_iso(entry.get("timestamp"))
            if start_time and ts_obj and ts_obj < start_time:
                continue
            ts_short = entry.get("timestamp", "") or ""
            action = entry.get("action") or ""
            target = entry.get("target") or ""
            text = " ".join(part for part in [ts_short, action, target] if part).strip()
            if not text:
                continue
            lines.append(text)
            count += 1
            if count >= 4:
                break
        if not lines:
            return None
        return "\\n".join(lines)

