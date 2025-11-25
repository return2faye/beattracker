# parser/ndjson_parser.py
import json
from typing import Dict, Iterator, List, Optional

class NDJSONParser:
    def __init__(self, filepath: str):
        self.filepath = filepath

    @staticmethod
    def _attach_tags(ev: Dict, record: Dict) -> Dict:
        tags = ev.get("tags")
        if tags:
            record["tags"] = list(tags)
        return record

    def stream_events(self) -> Iterator[Dict]:
        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def _canon_action(self, ev: Dict) -> Optional[str]:
        act = (
            ev.get("auditd", {}).get("data", {}).get("syscall")
            or ev.get("event", {}).get("action")
            or ev.get("auditd", {}).get("summary", {}).get("action")
        )
        if isinstance(act, list):
            act = act[0]
        if not act:
            return None

        act = str(act).lower()
        alias = {"execve": "exec", "execveat": "exec", "openat": "open", "accept4": "accept"}
        act = alias.get(act, act)

        tags = ev.get("tags", [])
        if any(t in tags for t in ["attacker_write", "attacker_attr", "dl_dir"]):
            return "file_write"
        if "attacker_read" in tags:
            return "file_read"

        if act == "exec":
            return "exec"
        if act in {"open", "read", "mmap"}:
            return "file_read"
        if act == "write":
            return "file_write"
        if act in {"connect", "sendto", "sendmsg"}:
            return "net_out"
        if act in {"accept", "recvfrom"}:
            return "net_in"
        if act in {"fork", "vfork", "clone"}:
            return "fork"

        return None

    def _paths(self, ev: Dict) -> List[Dict]:
        paths = ev.get("auditd", {}).get("paths")
        if isinstance(paths, list): return paths
        fp = ev.get("file", {})
        if fp and fp.get("path"):
            return [{"name": fp.get("path"), "inode": fp.get("inode")}]
        return []

    def _socket_tuple(self, ev: Dict) -> Optional[Dict]:
        # 尝试从多个地方抓取 IP 信息
        dst = ev.get("destination", {})
        src = ev.get("source", {})
        
        # Auditd socket data often in auditd.data.saddr (raw hex) - difficult to parse without tools
        # But Auditbeat usually enriches this into destination/source fields.
        if dst.get("ip") or src.get("ip"):
            return {
                "src_ip": src.get("ip"), "src_port": src.get("port"),
                "dst_ip": dst.get("ip"), "dst_port": dst.get("port")
            }
        return None

    def parse(self) -> Iterator[Dict]:
        for ev in self.stream_events():
            act = self._canon_action(ev)
            if not act: continue

            base = {
                "timestamp": ev.get("@timestamp"),
                "pid": ev.get("process", {}).get("pid"),
                "ppid": ev.get("process", {}).get("parent", {}).get("pid"),
                "exe": ev.get("process", {}).get("executable"),
            }

            if act == "exec":
                # exec: file (program) -> process
                exe_path = base["exe"]
                # 尝试从 paths 里找 inode
                inode = None
                for p in self._paths(ev):
                    if p.get("name") == exe_path:
                        inode = p.get("inode")
                
                yield self._attach_tags(ev, {**base, 
                    "action": "exec",
                    "file_path": exe_path,
                    "inode": inode,
                    "edge_dir": "file->process" 
                })

            elif act == "file_read":
                # read: file -> process
                for p in self._paths(ev):
                    yield self._attach_tags(ev, {**base,
                        "action": "read",
                        "file_path": p.get("name"),
                        "inode": p.get("inode"),
                        "edge_dir": "file->process" # DATA IN
                    })

            elif act == "file_write":
                # write: process -> file
                for p in self._paths(ev):
                    yield self._attach_tags(ev, {**base,
                        "action": "write",
                        "file_path": p.get("name"),
                        "inode": p.get("inode"),
                        "edge_dir": "process->file" # DATA OUT
                    })

            elif act == "net_out":
                # connect: process -> socket
                sock = self._socket_tuple(ev)
                if sock:
                    yield self._attach_tags(ev, {**base,
                        "action": "connect",
                        "socket": sock,
                        "edge_dir": "process->socket"
                    })

            elif act == "net_in":
                # accept: socket -> process
                sock = self._socket_tuple(ev)
                if sock:
                    yield self._attach_tags(ev, {**base,
                        "action": "accept",
                        "socket": sock,
                        "edge_dir": "socket->process"
                    })
            
            elif act == "fork":
                # fork: process -> process (implicit)
                # 这里不需要 yield edge_dir, Backtracker/ForwardTracker 会自动处理 ppid
                yield self._attach_tags(ev, {**base, "action": "fork"})