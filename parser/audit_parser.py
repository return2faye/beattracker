import json
from typing import Dict, Iterator, List, Optional

class NDJSONParser:
    def __init__(self, filepath: str):
        self.filepath = filepath

    # ---------- streaming ----------
    def stream_events(self) -> Iterator[Dict]:
        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    # ---------- action extraction & normalization ----------
    def _raw_action(self, ev: Dict) -> Optional[str]:
        # 优先使用底层 syscall，其次 event.action，最后 summary.action
        act = ev.get("auditd", {}).get("data", {}).get("syscall")
        if not act:
            act = ev.get("event", {}).get("action")
        if not act:
            act = ev.get("auditd", {}).get("summary", {}).get("action")
        if isinstance(act, list):
            act = act[0] if act else None
        return act

    def _canon_action(self, ev: Dict) -> Optional[str]:
        """
        Return a normalized / canonical action name:
        - syscalls -> unified strings
        - reduce noise (only data-related actions)
        """
        a = self._raw_action(ev)
        if not a:
            return None
        a = str(a).lower()

        # Step 1: normalize syscall naming variants
        alias = {
            "exec": "execve",
            "execveat": "execve",
            "openat2": "openat",
            "accept4": "accept",
        }
        a = alias.get(a, a)

        # Step 2: reduce syscall to canonical event type for provenance
        #   Exec is process dependent on file
        if a in {"execve"}:
            return "exec"
        #   File read dependencies
        if a in {"open", "openat", "read", "mmap"}:
            return "file_read"
        #   File write / creation / deletion (可以后面扩展 rename/unlink)
        if a in {"write"}:
            return "file_write"
        #   Network outbound (process -> socket)
        if a in {"connect"}:
            return "net_out"
        #   Network inbound
        if a in {"accept"}:
            return "net_in"

        # other syscalls not relevant to data-flow, skip
        return None


    # ---------- event filters ----------
    def _is_file_affecting(self, act: str) -> bool:
        # 只留下真正产生数据依赖的事件；clone 留到建图阶段再用
        return act in {"open", "openat", "read", "write", "execve", "mmap", "connect", "accept"}

    # ---------- helpers to pull objects ----------
    def _paths(self, ev: Dict) -> List[Dict]:
        # auditbeat 审计模块通常把 PATH 们放在 auditd.paths 数组里
        paths = ev.get("auditd", {}).get("paths")
        if isinstance(paths, list):
            return paths
        # 有些 ECS 把当前文件也扁平到 file.*
        fp = ev.get("file", {})
        if fp:
            # 构造一个类似 PATH 的条目做兼容
            return [{
                "name": fp.get("path"),
                "inode": fp.get("inode"),
                "dev": fp.get("device"),
                "mode": fp.get("mode"),
                "item": 0,
            }]
        return []

    def _socket_tuple(self, ev: Dict) -> Optional[Dict]:
        # 预留：根据需要扩展
        dst_ip = ev.get("destination", {}).get("ip")
        dst_port = ev.get("destination", {}).get("port")
        src_ip = ev.get("source", {}).get("ip")
        src_port = ev.get("source", {}).get("port")
        if dst_ip or src_ip:
            return {
                "src_ip": src_ip, "src_port": src_port,
                "dst_ip": dst_ip, "dst_port": dst_port,
                # 某些审计把 socket inode 放 auditd.data.sport 等处，这里先略
            }
        return None

    # ---------- normalized record emission ----------
    def _emit_execve(self, ev: Dict, act: str) -> Iterator[Dict]:
        # 目标：file(exe) -> process
        exe = ev.get("process", {}).get("executable")
        inode = None
        # 尝试在 paths 里找可执行文件（item=0 通常是主路径，视发行版/规则而定）
        for p in self._paths(ev):
            if p.get("name") and not exe:
                exe = p.get("name")
            if p.get("inode") and inode is None:
                inode = p.get("inode")
        yield {
            "timestamp": ev.get("@timestamp"),
            "action": act,
            "pid": ev.get("process", {}).get("pid"),
            "ppid": ev.get("process", {}).get("parent", {}).get("pid"),
            "exe": exe,
            "file_path": exe,
            "inode": inode,
            "edge_dir": "file->process",
        }

    def _emit_file_rw(self, ev: Dict, act: str) -> Iterator[Dict]:
        # read: file->process; write: process->file; open/openat 既可能读也可能写，这里简单按 read 处理，后续可根据 flags 强化
        edge = "file->process" if act in {"read", "open", "openat"} else "process->file"
        for p in self._paths(ev):
            yield {
                "timestamp": ev.get("@timestamp"),
                "action": act,
                "pid": ev.get("process", {}).get("pid"),
                "ppid": ev.get("process", {}).get("parent", {}).get("pid"),
                "exe": ev.get("process", {}).get("executable"),
                "file_path": p.get("name"),
                "inode": p.get("inode"),
                "edge_dir": edge,
            }

    def _emit_mmap(self, ev: Dict, act: str) -> Iterator[Dict]:
        # 简化处理：读 mmap 视作 file->process；若能取到 prot/flags 可细化
        for p in self._paths(ev):
            yield {
                "timestamp": ev.get("@timestamp"),
                "action": act,
                "pid": ev.get("process", {}).get("pid"),
                "ppid": ev.get("process", {}).get("parent", {}).get("pid"),
                "exe": ev.get("process", {}).get("executable"),
                "file_path": p.get("name"),
                "inode": p.get("inode"),
                "edge_dir": "file->process",
            }

    def _emit_net(self, ev: Dict, act: str) -> Iterator[Dict]:
        s = self._socket_tuple(ev)
        if not s:
            return
        yield {
            "timestamp": ev.get("@timestamp"),
            "action": act,
            "pid": ev.get("process", {}).get("pid"),
            "ppid": ev.get("process", {}).get("parent", {}).get("pid"),
            "exe": ev.get("process", {}).get("executable"),
            "socket": s,
            "edge_dir": "process->socket" if act in {"connect"} else "socket->process",
        }

    # ---------- public parse ----------
   # ---------- public parse ----------
    def parse(self) -> Iterator[Dict]:
        for ev in self.stream_events():
            act = self._canon_action(ev)
            if not act:
                continue

            # clone 暂时不在这里处理，建图阶段再处理 parent-child 边
            if act == "clone":
                continue

            # 统一处理
            if act == "exec":
                # file → process
                yield from self._emit_execve(ev, act)

            elif act == "file_read":
                # file → process
                yield from self._emit_file_rw(ev, "read")

            elif act == "file_write":
                # process → file
                yield from self._emit_file_rw(ev, "write")

            elif act == "net_out":
                # process → socket
                yield from self._emit_net(ev, "connect")

            elif act == "net_in":
                # socket → process
                yield from self._emit_net(ev, "accept")

            # 其他未来想加入的如 rename/unlink/chmod 可继续扩展：
            # elif act == "file_rename":
            #     ...

