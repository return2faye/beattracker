# parser_test_backtrack.py
import sys
from pathlib import Path

# Allow running this file directly (python parser/parser_test.py)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parser.ndjson_parser import NDJSONParser  # noqa: E402
from tracker import Backtracker  # noqa: E402

DATA_PATH = Path(__file__).resolve().parents[1] / "logs" / "auditbeat-20251031.ndjson"

# 读取并 normalize 全量事件（注意：若日志非常大，改为增量索引或 sqlite）
p = NDJSONParser(str(DATA_PATH))
events = list(p.parse())   # 这里把 parse 的输出全部装内存；若日志太大可改为 streaming->sqlite

bt = Backtracker(events)

# CLI 风格：让用户选择起点
print("Choose start type: 1=inode 2=pid 3=socket")
c = input("choice> ").strip()
if c == "1":
    inode = input("inode> ").strip()
    traced = bt.backtrack("inode", inode, max_hops=5)
elif c == "2":
    pid = int(input("pid> ").strip())
    traced = bt.backtrack("pid", pid, max_hops=5)
else:
    sock = input("sock (ip:port)> ").strip()
    traced = bt.backtrack("socket", sock, max_hops=5)

dot = bt.export_dot(traced)
with open("backtrace_subgraph.dot", "w", encoding="utf-8") as f:
    f.write(dot)
print("Written backtrace_subgraph.dot")
