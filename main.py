"""Entry point for automated suspicious event detection and tracing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from parser import NDJSONParser
from reporter import DetectionReporter
from tracker import Backtracker
from utils.tag_pool import TagPool

DEFAULT_LOG_FILE = "logs/auditbeat-20251125.ndjson"
DEFAULT_TAG_POOL = "config/tag_pool.json"
DEFAULT_REPORT_DIR = Path("reports")
DEFAULT_MAX_HOPS = 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit log analyzer (minimal CLI, defaults from config)."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default=DEFAULT_LOG_FILE,
        help=f"NDJSON log file to scan (default: {DEFAULT_LOG_FILE}).",
    )
    return parser.parse_args()


def choose_start_node(event: Dict[str, Any]) -> Optional[Tuple[str, Any]]:
    """Infer the best backtracker start node from a normalized event."""
    pid = event.get("pid")
    if pid is not None:
        return ("pid", int(pid))
    socket = event.get("socket")
    if socket:
        addr = socket.get("dst_ip") or socket.get("src_ip")
        port = socket.get("dst_port") or socket.get("src_port")
        if addr and port:
            return ("socket", f"{addr}:{port}")
    inode = event.get("inode")
    if inode:
        return ("inode", str(inode))
    return None


def detect_suspicious_events(events: Sequence[Dict[str, Any]], tag_pool: TagPool) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    for idx, ev in enumerate(events):
        matched = tag_pool.match(ev.get("tags"))
        if not matched:
            continue
        detections.append(
            {
                "index": idx,
                "matched_tags": sorted(matched),
                "event": ev,
            }
        )
    return detections


def run_backtracker(events: Sequence[Dict[str, Any]], detections: List[Dict[str, Any]], max_hops: int) -> None:
    if not detections:
        return
    tracker = Backtracker(events)
    for detection in detections:
        event = detection["event"]
        start = choose_start_node(event)
        if not start:
            detection["backtrack_error"] = "Unable to infer start node"
            continue
        start_type, start_id = start
        detection["backtrack_start"] = {"type": start_type, "id": start_id}
        detection["trace"] = tracker.backtrack(start_type, start_id, max_hops=max_hops)


def save_results(detections: List[Dict[str, Any]], path: Path) -> None:
    payload = {
        "detections": detections,
        "total": len(detections),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()
    tag_pool = TagPool.from_file(DEFAULT_TAG_POOL)
    if not tag_pool:
        raise SystemExit("Tag pool is empty; nothing to detect.")

    ndjson_parser = NDJSONParser(args.log_file)
    events = list(ndjson_parser.parse())
    if not events:
        raise SystemExit("No events parsed from log file.")

    detections = detect_suspicious_events(events, tag_pool)
    run_backtracker(events, detections, max_hops=DEFAULT_MAX_HOPS)
    reporter = DetectionReporter(DEFAULT_REPORT_DIR)
    reporter.emit_dot_reports(detections, trace_key="trace", kind="backward")

    results_path = DEFAULT_REPORT_DIR / "detections.json"
    save_results(detections, results_path)

    # Human-friendly console output
    if not detections:
        print("No suspicious events matched the current tag pool.")
        print(f"Summary written to {results_path}")
        return

    print(f"Detected {len(detections)} suspicious event(s):")
    for det in detections:
        tags = ", ".join(det["matched_tags"])
        ts = det["event"].get("timestamp")
        action = det["event"].get("action")
        print(f"- idx={det['index']} tags=[{tags}] ts={ts} action={action}")
        if "backtrack_start" in det:
            start = det["backtrack_start"]
            print(f"  backtrack start: {start['type']} -> {start['id']}")
        if det.get("trace"):
            nodes = len(det["trace"].get("nodes", []))
            edges = len(det["trace"].get("edges", []))
            print(f"  trace: {nodes} nodes, {edges} edges")
        reports = det.get("reports") or {}
        if reports.get("backward_dot"):
            print(f"  backward dot: {reports['backward_dot']}")
        if det.get("backtrack_error"):
            print(f"  backtrack error: {det['backtrack_error']}")

    print(f"Summary written to {results_path}")


if __name__ == "__main__":
    main()

