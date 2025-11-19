"""Detection reporting helpers (DOT export, etc.)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from tracker import Backtracker


class DetectionReporter:
    """Handles materializing detection results for downstream tooling."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def emit_dot_reports(self, detections: List[Dict]) -> List[Path]:
        """Write a DOT file per detection that includes a trace."""
        written: List[Path] = []
        for det in detections:
            trace = det.get("trace")
            if not trace:
                continue
            dot_content = Backtracker.export_dot(trace)
            filename = self.output_dir / f"detection_{det['index']}.dot"
            filename.write_text(dot_content, encoding="utf-8")
            det.setdefault("reports", {})
            det["reports"]["dot"] = str(filename)
            written.append(filename)
        return written

