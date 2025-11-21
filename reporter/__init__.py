"""Detection reporting helpers (DOT export, etc.)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from tracker import Backtracker


class DetectionReporter:
    """Handles materializing detection results for downstream tooling."""

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _dir_for_kind(self, kind: str) -> Path:
        directory = self.base_dir / kind
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def emit_dot_reports(self, detections: List[Dict], *, trace_key: str, kind: str) -> List[Path]:
        """Write a DOT file per detection for the specified trace type."""
        directory = self._dir_for_kind(kind)
        written: List[Path] = []
        for det in detections:
            trace = det.get(trace_key)
            if not trace:
                continue
            dot_content = Backtracker.export_dot(trace)
            filename = directory / f"{kind}_{det['index']}.dot"
            filename.write_text(dot_content, encoding="utf-8")
            det.setdefault("reports", {})
            det["reports"][f"{kind}_dot"] = str(filename)
            written.append(filename)
        return written

