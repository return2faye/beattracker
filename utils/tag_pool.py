"""Tag pool utilities for suspicious event detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Sequence, Set


class TagPool:
    """Simple container for the tags we consider suspicious."""

    def __init__(self, tags: Iterable[str]):
        self._tags: Set[str] = {t.strip() for t in tags if t and t.strip()}

    def __contains__(self, item: str) -> bool:  # pragma: no cover - passthrough
        return item in self._tags

    def __bool__(self) -> bool:
        return bool(self._tags)

    def to_list(self) -> List[str]:
        return sorted(self._tags)

    def match(self, event_tags: Sequence[str] | None) -> Set[str]:
        """Return the subset of event_tags that are in the pool."""
        if not event_tags:
            return set()
        return {t for t in event_tags if t in self._tags}

    @classmethod
    def from_file(cls, path: str | Path) -> "TagPool":
        """Load tags from a JSON file.

        Supported formats:
        - ["tag1", "tag2", ...]
        - {"tags": ["tag1", ...]}
        """
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Tag pool file not found: {file_path}")
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            tags = data.get("tags", [])
        elif isinstance(data, list):
            tags = data
        else:
            raise ValueError("Tag pool JSON must be a list or a dict with 'tags'.")
        return cls(tags)

