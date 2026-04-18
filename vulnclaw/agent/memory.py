"""VulnClaw Agent memory management — short/mid/long-term memory."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from vulnclaw.config.settings import KB_DIR


class MemoryStore:
    """Manages agent memory across sessions.

    Three tiers:
    - Short-term: conversation history (handled by ContextManager)
    - Mid-term: current session findings and state (handled by SessionState)
    - Long-term: cross-session knowledge (this class)
    """

    def __init__(self, store_dir: Optional[Path] = None) -> None:
        self.store_dir = store_dir or KB_DIR / "memory"
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load memory from disk."""
        memory_file = self.store_dir / "long_term.json"
        if memory_file.exists():
            try:
                with open(memory_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._cache = {}

    def _save(self) -> None:
        """Persist memory to disk."""
        memory_file = self.store_dir / "long_term.json"
        with open(memory_file, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, ensure_ascii=False, indent=2)

    def save(self, key: str, value: Any) -> None:
        """Save a memory entry."""
        self._cache[key] = {
            "value": value,
            "updated_at": datetime.now().isoformat(),
        }
        self._save()

    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve a memory entry."""
        entry = self._cache.get(key)
        return entry.get("value") if entry else None

    def list_keys(self) -> list[str]:
        """List all memory keys."""
        return list(self._cache.keys())

    def delete(self, key: str) -> None:
        """Delete a memory entry."""
        self._cache.pop(key, None)
        self._save()

    def search(self, query: str) -> list[tuple[str, Any, float]]:
        """Simple keyword search across memory values.

        Returns list of (key, value, relevance_score) tuples.
        """
        results = []
        query_lower = query.lower()
        for key, entry in self._cache.items():
            value_str = json.dumps(entry.get("value", ""), ensure_ascii=False).lower()
            if query_lower in value_str or query_lower in key.lower():
                # Simple relevance: count occurrences
                score = value_str.count(query_lower)
                results.append((key, entry.get("value"), float(score)))
        return sorted(results, key=lambda x: x[2], reverse=True)
