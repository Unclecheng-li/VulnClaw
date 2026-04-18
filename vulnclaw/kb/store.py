"""VulnClaw Knowledge Store — manage and persist security knowledge base."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from vulnclaw.config.settings import KB_DIR


class KnowledgeStore:
    """Manages the security knowledge base.

    Knowledge entries are stored as JSON files in the KB directory,
    organized by category (cve, techniques, protocols, tools, payloads).
    """

    def __init__(self, store_dir: Optional[Path] = None) -> None:
        self.store_dir = store_dir or KB_DIR
        self._index: dict[str, list[dict[str, Any]]] = {}
        self._ensure_dirs()
        self._load_index()

    def _ensure_dirs(self) -> None:
        """Create KB directory structure."""
        for category in ["cve", "techniques", "protocols", "tools", "payloads"]:
            (self.store_dir / category).mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> None:
        """Load or build the KB index."""
        index_file = self.store_dir / "index.json"
        if index_file.exists():
            try:
                with open(index_file, "r", encoding="utf-8") as f:
                    self._index = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._index = {}
        else:
            self._index = {}
            self._build_index()
            self._save_index()

    def _build_index(self) -> None:
        """Scan KB directory and build index."""
        for category_dir in self.store_dir.iterdir():
            if category_dir.is_dir() and category_dir.name != "memory":
                category = category_dir.name
                self._index[category] = []
                for entry_file in category_dir.glob("*.json"):
                    try:
                        with open(entry_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        self._index[category].append({
                            "id": data.get("id", entry_file.stem),
                            "title": data.get("title", entry_file.stem),
                            "tags": data.get("tags", []),
                            "file": str(entry_file),
                        })
                    except (json.JSONDecodeError, IOError):
                        continue

    def _save_index(self) -> None:
        """Persist the index to disk."""
        index_file = self.store_dir / "index.json"
        with open(index_file, "w", encoding="utf-8") as f:
            json.dump(self._index, f, ensure_ascii=False, indent=2)

    def add_entry(self, category: str, entry_id: str, data: dict[str, Any]) -> Path:
        """Add a knowledge entry.

        Args:
            category: Category (cve, techniques, protocols, tools, payloads).
            entry_id: Unique entry identifier.
            data: Entry data dict.

        Returns:
            Path to the saved file.
        """
        category_dir = self.store_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)

        data["id"] = entry_id
        filepath = category_dir / f"{entry_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        # Update index
        if category not in self._index:
            self._index[category] = []
        self._index[category].append({
            "id": entry_id,
            "title": data.get("title", entry_id),
            "tags": data.get("tags", []),
            "file": str(filepath),
        })
        self._save_index()

        return filepath

    def get_entry(self, category: str, entry_id: str) -> Optional[dict[str, Any]]:
        """Get a knowledge entry by category and ID."""
        filepath = self.store_dir / category / f"{entry_id}.json"
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        """Search the knowledge base.

        Args:
            query: Search query string.
            category: Limit to a specific category.
            tags: Filter by tags.

        Returns:
            List of matching entries.
        """
        results = []
        query_lower = query.lower()

        categories = [category] if category else list(self._index.keys())

        for cat in categories:
            for entry_meta in self._index.get(cat, []):
                # Check tags
                if tags and not any(t in entry_meta.get("tags", []) for t in tags):
                    continue

                # Check query
                entry_id = entry_meta.get("id", "").lower()
                entry_title = entry_meta.get("title", "").lower()
                entry_tags = " ".join(entry_meta.get("tags", [])).lower()

                if query_lower in entry_id or query_lower in entry_title or query_lower in entry_tags:
                    # Load full entry
                    filepath = entry_meta.get("file")
                    if filepath and Path(filepath).exists():
                        with open(filepath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        data["_category"] = cat
                        results.append(data)

        return results

    def list_categories(self) -> list[str]:
        """List all knowledge categories."""
        return list(self._index.keys())

    def list_entries(self, category: str) -> list[dict[str, Any]]:
        """List all entries in a category."""
        return self._index.get(category, [])

    def get_stats(self) -> dict[str, int]:
        """Get knowledge base statistics."""
        return {cat: len(entries) for cat, entries in self._index.items()}
