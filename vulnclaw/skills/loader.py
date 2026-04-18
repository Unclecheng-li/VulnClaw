"""VulnClaw Skill Loader — load and parse Skill definition files.

Supports two Skill formats:
- Directory format: <skill_name>/SKILL.md + <skill_name>/references/
- Flat file format: <skill_name>.md (legacy, auto-migrated)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnclaw.config.settings import SKILLS_DIR


# ── Built-in skills directory ───────────────────────────────────────

_CORE_SKILLS_DIR = Path(__file__).parent / "core"
_SPECIALIZED_SKILLS_DIR = Path(__file__).parent / "specialized"


def _is_directory_skill(path: Path) -> bool:
    """Check if a path is a directory-format skill (has SKILL.md)."""
    return path.is_dir() and (path / "SKILL.md").exists()


def _is_flat_skill(path: Path) -> bool:
    """Check if a path is a flat-file skill (.md file directly)."""
    return path.is_file() and path.suffix == ".md"


def load_core_skill(name: str) -> Optional[dict[str, Any]]:
    """Load a core skill by name.

    Args:
        name: Skill name, e.g. "pentest-flow"

    Returns:
        Dict with keys: name, description, content, path, references
        Or None if not found.
    """
    # Try directory format first
    skill_dir = _CORE_SKILLS_DIR / name
    if _is_directory_skill(skill_dir):
        return _parse_skill_directory(skill_dir)

    # Fall back to flat file format
    skill_file = _CORE_SKILLS_DIR / f"{name}.md"
    if _is_flat_skill(skill_file):
        return _parse_skill_file(skill_file)

    return None


def load_specialized_skill(name: str) -> Optional[dict[str, Any]]:
    """Load a specialized skill by name."""
    # Try directory format first
    skill_dir = _SPECIALIZED_SKILLS_DIR / name
    if _is_directory_skill(skill_dir):
        return _parse_skill_directory(skill_dir)

    # Fall back to flat file format
    skill_file = _SPECIALIZED_SKILLS_DIR / f"{name}.md"
    if _is_flat_skill(skill_file):
        return _parse_skill_file(skill_file)

    return None


def load_custom_skill(name: str) -> Optional[dict[str, Any]]:
    """Load a user custom skill by name."""
    # Try directory format first
    skill_dir = SKILLS_DIR / name
    if _is_directory_skill(skill_dir):
        return _parse_skill_directory(skill_dir)

    # Fall back to flat file format
    skill_file = SKILLS_DIR / f"{name}.md"
    if _is_flat_skill(skill_file):
        return _parse_skill_file(skill_file)

    return None


def list_core_skills() -> list[str]:
    """List all available core skill names."""
    if not _CORE_SKILLS_DIR.exists():
        return []
    names = set()
    for child in _CORE_SKILLS_DIR.iterdir():
        if _is_directory_skill(child):
            names.add(child.name)
        elif _is_flat_skill(child) and child.suffix == ".md":
            names.add(child.stem)
    return sorted(names)


def list_specialized_skills() -> list[str]:
    """List all available specialized skill names."""
    if not _SPECIALIZED_SKILLS_DIR.exists():
        return []
    names = set()
    for child in _SPECIALIZED_SKILLS_DIR.iterdir():
        if _is_directory_skill(child):
            names.add(child.name)
        elif _is_flat_skill(child) and child.suffix == ".md":
            names.add(child.stem)
    return sorted(names)


def list_custom_skills() -> list[str]:
    """List all available custom skill names."""
    if not SKILLS_DIR.exists():
        return []
    names = set()
    for child in SKILLS_DIR.iterdir():
        if _is_directory_skill(child):
            names.add(child.name)
        elif _is_flat_skill(child) and child.suffix == ".md":
            names.add(child.stem)
    return sorted(names)


def load_skill_by_name(name: str) -> Optional[dict[str, Any]]:
    """Load a skill by name, searching core → specialized → custom."""
    for loader in [load_core_skill, load_specialized_skill, load_custom_skill]:
        result = loader(name)
        if result:
            return result
    return None


def _parse_skill_directory(skill_dir: Path) -> dict[str, Any]:
    """Parse a directory-format skill.

    Directory structure:
        <skill_name>/
        ├── SKILL.md          (required)
        └── references/       (optional)
            ├── ref1.md
            └── ref2.md
    """
    skill_file = skill_dir / "SKILL.md"
    result = _parse_skill_file(skill_file)

    # Collect reference files
    references_dir = skill_dir / "references"
    ref_files: list[str] = []
    if references_dir.exists() and references_dir.is_dir():
        for ref in sorted(references_dir.iterdir()):
            if ref.suffix in (".md", ".yaml", ".yml"):
                ref_files.append(ref.name)

    result["references"] = ref_files
    result["references_dir"] = str(references_dir)
    result["skill_dir"] = str(skill_dir)
    result["format"] = "directory"

    return result


def _parse_skill_file(path: Path) -> dict[str, Any]:
    """Parse a skill markdown file.

    Skill files use a simple format:
    - Optional YAML frontmatter (between --- markers)
    - Markdown body with skill content
    """
    content = path.read_text(encoding="utf-8")
    name = path.stem if path.name != "SKILL.md" else path.parent.name

    # Parse optional frontmatter
    description = ""
    body = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            import yaml
            try:
                frontmatter = yaml.safe_load(parts[1])
                if isinstance(frontmatter, dict):
                    description = frontmatter.get("description", "")
                    name = frontmatter.get("name", name)
            except yaml.YAMLError:
                pass
            body = parts[2].strip()

    return {
        "name": name,
        "description": description,
        "content": body,
        "path": str(path),
        "references": [],
        "references_dir": "",
        "skill_dir": str(path.parent) if path.name == "SKILL.md" else "",
        "format": "directory" if path.name == "SKILL.md" else "flat",
    }


def load_skill_reference(skill_name: str, ref_name: str) -> Optional[str]:
    """Load a reference file from a skill's references directory.

    Args:
        skill_name: The skill name
        ref_name: The reference file name (e.g. "02-client-api-reverse-and-burp.md")

    Returns:
        The reference file content as string, or None if not found.
    """
    skill = load_skill_by_name(skill_name)
    if not skill or not skill.get("references_dir"):
        return None

    ref_path = Path(skill["references_dir"]) / ref_name
    if ref_path.exists() and ref_path.is_file():
        return ref_path.read_text(encoding="utf-8")

    return None
