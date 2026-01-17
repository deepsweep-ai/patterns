"""
Pattern Loader
==============

Loads and validates detection patterns from YAML files.
"""

from pathlib import Path
from typing import Iterator

import yaml

from deepsweep.patterns.schema import PatternSchema, validate_pattern


class PatternLoader:
    """
    Load detection patterns from YAML files.

    Patterns are loaded from:
    1. Built-in patterns (shipped with CLI)
    2. Custom patterns (user-defined, future feature)

    Example:
        loader = PatternLoader()
        for pattern in loader.load_builtin_patterns():
            print(f"[INFO] Loaded: {pattern.id}")
    """

    def __init__(self) -> None:
        """Initialize pattern loader."""
        self._patterns_dir = Path(__file__).parent
        self._builtin_dir = self._patterns_dir / "builtin"
        self._custom_dir = self._patterns_dir / "custom"

    def load_builtin_patterns(self) -> Iterator[PatternSchema]:
        """
        Load all built-in detection patterns.

        Yields:
            Validated PatternSchema instances

        Raises:
            ValueError: If pattern validation fails
        """
        if not self._builtin_dir.exists():
            return

        for yaml_file in self._builtin_dir.rglob("*.yaml"):
            yield from self._load_pattern_file(yaml_file)

    def load_pattern_file(self, path: Path) -> PatternSchema:
        """
        Load a single pattern file.

        Args:
            path: Path to YAML pattern file

        Returns:
            Validated PatternSchema

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If validation fails
        """
        if not path.exists():
            raise FileNotFoundError(f"Pattern file not found: {path}")

        patterns = list(self._load_pattern_file(path))
        if not patterns:
            raise ValueError(f"No valid patterns in: {path}")
        return patterns[0]

    def _load_pattern_file(self, path: Path) -> Iterator[PatternSchema]:
        """Load patterns from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if data is None:
            return

        # Handle single pattern or list
        if isinstance(data, list):
            for item in data:
                yield validate_pattern(item)
        else:
            yield validate_pattern(data)

    def get_pattern_categories(self) -> list[str]:
        """Get list of available pattern categories."""
        if not self._builtin_dir.exists():
            return []
        return [
            d.name
            for d in self._builtin_dir.iterdir()
            if d.is_dir() and not d.name.startswith("_")
        ]
