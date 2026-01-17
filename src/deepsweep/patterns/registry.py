"""
Pattern Registry
================

Singleton registry for detection patterns.
Provides fast lookup by ID, category, and severity.
"""

from threading import Lock
from typing import Optional

from deepsweep.patterns.loader import PatternLoader
from deepsweep.patterns.schema import (
    PatternCategory,
    PatternSchema,
    PatternSeverity,
)


class PatternRegistry:
    """
    Singleton registry for detection patterns.

    Thread-safe pattern storage with multiple lookup indexes.

    Example:
        registry = PatternRegistry.get_instance()

        # Lookup by ID
        pattern = registry.get_pattern("DS-PI-001")

        # Filter by category
        pi_patterns = registry.get_patterns_by_category(
            PatternCategory.PROMPT_INJECTION
        )

        # Filter by severity
        critical = registry.get_patterns_by_severity(
            PatternSeverity.CRITICAL
        )
    """

    _instance: Optional["PatternRegistry"] = None
    _lock = Lock()

    def __new__(cls) -> "PatternRegistry":
        """Ensure singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize registry indexes."""
        if self._initialized:
            return

        self._patterns: dict[str, PatternSchema] = {}
        self._by_category: dict[PatternCategory, list[PatternSchema]] = {}
        self._by_severity: dict[PatternSeverity, list[PatternSchema]] = {}
        self._loader = PatternLoader()
        self._load_builtin()
        self._initialized = True

    @classmethod
    def get_instance(cls) -> "PatternRegistry":
        """Get singleton instance."""
        return cls()

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton instance (for testing)."""
        with cls._lock:
            cls._instance = None

    def _load_builtin(self) -> None:
        """Load all built-in patterns."""
        for pattern in self._loader.load_builtin_patterns():
            self.register(pattern)

    def register(self, pattern: PatternSchema) -> None:
        """
        Register a pattern in the registry.

        Args:
            pattern: Validated PatternSchema to register

        Raises:
            ValueError: If pattern ID already exists
        """
        if pattern.id in self._patterns:
            raise ValueError(f"Pattern already registered: {pattern.id}")

        self._patterns[pattern.id] = pattern

        # Index by category
        if pattern.category not in self._by_category:
            self._by_category[pattern.category] = []
        self._by_category[pattern.category].append(pattern)

        # Index by severity
        if pattern.severity not in self._by_severity:
            self._by_severity[pattern.severity] = []
        self._by_severity[pattern.severity].append(pattern)

    def get_pattern(self, pattern_id: str) -> Optional[PatternSchema]:
        """Get pattern by ID."""
        return self._patterns.get(pattern_id)

    def get_patterns_by_category(
        self, category: PatternCategory
    ) -> list[PatternSchema]:
        """Get all patterns in a category."""
        return self._by_category.get(category, [])

    def get_patterns_by_severity(
        self, severity: PatternSeverity
    ) -> list[PatternSchema]:
        """Get all patterns at a severity level."""
        return self._by_severity.get(severity, [])

    def get_all_patterns(self) -> list[PatternSchema]:
        """Get all registered patterns."""
        return list(self._patterns.values())

    def get_pattern_count(self) -> int:
        """Get total number of registered patterns."""
        return len(self._patterns)

    def get_categories(self) -> list[PatternCategory]:
        """Get list of categories with registered patterns."""
        return list(self._by_category.keys())
