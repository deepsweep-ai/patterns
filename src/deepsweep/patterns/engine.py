"""
Pattern Detection Engine
========================

Executes detection patterns against target files.
Integrates with existing DeepSweep validation pipeline.
"""

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from deepsweep.patterns.registry import PatternRegistry
from deepsweep.patterns.schema import (
    DetectionType,
    PatternSchema,
    PatternSeverity,
)


@dataclass
class Finding:
    """
    Security finding from pattern detection.

    Attributes:
        pattern_id: Pattern that triggered this finding
        severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        file_path: Absolute path to affected file
        line_number: Line number where finding occurred
        column: Column offset (if available)
        matched_text: The text that triggered the pattern
        pattern_name: Specific pattern name that matched
        confidence: Detection confidence (0.0-1.0)
    """

    pattern_id: str
    severity: PatternSeverity
    file_path: Path
    line_number: int
    matched_text: str
    pattern_name: str
    confidence: float
    column: int = 0

    def format_console(self) -> str:
        """Format finding for console output per ADR-002."""
        severity_tag = f"[{self.severity.value}]"
        location = f"{self.file_path}:{self.line_number}"
        if self.column > 0:
            location += f":{self.column}"
        return f"{severity_tag} {self.pattern_id} at {location}: {self.pattern_name}"


@dataclass
class ValidationResult:
    """
    Complete validation result for a workspace.

    Attributes:
        findings: List of all findings
        files_scanned: Number of files validated
        patterns_applied: Number of patterns applied
        duration_ms: Validation duration in milliseconds
        score: Security score (0-100, higher is better)
        grade: Letter grade (A/B/C/D/F)
    """

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    patterns_applied: int = 0
    duration_ms: int = 0
    score: int = 100
    grade: str = "A"

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(
            1 for f in self.findings if f.severity == PatternSeverity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(
            1 for f in self.findings if f.severity == PatternSeverity.HIGH
        )

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM severity findings."""
        return sum(
            1 for f in self.findings if f.severity == PatternSeverity.MEDIUM
        )

    @property
    def low_count(self) -> int:
        """Count of LOW severity findings."""
        return sum(
            1 for f in self.findings if f.severity == PatternSeverity.LOW
        )

    def calculate_score(self) -> None:
        """Calculate security score based on findings."""
        # Deduct points based on severity
        deductions = (
            self.critical_count * 25
            + self.high_count * 15
            + self.medium_count * 5
            + self.low_count * 1
        )
        self.score = max(0, 100 - deductions)

        # Assign grade
        if self.score >= 90:
            self.grade = "A"
        elif self.score >= 80:
            self.grade = "B"
        elif self.score >= 70:
            self.grade = "C"
        elif self.score >= 60:
            self.grade = "D"
        else:
            self.grade = "F"


class PatternEngine:
    """
    Execute detection patterns against files.

    Example:
        engine = PatternEngine()
        result = engine.validate_workspace(Path("."))

        for finding in result.findings:
            print(finding.format_console())

        print(f"[INFO] Score: {result.score} ({result.grade})")
    """

    def __init__(self) -> None:
        """Initialize engine with pattern registry."""
        self._registry = PatternRegistry.get_instance()

    def validate_workspace(
        self,
        workspace: Path,
        categories: list[str] | None = None,
    ) -> ValidationResult:
        """
        Validate all files in a workspace.

        Args:
            workspace: Path to workspace directory
            categories: Optional list of categories to check

        Returns:
            ValidationResult with all findings
        """
        start_time = time.time()

        result = ValidationResult()
        patterns = self._get_patterns(categories)
        result.patterns_applied = len(patterns)

        for file_path in self._iter_files(workspace):
            result.files_scanned += 1
            for finding in self._validate_file(file_path, patterns):
                result.findings.append(finding)

        result.duration_ms = int((time.time() - start_time) * 1000)
        result.calculate_score()

        return result

    def _get_patterns(
        self, categories: list[str] | None
    ) -> list[PatternSchema]:
        """Get patterns filtered by category."""
        if categories is None:
            return self._registry.get_all_patterns()

        from deepsweep.patterns.schema import PatternCategory

        patterns = []
        for cat_name in categories:
            try:
                cat = PatternCategory(cat_name)
                patterns.extend(self._registry.get_patterns_by_category(cat))
            except ValueError:
                pass  # Invalid category, skip
        return patterns

    def _iter_files(self, workspace: Path) -> Iterator[Path]:
        """Iterate over files to validate."""
        # Get all unique file types from patterns
        file_types: set[str] = set()
        for pattern in self._registry.get_all_patterns():
            file_types.update(pattern.detection.file_types)

        for file_type in file_types:
            if file_type.startswith("."):
                # Extension match
                for file_path in workspace.rglob(f"*{file_type}"):
                    if not self._should_ignore(file_path):
                        yield file_path
            else:
                # Exact filename match
                for file_path in workspace.rglob(file_type):
                    if not self._should_ignore(file_path):
                        yield file_path

    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        ignore_dirs = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            ".mypy_cache",
            ".pytest_cache",
            ".deepsweep-assessment",
        }
        return any(part in ignore_dirs for part in path.parts)

    def _validate_file(
        self,
        file_path: Path,
        patterns: list[PatternSchema],
    ) -> Iterator[Finding]:
        """Validate a single file against patterns."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            return

        lines = content.split("\n")

        for pattern in patterns:
            # Check if pattern applies to this file type
            if not self._pattern_applies(pattern, file_path):
                continue

            # Check exclude patterns first
            if self._is_excluded(content, pattern):
                continue

            # Run detection
            if pattern.detection.type in (
                DetectionType.REGEX,
                DetectionType.COMPOSITE,
            ):
                yield from self._run_regex_detection(file_path, lines, pattern)

    def _pattern_applies(
        self, pattern: PatternSchema, file_path: Path
    ) -> bool:
        """Check if pattern should be applied to file."""
        for file_type in pattern.detection.file_types:
            if file_type.startswith("."):
                # Check both suffix (e.g., .py) and name (e.g., .cursorrules)
                if file_path.suffix == file_type or file_path.name == file_type:
                    return True
            else:
                if file_path.name == file_type:
                    return True
        return False

    def _is_excluded(self, content: str, pattern: PatternSchema) -> bool:
        """Check if content matches exclusion patterns."""
        for exclude in pattern.detection.exclude_patterns:
            if exclude in content:
                return True
        return False

    def _run_regex_detection(
        self,
        file_path: Path,
        lines: list[str],
        pattern: PatternSchema,
    ) -> Iterator[Finding]:
        """Run regex-based detection."""
        for line_num, line in enumerate(lines, start=1):
            for detection in pattern.detection.patterns:
                try:
                    matches = list(
                        re.finditer(detection.pattern, line, re.IGNORECASE)
                    )
                except re.error:
                    continue

                for match in matches:
                    yield Finding(
                        pattern_id=pattern.id,
                        severity=pattern.severity,
                        file_path=file_path,
                        line_number=line_num,
                        column=match.start() + 1,
                        matched_text=match.group(0),
                        pattern_name=detection.name,
                        confidence=pattern.metadata.confidence
                        * detection.weight,
                    )
