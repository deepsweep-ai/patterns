"""
Pattern Schema Validation
=========================

YAML schema validation for DeepSweep detection patterns.
Enforces ADR-003 pattern structure.
"""

import re
from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    """Valid pattern categories per ADR-003."""

    PROMPT_INJECTION = "prompt_injection"
    MCP_SECURITY = "mcp_security"
    SECRETS = "secrets"
    CONFIG_DRIFT = "config_drift"
    SUPPLY_CHAIN = "supply_chain"


class PatternSeverity(str, Enum):
    """Valid severity levels per ADR-002."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionType(str, Enum):
    """Valid detection types."""

    REGEX = "regex"
    SEMANTIC = "semantic"
    AST = "ast"
    COMPOSITE = "composite"


@dataclass
class DetectionPattern:
    """Individual detection pattern definition."""

    pattern: str
    name: str
    weight: float = 1.0


@dataclass
class Detection:
    """Detection configuration."""

    type: DetectionType
    patterns: list[DetectionPattern]
    file_types: list[str]
    exclude_patterns: list[str] = field(default_factory=list)


@dataclass
class Remediation:
    """Remediation guidance."""

    summary: str
    steps: list[str]
    references: list[str]
    auto_fix: bool = False


@dataclass
class PatternMetadata:
    """Pattern metadata."""

    author: str
    created: str  # ISO 8601 date
    updated: str  # ISO 8601 date
    confidence: float
    false_positive_rate: float
    tags: list[str]


@dataclass
class PatternSchema:
    """
    Complete pattern schema per ADR-003.

    Example:
        schema = PatternSchema(
            id="DS-PI-001",
            name="Cursor Rules Backdoor",
            version="1.0.0",
            category=PatternCategory.PROMPT_INJECTION,
            severity=PatternSeverity.CRITICAL,
            cvss=9.1,
            cve=["CVE-2025-43570"],
            owasp_mapping=["ASI01", "ASI06"],
            description="Detects hidden instruction injection...",
            detection=Detection(...),
            remediation=Remediation(...),
            examples_malicious=["..."],
            examples_benign=["..."],
            metadata=PatternMetadata(...)
        )
    """

    id: str
    name: str
    version: str
    category: PatternCategory
    severity: PatternSeverity
    cvss: float
    description: str
    detection: Detection
    remediation: Remediation
    examples_malicious: list[str]
    examples_benign: list[str]
    metadata: PatternMetadata
    cve: list[str] = field(default_factory=list)
    owasp_mapping: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate pattern ID format."""
        if not re.match(r"^DS-[A-Z]{2,4}-\d{3}$", self.id):
            raise ValueError(
                f"Invalid pattern ID format: {self.id}. "
                "Expected format: DS-XX-NNN (e.g., DS-PI-001)"
            )
        if not 0.0 <= self.cvss <= 10.0:
            raise ValueError(f"CVSS must be 0.0-10.0, got: {self.cvss}")
        if not 0.0 <= self.metadata.confidence <= 1.0:
            raise ValueError(
                f"Confidence must be 0.0-1.0, got: {self.metadata.confidence}"
            )

    @staticmethod
    def _validate_id(pattern_id: str) -> bool:
        """
        Validate pattern ID format.

        Args:
            pattern_id: Pattern ID to validate

        Returns:
            True if valid

        Raises:
            ValueError: If invalid format
        """
        if not re.match(r"^DS-[A-Z]{2,4}-\d{3}$", pattern_id):
            raise ValueError(
                f"Invalid pattern ID format: {pattern_id}. "
                "Expected format: DS-XX-NNN (e.g., DS-PI-001)"
            )
        return True


def validate_pattern(data: dict) -> PatternSchema:
    """
    Validate pattern data against schema.

    Args:
        data: Raw YAML/dict pattern data

    Returns:
        Validated PatternSchema instance

    Raises:
        ValueError: If validation fails
    """
    # Convert nested structures
    detection = Detection(
        type=DetectionType(data["detection"]["type"]),
        patterns=[
            DetectionPattern(**p) for p in data["detection"]["patterns"]
        ],
        file_types=data["detection"]["file_types"],
        exclude_patterns=data["detection"].get("exclude_patterns", []),
    )

    remediation = Remediation(
        summary=data["remediation"]["summary"],
        steps=data["remediation"]["steps"],
        references=data["remediation"]["references"],
        auto_fix=data["remediation"].get("auto_fix", False),
    )

    metadata = PatternMetadata(
        author=data["metadata"]["author"],
        created=data["metadata"]["created"],
        updated=data["metadata"]["updated"],
        confidence=data["metadata"]["confidence"],
        false_positive_rate=data["metadata"]["false_positive_rate"],
        tags=data["metadata"]["tags"],
    )

    return PatternSchema(
        id=data["id"],
        name=data["name"],
        version=data["version"],
        category=PatternCategory(data["category"]),
        severity=PatternSeverity(data["severity"]),
        cvss=data["cvss"],
        cve=data.get("cve", []),
        owasp_mapping=data.get("owasp_mapping", []),
        description=data["description"],
        detection=detection,
        remediation=remediation,
        examples_malicious=data["examples"]["malicious"],
        examples_benign=data["examples"]["benign"],
        metadata=metadata,
    )
