"""
DeepSweep Detection Pattern System
==================================

Enterprise-grade detection patterns for agentic AI security validation.

Pattern Categories:
- prompt_injection: AI instruction hijacking attacks
- mcp_security: Model Context Protocol vulnerabilities
- config_drift: Configuration-based security bypasses
- secrets: Credential and key exposure
- supply_chain: Dependency and package attacks

Usage:
    from deepsweep.patterns import PatternRegistry

    registry = PatternRegistry.get_instance()
    patterns = registry.get_patterns_by_category("prompt_injection")

    for pattern in patterns:
        print(f"[INFO] Pattern: {pattern.id} - {pattern.name}")
"""

from deepsweep.patterns.engine import Finding, PatternEngine, ValidationResult
from deepsweep.patterns.loader import PatternLoader
from deepsweep.patterns.registry import PatternRegistry
from deepsweep.patterns.schema import PatternSchema, validate_pattern

__all__ = [
    "Finding",
    "PatternEngine",
    "PatternLoader",
    "PatternRegistry",
    "PatternSchema",
    "ValidationResult",
    "validate_pattern",
]
