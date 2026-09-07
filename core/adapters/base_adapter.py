"""
Base Adapter Architecture for External Security Tools v6.0.

Every external security tool adapter inherits from BaseToolAdapter and implements:
  - check_available()
  - get_version()
  - configure()
  - run()
  - parse_results()
  - normalize_results()
  - health_check()
"""

import abc
from typing import Dict, List, Optional
from core.plugin_base import Finding


class BaseToolAdapter(abc.ABC):
    """Abstract base class for all external security tool adapters."""

    def __init__(self, tool_name: str, tool_key: str):
        self.tool_name = tool_name
        self.tool_key = tool_key
        self.config = {}
        self.is_configured = False

    @abc.abstractmethod
    def check_available(self) -> bool:
        """Check if the tool is installed, accessible, or configured."""
        pass

    @abc.abstractmethod
    def get_version(self) -> str:
        """Return detected version string."""
        pass

    @abc.abstractmethod
    def run(self, target: str, options: dict = None) -> dict:
        """
        Execute tool against target.
        Returns dict containing raw execution output/data.
        """
        pass

    @abc.abstractmethod
    def parse_results(self, raw_output: dict) -> list:
        """Parse tool-specific output into raw finding dictionaries."""
        pass

    @abc.abstractmethod
    def normalize_results(self, parsed_findings: list) -> List[Finding]:
        """
        Convert tool-specific findings into normalized Sentinel Finding objects.
        CRITICAL: All normalized findings set `validated = False` until validated by Sentinel!
        """
        pass

    def health_check(self) -> bool:
        """Check if tool adapter is healthy and ready for execution."""
        return self.check_available()
