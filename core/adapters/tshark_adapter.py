"""TShark Packet Capture & Protocol Analyzer Adapter v6.0."""
import subprocess
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class TSharkAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("TShark / Wireshark", "tshark")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        return self.manager.detect_tool("tshark").installed

    def get_version(self) -> str:
        return self.manager.detect_tool("tshark").version

    def run(self, target: str, options: dict = None) -> dict:
        status = self.manager.detect_tool("tshark")
        if not status.installed:
            return {"error": "TShark is not installed", "packets": []}
        return {"packets": []}

    def parse_results(self, raw_output: dict) -> list:
        return raw_output.get("packets", [])

    def normalize_results(self, parsed_findings: list) -> list:
        return []
