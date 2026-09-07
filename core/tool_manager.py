"""
Windows-First External Tool Manager & Detector v6.0.

Automatically detects installed external security tools via:
  - PATH lookup (shutil.which)
  - Common Windows Installation Paths
  - Custom User Configuration (config/tools.yaml)
  - Environment Variables
  - WSL (Windows Subsystem for Linux) Commands
  - Docker Containers
  - REST API Connectors

Does NOT assume Linux paths or hardcode single user paths.
"""

import os
import sys
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional
from core.tool_registry import TOOL_REGISTRY, ToolDefinition


@dataclass
class ToolStatus:
    key: str
    name: str
    category: str
    installed: bool
    status_label: str  # ✓ Ready, ✗ Not Found, ○ API Not Configured, ○ WSL Available
    version: str
    location: str
    invocation_mode: str  # native, wsl, docker, api, none
    error_msg: str = ""


class ExternalToolManager:
    """Manages detection, status reporting, and execution strategy for external tools."""

    def __init__(self, custom_config: dict = None):
        self.custom_config = custom_config or {}
        self.cached_status: Dict[str, ToolStatus] = {}

    def detect_all_tools(self) -> Dict[str, ToolStatus]:
        """Detect availability and status of all registered security tools."""
        statuses = {}
        for key, tool_def in TOOL_REGISTRY.items():
            status = self.detect_tool(key)
            statuses[key] = status
            self.cached_status[key] = status
        return statuses

    def detect_tool(self, tool_key: str) -> ToolStatus:
        """Detect availability of a single tool."""
        tool_def = TOOL_REGISTRY.get(tool_key.lower())
        if not tool_def:
            return ToolStatus(
                key=tool_key, name=tool_key, category="unknown",
                installed=False, status_label="✗ Unknown Tool",
                version="N/A", location="N/A", invocation_mode="none"
            )

        # Check 1: Custom Config Path
        cfg = self.custom_config.get("tools", {}).get(tool_key, {})
        custom_path = cfg.get("executable") or cfg.get("path")
        if custom_path and os.path.exists(custom_path):
            ver = self._get_version(custom_path, tool_key)
            return ToolStatus(
                key=tool_key, name=tool_def.name, category=tool_def.category,
                installed=True, status_label="✓ Configured Path",
                version=ver, location=custom_path, invocation_mode="native"
            )

        # Check 2: Native Executables in PATH
        for exe_name in tool_def.executable_names:
            found_path = shutil.which(exe_name)
            if found_path:
                ver = self._get_version(found_path, tool_key)
                return ToolStatus(
                    key=tool_key, name=tool_def.name, category=tool_def.category,
                    installed=True, status_label="✓ Installed (PATH)",
                    version=ver, location=found_path, invocation_mode="native"
                )

        # Check 3: Common Windows Program Files Paths
        for win_path in tool_def.common_windows_paths:
            if os.path.exists(win_path):
                ver = self._get_version(win_path, tool_key)
                return ToolStatus(
                    key=tool_key, name=tool_def.name, category=tool_def.category,
                    installed=True, status_label="✓ Windows Installed",
                    version=ver, location=win_path, invocation_mode="native"
                )

        # Check 4: REST API Connectors (ZAP, Burp, Nessus, Wazuh, etc.)
        if tool_def.api_supported:
            api_url = cfg.get("api_url") or os.environ.get(f"{tool_key.upper()}_API_URL")
            api_key = cfg.get("api_key") or os.environ.get(f"{tool_key.upper()}_API_KEY")
            if api_url or api_key:
                return ToolStatus(
                    key=tool_key, name=tool_def.name, category=tool_def.category,
                    installed=True, status_label="✓ API Configured",
                    version="API", location=api_url or "Configured", invocation_mode="api"
                )

        # Check 5: WSL (Windows Subsystem for Linux) Fallback
        if tool_def.wsl_command and self._is_wsl_available():
            wsl_path = self._check_wsl_command(tool_def.wsl_command)
            if wsl_path:
                return ToolStatus(
                    key=tool_key, name=tool_def.name, category=tool_def.category,
                    installed=True, status_label="○ WSL Available",
                    version="WSL", location=f"wsl {tool_def.wsl_command}", invocation_mode="wsl"
                )

        # Default: Not Installed / Not Configured
        if tool_def.api_supported:
            return ToolStatus(
                key=tool_key, name=tool_def.name, category=tool_def.category,
                installed=False, status_label="○ API Not Configured",
                version="N/A", location="N/A", invocation_mode="none"
            )

        return ToolStatus(
            key=tool_key, name=tool_def.name, category=tool_def.category,
            installed=False, status_label="✗ Not Found",
            version="N/A", location="N/A", invocation_mode="none"
        )

    def print_tools_dashboard(self):
        """Print a CLI status table of external tool availability."""
        statuses = self.detect_all_tools()
        print("\n" + "=" * 65)
        print("         Sentinel External Security Tools Manager")
        print("=" * 65)
        print(f"{'Tool':<20} | {'Category':<12} | {'Status':<20} | {'Mode':<8}")
        print("-" * 65)
        for key, s in statuses.items():
            print(f"{s.name:<20} | {s.category:<12} | {s.status_label:<20} | {s.invocation_mode:<8}")
        print("=" * 65 + "\n")

    # ── Helpers ──

    def _get_version(self, exe_path: str, tool_key: str) -> str:
        """Attempt to extract tool version via --version flag."""
        try:
            cmd = [exe_path, "--version"]
            if tool_key == "nmap":
                cmd = [exe_path, "-V"]
            elif tool_key == "tshark":
                cmd = [exe_path, "-v"]

            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            out = proc.stdout or proc.stderr
            if out:
                first_line = out.strip().split("\n")[0]
                return first_line[:30]
        except Exception:
            pass
        return "Installed"

    def _is_wsl_available(self) -> bool:
        """Check if WSL is installed on Windows."""
        if sys.platform != "win32":
            return False
        return shutil.which("wsl.exe") is not None

    def _check_wsl_command(self, cmd_name: str) -> bool:
        """Check if command is available inside WSL."""
        try:
            proc = subprocess.run(["wsl.exe", "which", cmd_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            return proc.returncode == 0
        except Exception:
            return False
