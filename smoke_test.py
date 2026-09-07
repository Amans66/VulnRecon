"""Quick smoke test: run just the host-level plugins against lpu.in."""
import sys
sys.stdout.reconfigure(encoding='utf-8')

import warnings
warnings.filterwarnings("ignore")

from core.http_client import get
from core import reporter

target = "http://lpu.in"

# Test the key plugins that were broken
plugins_to_test = [
    ("security_misconfiguration", "test_security_misconfiguration"),
    ("clickjacking", "test_clickjacking"),
    ("cors", "test_cors"),
    ("session_hijacking", "test_session_hijacking"),
    ("tech_detection", "test_tech_detection"),
    ("sensitive_data_exposure", "test_sensitive_data_exposure"),
    ("unvalidated_redirects", "test_unvalidated_redirects"),
]

print(f"=== Smoke Testing {target} ===\n")

for module_name, func_name in plugins_to_test:
    try:
        import importlib
        mod = importlib.import_module(f"plugins.{module_name}")
        func = getattr(mod, func_name)
        result = func(target)
        if result:
            result.setdefault("confidence", 75)
            result.setdefault("signals", [])
            result.setdefault("evidence", "")
            result.setdefault("parameter", "")
            result.setdefault("status", "CONFIRMED" if result.get("confidence", 0) >= 70 else "POSSIBLE")
            reporter.print_finding(result)
        else:
            print(f"  [CLEAN] {func_name}: No finding")
    except Exception as e:
        print(f"  [ERROR] {func_name}: {e}")

print("\n=== Done ===")
