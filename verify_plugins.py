"""Verify plugin loading."""
import sys
sys.stdout.reconfigure(encoding='utf-8')

import importlib
import pkgutil
import plugins as plugins_pkg

HOST_ONLY_PLUGINS = {
    "test_subdomain_enum", "test_port_scanner", "test_waf_detector",
    "test_dir_fuzzer", "test_broken_authentication", "test_credential_stuffing",
    "test_insecure_crypto_storage", "test_missing_function_level_access",
    "test_privilege_escalation", "test_idor",
    "test_cors", "test_http_verbs", "test_clickjacking",
    "test_session_fixation", "test_session_hijacking", "test_vulnerable_components",
    "test_security_misconfiguration", "test_header_injection",
    "test_unvalidated_redirects", "test_tech_detection",
}

host = []
page = []
errors = []

for _, module_name, _ in pkgutil.iter_modules(plugins_pkg.__path__):
    try:
        module = importlib.import_module(f"plugins.{module_name}")
        for attr_name in dir(module):
            if attr_name.startswith("test_") and callable(getattr(module, attr_name)):
                func = getattr(module, attr_name)
                if attr_name in HOST_ONLY_PLUGINS:
                    host.append(attr_name)
                else:
                    page.append(attr_name)
    except Exception as e:
        errors.append(f"{module_name}: {e}")

print(f"HOST plugins: {len(host)}")
for p in sorted(host):
    print(f"  [HOST] {p}")
print(f"\nPAGE plugins: {len(page)}")
for p in sorted(page):
    print(f"  [PAGE] {p}")
if errors:
    print(f"\nERRORS:")
    for e in errors:
        print(f"  {e}")
