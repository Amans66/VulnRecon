"""
🛡️ Sentinel Vulnerability Scanner v6.0 — Enterprise Architecture.
Multi-signal detection, adaptive engine, attack chain analysis,
validation pipeline, correlation engine, and web security dashboard.
"""

import os
import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import warnings
warnings.filterwarnings("ignore", message=".*XMLParsedAsHTMLWarning.*")
warnings.filterwarnings("ignore", message=".*It looks like you're using an HTML parser.*")
try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

import time
import threading
import argparse
import importlib
import pkgutil
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

from core.http_client import get as http_get, configure_session
from core import reporter
from core.config import ScannerConfig
from core.adaptive_engine import AdaptiveEngine, TargetProfile
from core.attack_chain import AttackChainAnalyzer
from core.scope import ScopeValidator
from core.request_history import request_history
from core.auth_profiles import AuthProfileManager
from core.attack_surface import AttackSurfaceMap, Endpoint, DiscoveredForm, FormField
from core.js_analyzer import JSAnalyzer
from core.validator import ValidationEngine
from core.correlator import FindingCorrelator

# ── Dynamic Host vs. Page Plugin Split ──
HOST_PLUGINS = []
PAGE_PLUGINS = []

# Plugins that are active parameter/form injection tools (only run on pages with inputs)
INPUT_FUZZING_PLUGINS = {
    "test_sqli", "test_xss", "test_command_injection",
    "test_lfi", "test_rfi", "test_xml_injection", "test_ldap_injection",
    "test_html_injection", "test_path_traversal", "test_rce",
    "test_buffer_overflow", "test_ssrf", "test_nosql_injection",
    "test_xpath_injection", "test_ssti", "test_mass_assignment",
    "test_prototype_pollution", "test_http_param_pollution",
    "test_parameter_manipulation", "test_file_upload",
}

# Plugins that only need to run ONCE on the base domain (not per-page)
HOST_ONLY_PLUGINS = {
    # Network / Infrastructure
    "test_subdomain_enum", "test_port_scanner", "test_waf_detector",
    # Path brute-forcing
    "test_dir_fuzzer", "test_broken_authentication", "test_credential_stuffing",
    "test_insecure_crypto_storage", "test_missing_function_level_access",
    "test_privilege_escalation", "test_idor", "test_forced_browsing",
    "test_jwt_security", "test_graphql_security", "test_cookie_security",
    "test_secrets_exposure", "test_workflow_bypass",
    # Header / config checks
    "test_cors", "test_http_verbs", "test_clickjacking",
    "test_session_fixation", "test_session_hijacking", "test_vulnerable_components",
    "test_security_misconfiguration", "test_header_injection",
    "test_unvalidated_redirects", "test_open_redirect", "test_tech_detection",
    "test_excessive_data_exposure",
}

EXPENSIVE_HOST_PLUGINS = {
    "test_port_scanner",
    "test_subdomain_enum",
    "test_dir_fuzzer",
    "test_credential_stuffing",
    "test_privilege_escalation",
    "test_insecure_crypto_storage",
    "test_missing_function_level_access",
    "test_vulnerable_components",
}

EXPENSIVE_PAGE_PLUGINS = {
    "test_ssrf",
    "test_buffer_overflow",
    "test_rce",
    "test_path_traversal",
    "test_lfi",
    "test_rfi",
    "test_sqli",
    "test_xss",
    "test_ssti",
    "test_race_condition",
}


def load_plugins():
    """Dynamically loads and partitions all plugins from the plugins/ directory."""
    import plugins as plugins_pkg
    
    loaded_count = 0
    for _, module_name, _ in pkgutil.iter_modules(plugins_pkg.__path__):
        try:
            module = importlib.import_module(f"plugins.{module_name}")
            for attr_name in dir(module):
                if attr_name.startswith("test_") and callable(getattr(module, attr_name)):
                    func = getattr(module, attr_name)
                    if attr_name in HOST_ONLY_PLUGINS:
                        if func not in HOST_PLUGINS:
                            HOST_PLUGINS.append(func)
                    else:
                        if func not in PAGE_PLUGINS:
                            PAGE_PLUGINS.append(func)
                    loaded_count += 1
        except Exception as e:
            print(f"[!] Failed to load plugin {module_name}: {e}")
    return loaded_count

load_plugins()


def select_plugins_for_intensity(plugin_list, intensity, is_host=True):
    """Reduce scan breadth for quick runs while keeping standard/thorough coverage intact."""
    if intensity > 1:
        return list(plugin_list)

    skipped_plugins = EXPENSIVE_HOST_PLUGINS if is_host else EXPENSIVE_PAGE_PLUGINS
    return [plugin for plugin in plugin_list if plugin.__name__ not in skipped_plugins]


STATIC_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
    '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.webm',
    '.xml', '.rss', '.atom', '.txt', '.csv', '.xls', '.xlsx', '.doc', '.docx',
}

DYNAMIC_EXTENSIONS = {
    '.php', '.asp', '.aspx', '.jsp', '.jspx', '.cfm', '.cgi', '.pl',
    '.py', '.rb', '.do', '.action',
}

_INPUT_CACHE = {}
_INPUT_CACHE_LOCK = threading.Lock()


def normalize_target_url(target_url):
    """Normalize a user-provided target into a canonical absolute URL."""
    value = (target_url or "").strip()
    if not value:
        raise ValueError("Target URL cannot be empty")

    if "://" not in value:
        value = f"http://{value}"

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target_url}")

    if not parsed.path:
        parsed = parsed._replace(path="/")

    return urlunparse(parsed)


def should_skip_url(url, scope_validator=None):
    """Avoid crawling static assets and out-of-scope targets."""
    if scope_validator and not scope_validator.is_in_scope(url):
        return True

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return True

    path = parsed.path.lower()
    if path in {"", "/", "/robots.txt", "/sitemap.xml", "/favicon.ico"}:
        return path in {"/robots.txt", "/sitemap.xml", "/favicon.ico"}

    ext = os.path.splitext(path)[1].lower()
    return ext in STATIC_EXTENSIONS


def crawl(base_url, max_depth=2, max_urls=100, scope_validator=None, attack_surface=None):
    """Concurrent BFS crawl to discover endpoints and map attack surface."""
    import re
    visited = set()
    found = {base_url}
    netloc = urlparse(base_url).netloc
    queue = [(base_url, 0)]
    js_analyzer = JSAnalyzer()

    print(f"🔍 Crawling website up to depth {max_depth}...")

    endpoint_pattern = re.compile(r'["\'](/[a-zA-Z0-9_\-\./\?\=\&]+)["\']')

    with ThreadPoolExecutor(max_workers=min(15, max(4, max_depth + 4))) as pool:
        while queue and len(found) < max_urls:
            current_level = queue[:]
            queue.clear()

            futures = {}
            for url, depth in current_level:
                if url in visited or depth > max_depth:
                    continue
                visited.add(url)
                if len(found) >= max_urls:
                    break

                if scope_validator and not scope_validator.check_rate_limit():
                    scope_validator.wait_for_rate_limit()

                futures[pool.submit(http_get, url)] = (url, depth)

            for future in as_completed(futures):
                url, depth = futures[future]
                try:
                    r = future.result()
                    
                    # Record in request history
                    request_history.record(
                        method="GET", url=url, headers=r.request.headers if hasattr(r, 'request') else {},
                        response_status=r.status_code, response_headers=r.headers,
                        response_body_snippet=r.text[:500], elapsed=r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0
                    )

                    content_type = r.headers.get("Content-Type", "").lower()

                    # Handle JavaScript files with JSAnalyzer
                    if "javascript" in content_type or url.endswith(".js"):
                        if attack_surface:
                            attack_surface.add_js_file(url)
                            js_analysis = js_analyzer.analyze_file(url, r.text)
                            for ep in js_analysis.get("endpoints", []):
                                full_ep = urljoin(url, ep)
                                attack_surface.add_api_route(full_ep)
                        continue

                    if not any(t in content_type for t in ["text/html", "text/plain", "application/json"]):
                        continue

                    raw_text = r.text
                    soup = BeautifulSoup(raw_text, "html.parser")
                    extracted_links = set()

                    # Capture forms in attack surface
                    if attack_surface:
                        for form_tag in soup.find_all("form"):
                            action = form_tag.get("action", url)
                            method = form_tag.get("method", "GET").upper()
                            fields = []
                            for inp in form_tag.find_all(["input", "textarea", "select"]):
                                name = inp.get("name")
                                if name:
                                    fields.append(FormField(name=name, field_type=inp.get("type", "text")))
                            attack_surface.add_form(DiscoveredForm(action=action, method=method, fields=fields, page_url=url))

                    for tag in soup.find_all("a", href=True):
                        extracted_links.add(tag["href"].strip())
                    for form in soup.find_all("form", action=True):
                        extracted_links.add(form["action"].strip())
                    for tag in soup.find_all(["iframe", "script"], src=True):
                        extracted_links.add(tag["src"].strip())
                    for match in endpoint_pattern.finditer(raw_text):
                        extracted_links.add(match.group(1))

                    for href in extracted_links:
                        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                            continue

                        full = urljoin(url, href)
                        full = urlunparse(urlparse(full)._replace(fragment=""))
                        parsed = urlparse(full)
                        if parsed.netloc != netloc or full in found or should_skip_url(full, scope_validator):
                            continue
                        if len(found) < max_urls:
                            found.add(full)
                            queue.append((full, depth + 1))
                            if attack_surface:
                                attack_surface.add_endpoint(Endpoint(url=full, method="GET", params=list(parse_qs(parsed.query).keys())))
                except Exception:
                    pass

    return list(found)


def has_active_inputs(url):
    """Checks if a page has dynamic inputs or parameter structures."""
    with _INPUT_CACHE_LOCK:
        if url in _INPUT_CACHE:
            return _INPUT_CACHE[url]

    parsed = urlparse(url)
    if parsed.query:
        result = True
    else:
        path = parsed.path.lower()
        ext = ''
        if '.' in path.split('/')[-1]:
            ext = '.' + path.split('/')[-1].rsplit('.', 1)[-1]

        if ext in STATIC_EXTENSIONS:
            result = False
        elif ext in DYNAMIC_EXTENSIONS:
            result = True
        else:
            try:
                r = http_get(url, timeout=3)
                soup = BeautifulSoup(r.text, "html.parser")
                result = bool(soup.find("form")) or not ext
            except Exception:
                result = not ext

    with _INPUT_CACHE_LOCK:
        _INPUT_CACHE[url] = result
    return result


class ProgressTracker:
    def __init__(self, total, phase_name=""):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()
        self.phase_name = phase_name

    def tick(self):
        with self.lock:
            self.done += 1
            if self.total <= 0:
                return
            pct = (self.done / self.total) * 100
            bar = "█" * int(pct // 2.5) + "░" * (40 - int(pct // 2.5))
            sys.stdout.write(f"\r   [{bar}] {pct:5.1f}%  ({self.done}/{self.total})")
            sys.stdout.flush()

    def finish(self):
        sys.stdout.write("\n")
        sys.stdout.flush()


def _coerce_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def normalize_finding(finding):
    """Normalize plugin output into a consistent finding structure."""
    if not isinstance(finding, dict):
        return {}

    normalized = dict(finding)
    normalized.setdefault("confidence", 75)
    normalized.setdefault("signals", [])
    normalized.setdefault("evidence", "")
    normalized.setdefault("parameter", "")
    normalized.setdefault("payload", "")
    normalized.setdefault("severity", "Medium")
    vuln_name = normalized.get("vuln", normalized.get("title", "Unknown"))
    normalized.setdefault("owasp", "Unknown")
    normalized.setdefault("remediation", "Review and fix.")
    normalized.setdefault("risk_score", 50)

    # v6.0 fields
    normalized.setdefault("cwe", ScannerConfig.get_cwe(vuln_name))
    normalized.setdefault("cvss", ScannerConfig.get_cvss(vuln_name))
    normalized.setdefault("validation_status", "needs_manual")

    normalized["confidence"] = max(0, min(_coerce_int(normalized.get("confidence"), 75), 100))
    normalized["risk_score"] = max(0, min(_coerce_int(normalized.get("risk_score"), 50), 100))

    if not normalized.get("status") or normalized["status"].upper() not in {"DISCOVERED", "CONFIRMED", "POSSIBLE", "NOISE", "HIGH CONFIDENCE", "NEEDS MANUAL VERIFICATION"}:
        if normalized["confidence"] >= ScannerConfig.CONFIDENCE_CONFIRMED:
            normalized["status"] = "DISCOVERED"
        elif normalized["confidence"] >= ScannerConfig.CONFIDENCE_POSSIBLE:
            normalized["status"] = "POSSIBLE"
        else:
            normalized["status"] = "DISCOVERED"
    else:
        normalized["status"] = normalized["status"].upper()
    if not isinstance(normalized["signals"], list):
        normalized["signals"] = [normalized["signals"]]
    return normalized


def should_keep_finding(finding, min_confidence=40):
    """Keep only findings that are confident and have evidence-backed validation context."""
    if not isinstance(finding, dict):
        return False

    vuln = str(finding.get("vuln", "")).strip()
    url = str(finding.get("url", "")).strip()
    if not vuln or not url:
        return False

    confidence = int(finding.get("confidence", 0))
    if confidence < max(0, min(100, int(min_confidence))):
        return False

    evidence = str(finding.get("evidence", "") or "")
    validation_status = str(finding.get("validation_status", "") or "").lower()
    has_evidence = bool(evidence.strip()) or validation_status in {"confirmed", "high_confidence", "needs_manual", "false_positive"}
    return has_evidence


def run_plugin(plugin, url):
    """Execute a single plugin safely."""
    try:
        result = plugin(url)
        if isinstance(result, list):
            return [normalize_finding(item) for item in result if normalize_finding(item)]
        return normalize_finding(result)
    except Exception:
        return None


def run_tech_detection(base_url):
    """Run tech detection early and return the detected tech stack."""
    tech_stack = []
    waf_detected = False
    waf_vendor = ""

    for plugin in HOST_PLUGINS:
        name = plugin.__name__
        if name == "test_tech_detection":
            try:
                result = plugin(base_url)
                if result and isinstance(result, dict):
                    details = result.get("details", "")
                    if "Technologies:" in details:
                        tech_part = details.split("Technologies:")[1].split(";")[0]
                        tech_stack = [t.strip() for t in tech_part.split(",")]
            except Exception:
                pass
        elif name == "test_waf_detector":
            try:
                result = plugin(base_url)
                if result and isinstance(result, dict):
                    waf_detected = True
                    waf_vendor = result.get("details", "")
            except Exception:
                pass

    return tech_stack, waf_detected, waf_vendor


def scan(urls, max_workers=30, verbose=False, intensity=2, scope_validator=None, attack_surface=None):
    """Run plugins with high performance concurrency and partition logic."""
    results = []
    seen = set()
    total_checks = 0

    base_url = urls[0] if urls else ""

    # ── Phase 0: Intelligence Gathering ──
    print("🧠 Phase 0 — Intelligence Gathering & Attack Surface Mapping...")
    tech_stack, waf_detected, waf_vendor = run_tech_detection(base_url)

    if tech_stack:
        print(f"   📋 Detected: {', '.join(tech_stack[:6])}")
        if attack_surface:
            for t in tech_stack:
                attack_surface.add_technology(t)

    if waf_detected:
        print(f"   🛡️  WAF Detected: {waf_vendor[:60]}")

    engine = AdaptiveEngine()
    engine.infer_from_tech_stack(tech_stack)
    engine.update_profile(waf_detected=waf_detected)

    profile = engine.profile
    if profile.language_hint:
        print(f"   🔧 Language: {profile.language_hint} | DBMS: {profile.dbms_hint} | OS: {profile.os_hint}")

    # ── Phase 0.5: Technology-Specific Module Execution ──
    from core.tech_modules import TechnologyScannerEngine
    tech_engine = TechnologyScannerEngine(base_url, tech_stack)
    tech_findings = tech_engine.run_conditional_checks()
    if tech_findings:
        print(f"   🎯 Conditional Technology Modules generated {len(tech_findings)} findings.")
        results.extend(tech_findings)

    print()

    host_plugins = select_plugins_for_intensity(HOST_PLUGINS, intensity, is_host=True)

    # ── Phase 1: Host-Level Scans ──
    print(f"🚀 Phase 1 — Running {len(host_plugins)} host-level scans on root domain...")
    
    with ThreadPoolExecutor(max_workers=min(max_workers, 10)) as pool:
        futures = {pool.submit(run_plugin, p, base_url): p.__name__ for p in host_plugins}
        for future in as_completed(futures):
            total_checks += 1
            res = future.result()
            
            findings_to_process = []
            if isinstance(res, list):
                findings_to_process = [r for r in res if r and isinstance(r, dict)]
            elif res and isinstance(res, dict):
                findings_to_process = [res]
            
            for finding in findings_to_process:
                normalized = normalize_finding(finding)
                if not should_keep_finding(normalized, ScannerConfig.CONFIDENCE_POSSIBLE):
                    continue
                key = (normalized.get("vuln"), normalized.get("url"), normalized.get("parameter"))
                if key not in seen:
                    seen.add(key)
                    results.append(normalized)
                    if verbose:
                        reporter.print_finding(normalized)
    print("   ✅ Host scans completed.\n")

    # ── Phase 2: Page-Level Scans ──
    print(f"🚀 Phase 2 — Scheduling page-level scans across {len(urls)} URLs...")

    urls_with_inputs = []
    urls_without_inputs = []
    for u in urls:
        if has_active_inputs(u):
            urls_with_inputs.append(u)
        else:
            urls_without_inputs.append(u)

    print(f"   📊 Target Breakdown: {len(urls_with_inputs)} pages with inputs, {len(urls_without_inputs)} static pages.")
    
    page_plugins = select_plugins_for_intensity(PAGE_PLUGINS, intensity, is_host=False)
    injection_plugins = [p for p in page_plugins if p.__name__ in INPUT_FUZZING_PLUGINS]
    non_injection_plugins = [p for p in page_plugins if p.__name__ not in INPUT_FUZZING_PLUGINS]
    
    total_tasks = (len(urls_with_inputs) * len(page_plugins)) + (len(urls_without_inputs) * len(non_injection_plugins))
    
    if total_tasks == 0:
        print("   ✅ No page tasks scheduled.")
        return results, total_checks

    progress = ProgressTracker(total_tasks)

    with ThreadPoolExecutor(max_workers=max(4, min(max_workers, 32))) as pool:
        futures = {}
        
        for url in urls_with_inputs:
            for p in page_plugins:
                f = pool.submit(run_plugin, p, url)
                futures[f] = (p.__name__, url)
                
        for url in urls_without_inputs:
            for p in non_injection_plugins:
                f = pool.submit(run_plugin, p, url)
                futures[f] = (p.__name__, url)

        for future in as_completed(futures):
            progress.tick()
            total_checks += 1
            res = future.result()
            
            findings_to_process = []
            if isinstance(res, list):
                findings_to_process = [r for r in res if r and isinstance(r, dict)]
            elif res and isinstance(res, dict):
                findings_to_process = [res]
            
            for finding in findings_to_process:
                normalized = normalize_finding(finding)
                if not should_keep_finding(normalized, ScannerConfig.CONFIDENCE_POSSIBLE):
                    continue
                key = (normalized.get("vuln"), normalized.get("url"), normalized.get("parameter"))
                if key not in seen:
                    seen.add(key)
                    results.append(normalized)
                    if verbose:
                        reporter.print_finding(normalized)

    progress.finish()
    return results, total_checks


def main():
    parser = argparse.ArgumentParser(
        description="🛡️  Sentinel Vulnerability Scanner v6.0 — Enterprise Web Security Auditing Platform"
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # 'tools' subcommand
    tools_parser = subparsers.add_parser("tools", help="Manage and check external security tool status")
    tools_parser.add_argument("subcommand", nargs="?", default="status", choices=["status", "list"], help="Tool action")

    # Scan arguments
    parser.add_argument("-u", "--url", help="Target URL to scan (e.g. http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Concurrent threads (default: 30)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Max crawl depth (default: 2)")
    parser.add_argument("-m", "--max-urls", type=int, default=100, help="Max URLs to discover (default: 100)")
    parser.add_argument("-o", "--output", default="results/scan_report", help="Output file prefix")
    parser.add_argument("-f", "--format", choices=["html", "json", "csv", "sarif", "markdown", "all"], default="all", help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print findings as they are discovered")
    parser.add_argument("--confidence", type=int, default=40, help="Min confidence threshold (default: 40)")
    parser.add_argument("--intensity", type=int, choices=[1, 2, 3, 4], default=2,
                        help="Scan intensity: 1=Quick, 2=Standard, 3=Thorough, 4=Aggressive (default: 2)")
    parser.add_argument("--mode", choices=["passive", "safe_active", "deep", "authenticated", "api"], default="safe_active", help="Scan mode")
    parser.add_argument("--smart", action="store_true", help="Enable intelligent payload mutation engine")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard after scan")
    parser.add_argument("--auth-config", help="Path to JSON file containing auth profiles")
    parser.add_argument("--tools", help="Comma-separated list of external tools to run (e.g. nmap,zap,dalfox,sqlmap)")

    args = parser.parse_args()

    # Subcommand handler: 'tools'
    if args.command == "tools":
        from core.tool_manager import ExternalToolManager
        tool_mgr = ExternalToolManager()
        tool_mgr.print_tools_dashboard()
        sys.exit(0)

    ScannerConfig.CONFIDENCE_POSSIBLE = args.confidence
    ScannerConfig.INTENSITY = args.intensity
    ScannerConfig.SCAN_MODE = args.mode
    ScannerConfig.ENABLE_MUTATION = args.smart
    ScannerConfig.REQUEST_TIMEOUT = max(args.timeout, 3)
    ScannerConfig.SSL_VERIFY = not args.insecure
    configure_session(verify=ScannerConfig.SSL_VERIFY)

    intensity_names = {1: "⚡ Quick", 2: "🔍 Standard", 3: "🔬 Thorough", 4: "💥 Aggressive"}
    intensity_label = intensity_names.get(args.intensity, "Standard")

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║     🛡️  Sentinel Vulnerability Scanner v6.0 — Enterprise      ║")
    print("║     Multi-Signal · Validation Engine · Attack Surface Map    ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    print(f"   Mode: {args.mode.upper()} | Intensity: {intensity_label}")
    print(f"   Loaded Plugins: {len(HOST_PLUGINS) + len(PAGE_PLUGINS)} total ({len(HOST_PLUGINS)} host, {len(PAGE_PLUGINS)} page)")

    if args.url:
        base_url = args.url.strip()
    else:
        try:
            base_url = input("🌐 Enter URL to scan (e.g. example.com): ").strip()
        except EOFError:
            print("[!] No URL provided. Exiting...")
            sys.exit(1)
        if not base_url:
            print("[!] URL is required. Exiting...")
            sys.exit(1)

    try:
        base_url = normalize_target_url(base_url)
    except ValueError as exc:
        print(f"❌ {exc}")
        sys.exit(1)

    scope_validator = ScopeValidator()
    scope_validator.set_scope_from_url(base_url)

    auth_manager = AuthProfileManager()
    if args.auth_config:
        auth_manager.load_from_file(args.auth_config)
        print(f"   🔐 {auth_manager.summary()}")

    attack_surface = AttackSurfaceMap()

    print(f"📡 Testing connection to {base_url} ...")
    try:
        http_get(base_url, timeout=5)
    except Exception as e:
        print(f"❌ Target is unreachable or down! Scan aborted.")
        print(f"   Details: {e}\n")
        sys.exit(1)
    
    print("   ✅ Host is up!")
    start = time.time()

    # Crawl Phase
    profile = ScannerConfig.INTENSITY_PROFILES.get(args.intensity, ScannerConfig.INTENSITY_PROFILES[2])
    crawl_depth = profile.get("crawl_depth", args.depth)
    crawl_max = profile.get("crawl_max", args.max_urls)
    
    print(f"\n🔍 Crawling {base_url} [Depth: {crawl_depth}, Max: {crawl_max}] ...")
    urls = crawl(base_url, max_depth=crawl_depth, max_urls=crawl_max, scope_validator=scope_validator, attack_surface=attack_surface)
    print(f"   Found {len(urls)} internal pages.\n")

    # Scan Phase
    max_workers = profile.get("max_workers", args.threads)
    raw_results, total_checks = scan(urls, max_workers=max_workers, verbose=args.verbose, intensity=args.intensity, scope_validator=scope_validator, attack_surface=attack_surface)

    # Validation Phase
    print("🧪 Phase 3 — Validation Engine (Reproducing findings)...")
    validator = ValidationEngine()
    validated_results = validator.validate_all(raw_results, min_confidence=args.confidence)

    # Correlation Phase
    print("🔗 Phase 4 — Correlation & Attack Chain Analysis...")
    correlator = FindingCorrelator()
    correlated_results = correlator.correlate(validated_results)

    chain_analyzer = AttackChainAnalyzer(correlated_results)
    chains = chain_analyzer.analyze()
    enriched_results = chain_analyzer.enrich_findings()
    risk_grade = chain_analyzer.get_risk_grade()

    elapsed = time.time() - start

    # Reporting Phase
    if enriched_results:
        enriched_results = [r for r in enriched_results if r.get("confidence", 0) >= args.confidence]
        if not args.verbose:
            print(f"\n🚨 {len(enriched_results)} vulnerabilities found:\n")
            for finding in enriched_results:
                reporter.print_finding(finding)

        reporter.print_summary(enriched_results, elapsed, chains, risk_grade)

        print("\n📝 Generating reports...")
        if args.format in ["html", "all"]:
            reporter.generate_html_report(enriched_results, f"{args.output}.html", base_url, elapsed, chains, risk_grade)
            print(f"   ✅ HTML     → {args.output}.html")
        if args.format in ["json", "all"]:
            reporter.generate_json_report(enriched_results, f"{args.output}.json", base_url, elapsed, chains, risk_grade)
            print(f"   ✅ JSON     → {args.output}.json")
        if args.format in ["csv", "all"]:
            reporter.generate_csv_report(enriched_results, f"{args.output}.csv")
            print(f"   ✅ CSV      → {args.output}.csv")
        if args.format in ["sarif", "all"]:
            reporter.generate_sarif_report(enriched_results, f"{args.output}.sarif", chains, risk_grade)
            print(f"   ✅ SARIF    → {args.output}.sarif")
        if args.format in ["markdown", "all"]:
            reporter.generate_markdown_report(enriched_results, f"{args.output}.md", chains, risk_grade)
            print(f"   ✅ Markdown → {args.output}.md")
        print()
    else:
        reporter.print_summary([], elapsed, [], risk_grade)
        print("\n🎉 No vulnerabilities detected above confidence threshold.\n")

    if args.dashboard:
        from dashboard.server import run_dashboard
        run_dashboard(report_path=f"{args.output}.json")


if __name__ == "__main__":
    main()
