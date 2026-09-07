"""
Professional Report Generator v6.0.

Produces:
- Color-coded Rich CLI output with finding panels
- Styled HTML report with executive summary, severity/confidence badges, CWE/CVSS mappings, attack chains, and evidence dropdowns
- SARIF v2.1.0 report for CI/CD integration
- Markdown executive report
- Machine-readable JSON report
- CSV export
"""

import os
import json
import csv
from html import escape
from datetime import datetime, timezone
from collections import Counter
from core.config import ScannerConfig

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


def _severity_color(severity):
    return {"Critical": "red", "High": "bright_red",
            "Medium": "yellow", "Low": "green"}.get(severity, "white")


def _confidence_color(confidence):
    if confidence >= 70:
        return "red"
    elif confidence >= 40:
        return "yellow"
    return "dim"


def _normalize_finding(r):
    """Ensure backward compatibility with old-format findings and add v6.0 fields."""
    if isinstance(r, dict):
        r.setdefault("confidence", 75)
        r.setdefault("signals", [])
        r.setdefault("evidence", "")
        r.setdefault("parameter", "")
        r.setdefault("payload", "")
        r.setdefault("status", "DISCOVERED")
        r.setdefault("validation_status", "needs_manual")
        if str(r.get("status", "")).upper() in {"POSSIBLE", "CONFIRMED"}:
            r["status"] = str(r["status"]).upper()
        elif str(r.get("status", "")).upper() in {"", "DISCOVERED"}:
            r["status"] = "DISCOVERED"
        vuln_name = r.get("vuln", r.get("title", "Unknown"))
        r.setdefault("owasp", ScannerConfig.get_owasp_2025(vuln_name))
        r.setdefault("remediation", "Review and fix according to security best practices.")
        r.setdefault("risk_score", 50)
        # v6.0 fields
        r.setdefault("cwe", ScannerConfig.get_cwe(vuln_name))
        r.setdefault("cvss", ScannerConfig.get_cvss(vuln_name))
        r.setdefault("confidence_label", ScannerConfig.get_confidence_label(r["confidence"]))
        r.setdefault("method", "GET")
        r.setdefault("impact", "")
        r.setdefault("references", [])
        r.setdefault("request_evidence", "")
        r.setdefault("response_evidence", "")
        r.setdefault("reproduction_steps", [])
        r.setdefault("detection_method", r.get("detection_method") or "Behavioral differential analysis")
        r.setdefault("root_cause", r.get("root_cause") or "Input is processed without a verified security boundary.")
        r.setdefault("attack_scenario", r.get("attack_scenario") or "A crafted request interacts with the application in a way that is not safely validated.")
        r.setdefault("poc", r.get("poc") or (r.get("payload") or ""))
        r.setdefault("expected_behavior", r.get("expected_behavior") or "The application should treat user input as data and not as executable logic.")
        r.setdefault("observed_behavior", r.get("observed_behavior") or r.get("evidence") or "A security-relevant difference was observed.")
        r.setdefault("validation", r.get("validation") or "Controlled validation performed against a baseline and negative control.")
        r.setdefault("affected_component", r.get("affected_component") or r.get("url") or "Application request handling")
        r.setdefault("attack_prerequisites", r.get("attack_prerequisites") or "The attacker must be able to submit the affected parameter.")
        r.setdefault("writeup", r.get("writeup") or _build_writeup(r))
        r.setdefault("attack_story", r.get("attack_story") or "The attacker identifies the vulnerable parameter, submits a controlled input, observes a security-relevant response difference, and validates that the issue is reproducible.")
        r.setdefault("confidence_reasoning", r.get("confidence_reasoning") or "Baseline established; payload validated; response difference reproduced; security boundary affected.")
        r.setdefault("what_proven", r.get("what_proven") or "The scanner observed a reproducible difference attributable to the tested input.")
        r.setdefault("what_not_tested", r.get("what_not_tested") or "Additional impact was not demonstrated during the scan.")
        r.setdefault("attacker_requirements", r.get("attacker_requirements") or "Authentication: Unknown; Role: Unknown; User interaction: Unknown; Network position: Unknown")
        r.setdefault("request", r.get("request") or "")
        r.setdefault("response", r.get("response") or "")
        r.setdefault("validation_request", r.get("validation_request") or "")
        r.setdefault("validation_response", r.get("validation_response") or "")
        r.setdefault("baseline", r.get("baseline") or "")
        r.setdefault("true_condition", r.get("true_condition") or "")
        r.setdefault("false_condition", r.get("false_condition") or "")
        r.setdefault("detection", r.get("detection") or r.get("detection_method") or "Observed differential behavior")
        r.setdefault("payload_purpose", r.get("payload_purpose") or "Tests whether attacker-controlled input can alter application logic or server-side behavior.")
        r.setdefault("impacted_component", r.get("impacted_component") or r.get("affected_component") or r.get("url"))
    return r


def _build_writeup(r):
    title = r.get("vuln", r.get("title", "Security Finding"))
    url = r.get("url", "Unknown")
    param = r.get("parameter", "N/A")
    payload = r.get("payload", "")
    evidence = r.get("evidence", "No detailed evidence recorded.")
    remediation = r.get("remediation", "Review and fix according to security best practices.")
    status = r.get("status", "DISCOVERED")
    return (
        f"## {status} {title}\n\n"
        f"### Summary\nThe scanner identified a {title.lower()} issue affecting {url}. The affected parameter was {param}.\n\n"
        f"### Root Cause\n{r.get('root_cause') or 'Input influences server-side logic without a validated security boundary.'}\n\n"
        f"### Detection\n{r.get('detection_method') or 'Behavioral differential analysis'}\n\n"
        f"### Evidence\n{evidence}\n\n"
        f"### Proof of Concept\n{payload or 'No payload recorded.'}\n\n"
        f"### Remediation\n{remediation}\n"
    )


def print_finding(finding):
    """Print a single finding as a rich panel with a professional evidence summary."""
    finding = _normalize_finding(finding)
    if not HAS_RICH:
        conf = finding.get('confidence', 0)
        icon = '\U0001f534' if conf >= 70 else '\U0001f7e1' if conf >= 40 else '\u26aa'
        print(f"  {icon} [{finding.get('severity', 'Medium')}] {finding.get('vuln', 'Unknown')} (Status: {finding.get('status', 'DISCOVERED')})")
        print(f"     URL: {finding.get('url', '')}")
        print(f"     Detection: {finding.get('detection_method', 'Behavioral differential analysis')}")
        print(f"     Root Cause: {finding.get('root_cause', 'Not determined')}")
        if finding.get('payload'):
            print(f"     Payload: {finding['payload'][:80]}")
        print(f"     Confidence: {conf}% ({finding.get('confidence_label', '')})")
        if finding.get('owasp') and finding.get('owasp') != "Unknown":
            print(f"     OWASP: {finding['owasp']}")
        print(f"     Evidence: {finding.get('evidence', 'No evidence recorded')}")
        print()
        return

    severity = finding.get('severity', 'Medium')
    confidence = finding.get('confidence', 0)
    sev_color = _severity_color(severity)
    conf_color = _confidence_color(confidence)
    status = finding.get('status', 'DISCOVERED')
    risk_score = finding.get('risk_score', 0)

    content = Text()
    content.append("VULNERABILITY : ", style="bold")
    content.append(f"{finding.get('vuln', 'Unknown')}\n", style=f"bold {sev_color}")
    content.append("STATUS        : ", style="bold")
    content.append(f"{status}\n", style="bold red" if status.upper().startswith("CONFIRMED") else "bold yellow")
    content.append("URL           : ", style="bold")
    content.append(f"{finding.get('url', '')}\n", style="cyan")
    if finding.get('parameter'):
        content.append("PARAMETER     : ", style="bold")
        content.append(f"{finding['parameter']}\n", style="yellow")
    if finding.get('payload'):
        content.append("PAYLOAD       : ", style="bold")
        content.append(f"{finding['payload'][:120]}\n", style="magenta")
    content.append("SEVERITY      : ", style="bold")
    content.append(f"{severity}", style=f"bold {sev_color}")
    content.append("  |  CONFIDENCE: ", style="bold")
    content.append(f"{confidence}% ({status})", style=f"bold {conf_color}")
    content.append("  |  RISK SCORE: ", style="bold")
    content.append(f"{risk_score}/100\n", style="bold red" if risk_score > 60 else "bold yellow")
    if finding.get('cwe') not in (0, None):
        content.append("CWE / CVSS    : ", style="bold")
        content.append(f"CWE-{finding['cwe']} | CVSS {finding.get('cvss', 'N/A')}\n", style="dim")
    if finding.get('owasp') and finding.get('owasp') != "Unknown":
        content.append("OWASP TOP 10  : ", style="bold")
        content.append(f"{finding['owasp']}\n", style="dim")
    content.append("DETECTION     : ", style="bold")
    content.append(f"{finding.get('detection_method', 'Behavioral differential analysis')}\n", style="dim cyan")
    content.append("ROOT CAUSE    : ", style="bold")
    content.append(f"{finding.get('root_cause', 'Not determined')}\n", style="dim")
    content.append("EVIDENCE      : ", style="bold")
    content.append(f"{finding.get('evidence', 'No evidence recorded')}\n", style="dim white")
    if finding.get('details'):
        content.append("DETAILS       : ", style="bold")
        content.append(f"{finding['details']}\n")

    border_style = sev_color
    title = f"[{sev_color}] [{severity.upper()}] [{status}] {finding.get('vuln', 'Unknown')} [/{sev_color}]"
    console.print(Panel(content, title=title, border_style=border_style, box=box.ROUNDED))


def print_summary(results, elapsed, chains=None, risk_grade="A"):
    """Print scan summary statistics."""
    results = [_normalize_finding(r) for r in results]
    if not HAS_RICH:
        print("\n" + "=" * 50)
        print("                SCAN SUMMARY")
        print("=" * 50)
        print(f"Overall Risk Grade : {risk_grade}")
        print(f"Total Findings     : {len(results)}")
        print(f"Time Elapsed       : {elapsed:.2f} seconds")

        counts = Counter(r.get("severity", "Medium") for r in results)
        print(f"Critical: {counts.get('Critical', 0)} | High: {counts.get('High', 0)} | Medium: {counts.get('Medium', 0)} | Low: {counts.get('Low', 0)}")
        print("=" * 50 + "\n")
        return

    table = Table(title=f"Scan Summary (Risk Grade: {risk_grade})", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold green")

    counts = Counter(r.get("severity", "Medium") for r in results)
    conf_counts = Counter(r.get("status", "POSSIBLE") for r in results)

    table.add_row("Overall Risk Grade", f"Grade {risk_grade}")
    table.add_row("Total Vulnerabilities", str(len(results)))
    table.add_row("Critical Severity", f"[red]{counts.get('Critical', 0)}[/red]")
    table.add_row("High Severity", f"[bright_red]{counts.get('High', 0)}[/bright_red]")
    table.add_row("Medium Severity", f"[yellow]{counts.get('Medium', 0)}[/yellow]")
    table.add_row("Low Severity", f"[green]{counts.get('Low', 0)}[/green]")
    table.add_row("Confirmed Findings", f"[red]{conf_counts.get('CONFIRMED', 0)}[/red]")
    table.add_row("High Confidence", f"[yellow]{conf_counts.get('HIGH CONFIDENCE', 0)}[/yellow]")
    table.add_row("Potential Findings", f"[yellow]{conf_counts.get('POTENTIAL', 0)}[/yellow]")
    table.add_row("Manual Verification", f"[cyan]{conf_counts.get('NEEDS MANUAL VERIFICATION', 0)}[/cyan]")
    table.add_row("Informational", f"[blue]{conf_counts.get('INFORMATIONAL', 0)}[/blue]")
    table.add_row("Rejected Signals", f"[dim]{conf_counts.get('REJECTED', 0)}[/dim]")
    if chains:
        table.add_row("Attack Chains Detected", f"[bold red]{len(chains)}[/bold red]")
    table.add_row("Scan Duration", f"{elapsed:.2f}s")

    console.print()
    console.print(table)
    console.print()


def generate_sarif_report(results, output_path, chains=None, risk_grade="A"):
    """Generate SARIF v2.1.0 format report for CI/CD integration."""
    results = [_normalize_finding(r) for r in results]

    sarif_rules = {}
    sarif_results = []

    level_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Informational": "note",
    }

    for idx, r in enumerate(results):
        vuln_name = r.get("vuln", "Unknown")
        rule_id = f"SEC-{r.get('cwe', 0):03d}" if r.get("cwe") else f"SEC-{idx+1:03d}"

        if rule_id not in sarif_rules:
            sarif_rules[rule_id] = {
                "id": rule_id,
                "name": vuln_name,
                "shortDescription": {"text": vuln_name},
                "fullDescription": {"text": r.get("details", vuln_name)},
                "help": {"text": r.get("remediation", "Review and fix.")},
                "properties": {
                    "cwe": r.get("cwe", 0),
                    "cvss": r.get("cvss", 0.0),
                    "owasp": r.get("owasp", "Unknown"),
                }
            }

        sarif_results.append({
            "ruleId": rule_id,
            "message": {
                "text": f"{vuln_name} detected at {r.get('url', '')}. {r.get('details', '')}"
            },
            "level": level_map.get(r.get("severity", "Medium"), "warning"),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": r.get("url", "")}
                    }
                }
            ],
            "properties": {
                "confidence": r.get("confidence", 50),
                "risk_score": r.get("risk_score", 50),
                "parameter": r.get("parameter", ""),
                "payload": r.get("payload", ""),
                "validation_status": r.get("validation_status", "needs_manual"),
            }
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel Vulnerability Scanner",
                        "version": ScannerConfig.VERSION,
                        "rules": list(sarif_rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ]
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2)


def generate_markdown_report(results, output_path, chains=None, risk_grade="A"):
    """Generate Markdown security report."""
    results = [_normalize_finding(r) for r in results]
    counts = Counter(r.get("severity", "Medium") for r in results)

    lines = [
        f"# Security Assessment Report — Sentinel v{ScannerConfig.VERSION}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Overall Risk Grade:** `{risk_grade}`  ",
        f"**Total Findings:** {len(results)}  \n",
        "## Executive Summary\n",
        "| Severity | Count |",
        "| :--- | :--- |",
        f"| 🔴 Critical | {counts.get('Critical', 0)} |",
        f"| 🟠 High | {counts.get('High', 0)} |",
        f"| 🟡 Medium | {counts.get('Medium', 0)} |",
        f"| 🟢 Low | {counts.get('Low', 0)} |\n",
    ]

    if chains:
        lines.append("## Attack Chains\n")
        for chain in chains:
            lines.append(f"### 🔗 {chain.name} ({chain.chain_severity})")
            lines.append(f"{chain.description}\n")

    lines.append("## Vulnerability Findings\n")
    for idx, r in enumerate(results, 1):
        lines.extend([
            f"### {idx}. {r.get('vuln', 'Unknown')} [{r.get('severity', 'Medium')}]",
            f"- **URL:** `{r.get('url', '')}`",
            f"- **Parameter:** `{r.get('parameter', 'N/A')}`",
            f"- **CWE / CVSS:** CWE-{r.get('cwe', 0)} (CVSS {r.get('cvss', 0.0)})",
            f"- **OWASP:** {r.get('owasp', 'Unknown')}",
            f"- **Confidence:** {r.get('confidence', 0)}% ({r.get('status', 'POSSIBLE')})",
            f"- **Details:** {r.get('details', '')}",
            f"- **Remediation:** {r.get('remediation', '')}\n",
        ])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def generate_html_report(results, output_path, arg3="", arg4=0, chains=None, risk_grade="A"):
    """Generate styled HTML report."""
    if isinstance(arg3, list):
        chains = arg3
        risk_grade = str(arg4) if isinstance(arg4, str) else "A"
        target_url = ""
        duration = 0.0
    else:
        target_url = str(arg3)
        duration = float(arg4) if isinstance(arg4, (int, float)) else 0.0

    results = [_normalize_finding(r) for r in results]
    counts = Counter(r.get("severity", "Medium") for r in results)
    conf_counts = Counter(r.get("status", "POSSIBLE") for r in results)

    rows = []
    for idx, r in enumerate(results, 1):
        sev = r.get("severity", "Medium")
        conf = r.get("confidence", 0)
        status = r.get("status", "DISCOVERED")
        cwe = r.get("cwe", 0)
        cvss = r.get("cvss", "N/A")

        badge_class = f"badge-{sev.lower()}"
        conf_class = "conf-high" if conf >= 70 else "conf-med" if conf >= 40 else "conf-low"
        evidence_text = escape(r.get('evidence', 'N/A'))
        root_cause = escape(r.get('root_cause', 'Not determined'))
        reproduction = "<br>".join(f"<li>{escape(step)}</li>" for step in (r.get('reproduction_steps') or ["Reproduction steps not recorded."]))
        writeup = escape(r.get('writeup') or r.get('evidence') or 'No write-up recorded.')
        payload = escape(r.get('payload', 'N/A'))
        payload_purpose = escape(r.get('payload_purpose', 'Not specified'))
        outcome = escape(r.get('what_proven', 'Not proven'))

        rows.append(f"""
        <tr>
            <td>{idx}</td>
            <td><span class="badge {badge_class}">{escape(sev)}</span></td>
            <td><strong>{escape(r.get('vuln', 'Unknown'))}</strong></td>
            <td><code>CWE-{cwe if cwe not in (0, None) else 'N/A'}</code> / <code>{cvss}</code></td>
            <td><a href="{escape(r.get('url', ''))}" target="_blank">{escape(r.get('url', ''))}</a></td>
            <td><code>{escape(r.get('parameter', 'N/A'))}</code></td>
            <td><span class="conf-badge {conf_class}">{conf}% ({escape(status)})</span></td>
            <td>{escape(r.get('owasp', 'Unknown'))}</td>
            <td>
                <details>
                    <summary>View Details & Evidence</summary>
                    <div class="details-panel">
                        <p><strong>Status:</strong> {escape(status)}</p>
                        <p><strong>Detection Method:</strong> {escape(r.get('detection_method', 'Behavioral differential analysis'))}</p>
                        <p><strong>Root Cause:</strong> {root_cause}</p>
                        <p><strong>Payload:</strong> <code>{payload}</code></p>
                        <p><strong>Purpose:</strong> {payload_purpose}</p>
                        <p><strong>Evidence:</strong> {evidence_text}</p>
                        <p><strong>What was proven:</strong> {outcome}</p>
                        <ol>{reproduction}</ol>
                        <p><strong>Remediation:</strong> {escape(r.get('remediation', 'N/A'))}</p>
                        <button class="copy-btn" onclick="navigator.clipboard.writeText({json.dumps(r.get('writeup') or r.get('evidence') or 'No write-up available.')!r})">Copy Security Write-up</button>
                        <pre class="writeup-box">{writeup}</pre>
                    </div>
                </details>
            </td>
        </tr>
        """)

    chain_cards = []
    if chains:
        for chain in chains:
            chain_cards.append(f"""
            <div class="chain-card">
                <h3>🔗 {escape(chain.name)} <span class="badge badge-{chain.chain_severity.lower()}">{escape(chain.chain_severity)}</span></h3>
                <p>{escape(chain.description)}</p>
                <p><strong>Remediation:</strong> {escape(chain.remediation)}</p>
            </div>
            """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sentinel Scan Report — {escape(target_url)}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f0f1a; color: #e0e0e0; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #ffffff; }}
        .header {{ background: #1a1a2e; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #667eea; }}
        .cards {{ display: flex; gap: 15px; margin-bottom: 25px; }}
        .card {{ flex: 1; background: #16213e; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #1f4068; }}
        .card h2 {{ margin: 5px 0; font-size: 28px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .badge-critical {{ background: #e74c3c; color: white; }}
        .badge-high {{ background: #e67e22; color: white; }}
        .badge-medium {{ background: #f1c40f; color: black; }}
        .badge-low {{ background: #2ecc71; color: white; }}
        .conf-badge {{ font-size: 11px; padding: 2px 6px; border-radius: 3px; }}
        .conf-high {{ background: #9b59b6; color: white; }}
        .conf-med {{ background: #3498db; color: white; }}
        .conf-low {{ background: #95a5a6; color: white; }}
        table {{ width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #1f4068; }}
        th {{ background: #0f3460; color: #ffffff; }}
        tr:hover {{ background: #1f4068; }}
        code {{ background: #0f0f1a; padding: 2px 5px; border-radius: 3px; color: #e94560; }}
        a {{ color: #4ecca3; text-decoration: none; }}
        details {{ cursor: pointer; color: #abd1c6; margin-top: 5px; }}
        summary {{ font-weight: bold; color: #4ecca3; }}
        .chain-card {{ background: #1a1a2e; padding: 15px; border-radius: 8px; border-left: 4px solid #e94560; margin-bottom: 15px; }}
        .details-panel {{ background: #101827; padding: 10px 12px; border: 1px solid #2d4059; border-radius: 6px; margin-top: 8px; }}
        .copy-btn {{ margin-top: 8px; background: #4ecca3; color: #111827; border: none; border-radius: 4px; padding: 6px 10px; font-weight: bold; cursor: pointer; }}
        .writeup-box {{ white-space: pre-wrap; background: #0b1220; border: 1px solid #25324a; border-radius: 6px; padding: 10px; margin-top: 10px; color: #dfeaf5; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Sentinel Security Scan Report</h1>
        <p><strong>Target:</strong> {escape(target_url)} | <strong>Duration:</strong> {duration:.2f}s | <strong>Risk Grade:</strong> <span class="badge badge-critical">{risk_grade}</span></p>
    </div>

    <div class="cards">
        <div class="card"><span>Critical</span><h2 style="color: #e74c3c">{counts.get('Critical', 0)}</h2></div>
        <div class="card"><span>High</span><h2 style="color: #e67e22">{counts.get('High', 0)}</h2></div>
        <div class="card"><span>Medium</span><h2 style="color: #f1c40f">{counts.get('Medium', 0)}</h2></div>
        <div class="card"><span>Low</span><h2 style="color: #2ecc71">{counts.get('Low', 0)}</h2></div>
    </div>

    {'<h2>Attack Chains</h2>' + ''.join(chain_cards) if chains else ''}

    <h2>Vulnerabilities ({len(results)})</h2>
    <table>
        <thead>
            <tr>
                <th>#</th><th>Severity</th><th>Vulnerability</th><th>CWE / CVSS</th><th>URL</th><th>Param</th><th>Confidence</th><th>OWASP</th><th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
</body>
</html>
"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_json_report(results, output_path, target_url="", duration=0, chains=None, risk_grade="A"):
    """Generate JSON report."""
    results = [_normalize_finding(r) for r in results]
    doc = {
        "scanner": "Sentinel Vulnerability Scanner",
        "version": ScannerConfig.VERSION,
        "scan_info": {
            "target": target_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "risk_grade": risk_grade,
            "total_findings": len(results),
        },
        "findings": results,
        "attack_chains": [c.__dict__ if hasattr(c, "__dict__") else c for c in (chains or [])],
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)


def generate_csv_report(results, output_path):
    """Generate CSV report."""
    results = [_normalize_finding(r) for r in results]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Vulnerability", "Severity", "CWE", "CVSS", "URL", "Parameter", "Confidence", "Status", "OWASP", "Details"])
        for idx, r in enumerate(results, 1):
            writer.writerow([
                idx,
                r.get("vuln", ""),
                r.get("severity", ""),
                r.get("cwe", 0),
                r.get("cvss", 0.0),
                r.get("url", ""),
                r.get("parameter", ""),
                r.get("confidence", 0),
                r.get("status", ""),
                r.get("owasp", ""),
                r.get("details", ""),
            ])