import json

data = json.load(open('results/scan_report.json', 'r', encoding='utf-8'))
print(f"Total: {data['total_findings']} | Confirmed: {data['confirmed']} | Possible: {data['possible']}\n")

for i, r in enumerate(data['scan_results'], 1):
    conf = r.get('confidence', 0)
    status = r.get('status', 'UNKNOWN')
    sev = r.get('severity', 'Medium')
    vuln = r.get('vuln', 'Unknown')
    url = r.get('url', '')[:60]
    param = r.get('parameter', '')
    signals = r.get('signals', [])
    sig_str = ', '.join(str(s) for s in signals) if isinstance(signals, list) else str(signals)
    print(f"{i:2d}. [{conf:3d}% {status:10s}] [{sev:8s}] {vuln}")
    print(f"    URL: {url}")
    if param:
        print(f"    Param: {param}")
    if sig_str:
        print(f"    Signals: {sig_str}")
    print()
