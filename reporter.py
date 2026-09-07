import os

def generate_html_report(results, output_path='results/scan_report.html'):
    html = "<html><head><title>Scan Report</title></head><body>"
    html += "<h1>Website Vulnerability Scan Report</h1>"
    for r in results:
        html += f"<p><strong>{r['vuln']}</strong> at <a href='{r['url']}'>{r['url']}</a> - {r['status']}</p><hr>"
    html += "</body></html>"

    os.makedirs("results", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)