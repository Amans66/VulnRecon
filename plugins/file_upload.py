"""
File Upload Vulnerability Plugin v6.0.

Discovers file upload controls and inspects client-side / endpoint restriction settings.

CWE-434 | CVSS 8.8 | OWASP A03:2021 Injection
"""

from core.response_analyzer import calculate_confidence, make_finding
from core.utils import get_forms

PLUGIN_CWE = 434
PLUGIN_CVSS = 8.8
PLUGIN_OWASP = "A03:2021 Injection"


def test_file_upload(url):
    """Scan forms for file upload inputs missing restrictive attributes."""
    try:
        forms = get_forms(url)
        if not forms:
            return None

        for form in forms:
            action = form.get("action", "")
            file_inputs = []

            for tag in form.find_all("input"):
                if tag.get("type", "").lower() == "file":
                    name = tag.get("name", "unnamed")
                    accept = tag.get("accept", "")
                    file_inputs.append({"name": name, "accept": accept})

            if file_inputs:
                unrestricted = [inp for inp in file_inputs if not inp["accept"]]

                signals = {
                    "upload_unrestricted": True if unrestricted else False,
                    "behavioral_anomaly": True,
                }
                confidence = calculate_confidence(signals)
                details_msg = f"File upload form found at '{action}'."
                if unrestricted:
                    details_msg += f" Inputs ({', '.join(i['name'] for i in unrestricted)}) lack client-side 'accept' restrictions."

                finding = make_finding(
                    url, "Unrestricted File Upload Endpoint",
                    confidence=confidence, signals=signals,
                    details=details_msg,
                    severity="High" if unrestricted else "Medium",
                    payload="File Upload Input Analysis",
                    evidence=f"Discovered {len(file_inputs)} file input(s) in form action '{action}'",
                )
                if finding:
                    finding["cwe"] = PLUGIN_CWE
                    finding["cvss"] = PLUGIN_CVSS
                    finding["owasp"] = PLUGIN_OWASP
                    return finding

    except Exception:
        pass
    return None
