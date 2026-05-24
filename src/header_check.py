import requests

def check_http_headers(url, session=None):
    """
    Evaluates defensive proxy attributes and security headers, outputting standard CVSS values.
    """
    http_client = session if session else requests.Session()
    missing_findings = []
    max_cvss = 0.0
    
    try:
        response = http_client.get(url, timeout=5)
        headers = response.headers
    except requests.RequestException as e:
        return {"error": f"Failed connection layout mapping: {e}"}

    security_headers = {
        'X-Frame-Options': {"severity": "Low", "cvss": 3.4, "desc": "Missing anti-clickjacking protection surface."},
        'Content-Security-Policy': {"severity": "Medium", "cvss": 5.3, "desc": "Missing inline execution boundaries (CSP)."},
        'Strict-Transport-Security': {"severity": "Low", "cvss": 2.5, "desc": "Missing strict HTTPS forcing (HSTS)."}
    }

    for header, matrix in security_headers.items():
        if header not in headers:
            missing_findings.append(matrix["desc"])
            if matrix["cvss"] > max_cvss:
                max_cvss = matrix["cvss"]

    severity = "Informational" if max_cvss == 0.0 else ("Medium" if max_cvss >= 5.0 else "Low")

    return {
        "vulnerable": len(missing_findings) > 0,
        "severity": severity,
        "cvss": max_cvss,
        "details": missing_findings if missing_findings else "All foundational defensive HTTP response controls passed."
    }