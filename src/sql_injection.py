import requests

def check_sql_injection(url, session=None):
    """
    Oracle-based Boolean Blind SQLi Testing Engine.
    """
    http_client = session if session else requests.Session()
    
    # Baseline comparison request
    try:
        baseline_resp = http_client.get(url, params={"id": "1"}, timeout=5)
        baseline_len = len(baseline_resp.text)
    except requests.RequestException:
        return {"vulnerable": False, "severity": "Informational", "cvss": 0.0, "details": "Unreachable target"}

    # Pairs of True and False statements
    boolean_tests = [
        {"true": "1 AND 1=1", "false": "1 AND 1=2"},
        {"true": "1' AND '1'='1", "false": "1' AND '1'='2"}
    ]

    for test in boolean_tests:
        try:
            resp_true = http_client.get(url, params={"id": test["true"]}, timeout=5)
            resp_false = http_client.get(url, params={"id": test["false"]}, timeout=5)
            
            # Vulnerability confirmed if True matches the baseline but False alters application behavior
            if len(resp_true.text) == baseline_len and len(resp_false.text) != baseline_len:
                return {
                    "vulnerable": True,
                    "severity": "Critical",
                    "cvss": 9.8,
                    "details": f"Confirmed Boolean Blind SQL Injection via parameter manipulation using payload balance: {test['true']}"
                }
        except requests.RequestException:
            continue

    return {"vulnerable": False, "severity": "Informational", "cvss": 0.0, "details": "No SQL injection detected via parameter injection vectors."}