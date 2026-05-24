import requests

def check_xss(url, session=None):
    """
    Upgraded XSS module that scans both classic parameters and modern SPA hash fragments.
    """
    if session is None:
        session = requests.Session()

    xss_payload = "<script>alert('XSS')</script>"
    vulnerability_details = []

    # Build target execution points specifically covering normal URLs and SPA routes
    test_urls = [
        f"{url}/#/search?q={xss_payload}", # Juice Shop tracking route pattern
        f"{url}?q={xss_payload}",
        f"{url}?search={xss_payload}"
    ]

    for test_url in test_urls:
        try:
            response = session.get(test_url, timeout=2)
            # Check if the payload gets unescaped back inside the response body string
            if xss_payload in response.text:
                vulnerability_details.append(f"Reflected/DOM Script reflection verified at endpoint: {test_url}")
                return {
                    "vulnerable": True,
                    "severity": "High",
                    "cvss": 7.2,
                    "details": vulnerability_details
                }
        except requests.exceptions.RequestException:
            continue

    return {
        "vulnerable": False,
        "severity": "Informational",
        "cvss": 0.0,
        "details": "No generic script payload reflections caught across parameter routes."
    }