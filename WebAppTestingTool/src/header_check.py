import requests

def check_http_headers(url):
    response = requests.get(url)
    headers = response.headers
    
    if 'X-Frame-Options' not in headers:
        print(f"Missing X-Frame-Options header at {url}")
    if 'Content-Security-Policy' not in headers:
        print(f"Missing Content-Security-Policy header at {url}")
    if 'Strict-Transport-Security' not in headers:
        print(f"Missing Strict-Transport-Security header at {url}")
