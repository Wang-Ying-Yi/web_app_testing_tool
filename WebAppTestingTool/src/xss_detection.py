import requests

def check_xss(url, params):
    xss_payload = "<script>alert('XSS')</script>"
    params['input'] = xss_payload  # Inject XSS payload in the input field
    response = requests.get(url, params=params)
    
    if xss_payload in response.text:
        print(f"Possible XSS vulnerability found at {url}")
    else:
        print(f"No XSS vulnerability at {url}")
