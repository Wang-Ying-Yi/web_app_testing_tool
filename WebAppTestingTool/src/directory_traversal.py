import requests

def check_directory_traversal(url):
    traversal_payloads = ['../../etc/passwd', '../../../etc/hosts']
    
    for payload in traversal_payloads:
        response = requests.get(url + payload)
        if "root:" in response.text:  # Checking for content of /etc/passwd
            print(f"Directory traversal vulnerability found at {url}")
        else:
            print(f"No directory traversal vulnerability at {url}")
