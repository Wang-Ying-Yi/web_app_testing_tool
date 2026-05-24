import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_target(base_url, session=None):
    """
    Crawls the target domain to build a map of entry points (links and forms).
    """
    print(f"[*] Initializing asset discovery crawl on: {base_url}")
    target_domain = urlparse(base_url).netloc
    urls_to_visit = [base_url]
    visited_urls = set()
    discovered_forms = []

    http_client = session if session else requests.Session()

    while urls_to_visit and len(visited_urls) < 15: # Safety limit for depth
        current_url = urls_to_visit.pop(0)
        if current_url in visited_urls:
            continue
            
        try:
            response = http_client.get(current_url, timeout=5)
            visited_urls.add(current_url)
            
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Find links
            for anchor in soup.find_all('a', href=True):
                full_url = urljoin(current_url, anchor['href'])
                # Stay within target domain boundary
                if urlparse(full_url).netloc == target_domain and full_url not in visited_urls:
                    urls_to_visit.append(full_url)
            
            # Find input forms
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                
                discovered_forms.append({
                    "action_url": urljoin(current_url, form_action),
                    "method": form_method,
                    "inputs": inputs
                })
                
        except Exception as e:
            print(f"[-] Crawl wrapper skipped endpoint {current_url}: {e}")

    print(f"[+] Asset discovery finished. Found {len(visited_urls)} paths and {len(discovered_forms)} input surfaces.")
    return list(visited_urls), discovered_forms