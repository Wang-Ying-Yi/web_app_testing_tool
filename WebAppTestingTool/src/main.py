from src.sql_injection import check_sql_injection
from xss_detection import check_xss
from brute_force import brute_force_login
from header_check import check_http_headers
from directory_traversal import check_directory_traversal
from report_generator import generate_report

def run_all_tests(url):
    results = {}
    
    # Run each individual test and store the results
    results['sql_injection'] = check_sql_injection(url)
    results['xss'] = check_xss(url, params={})
    results['brute_force'] = brute_force_login(url, ['admin'], ['password', '123456'])
    results['http_headers'] = check_http_headers(url)
    results['directory_traversal'] = check_directory_traversal(url)
    
    # Generate a final report
    generate_report(results)

# Example usage
# For quick testing of your tool, OWASP Juice Shop and PortSwigger Web Security Academy are easy to access and don’t require setup.
url = "http://example.com"
run_all_tests(url)
