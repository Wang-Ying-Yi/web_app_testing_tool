import argparse
import sys
import requests
from concurrent.futures import ThreadPoolExecutor

# Import your active web scanning modules
from xss_detection import check_xss
from directory_traversal import check_directory_traversal
from brute_force import brute_force_login
from report_generator import generate_report

def run_web_scan_pipeline(target_url):
    """
    Coordinates active web scanning modules concurrently using a shared session state
    and sends aggregated findings to the report generator.
    """
    print("=" * 70)
    print(f"[*] Initializing Active DAST Web Scanning Suite")
    print(f"[*] Target URL: {target_url}")
    print("=" * 70)

    # Initialize a shared session context for the scan cycle
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebAppTestingTool/1.0"
    })

    # Dictionary map to store security findings to pass to the report
    scan_results = {}

    # Define tasks for our thread worker execution grid
    # Mapping readable finding names -> Lambda functions wrapping our imported modules
    tasks = {
        "Reflected Cross-Site Scripting (XSS) Input Probing": lambda: check_xss(target_url, session=session),
        "Local Path & Directory Traversal Vulnerability Test": lambda: check_directory_traversal(target_url, session=session),
        "Weak Form Authentication Credential Brute-Force": lambda: brute_force_login(target_url, session=session)
    }

    print(f"[*] Dispatching concurrent worker threads against target application modules...")
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all target scanner functions concurrently
        future_to_module = {executor.submit(task): name for name, task in tasks.items()}
        
        for future in future_to_module:
            module_name = future_to_module[future]
            try:
                result = future.result()
                # If the module found a true vulnerability, store it in our report tracking map
                if result and result.get("vulnerable"):
                    print(f"[!] DANGER: {module_name} confirmed a vulnerability status!")
                    scan_results[module_name] = {
                        "severity": result.get("severity", "High"),
                        "cvss": result.get("cvss", 7.0),
                        "details": result.get("details", ["Vulnerability signature detected."])
                    }
                else:
                    print(f"[+] Clean: {module_name} completed with no vulnerabilities flagged.")
            except Exception as e:
                print(f"[-] Module crash encountered on thread '{module_name}': {e}")

    print(f"\n[+] Active scanning pass finalized. Compiling {len(scan_results)} verified threat vectors.")
    
    # Send findings array to your report generator to trigger Gemma 4 analysis
    generate_report(scan_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Active Web Application Security Assessment Engine")
    parser.add_argument("-t", "--target", help="The target application web URL string to scan (e.g., http://localhost:3000)")
    args = parser.parse_args()

    if args.target:
        scan_target = args.target
    else:
        print("=" * 60)
        print("         ACTIVE WEB APPLICATION TESTING FRAMEWORK         ")
        print("=" * 60)
        scan_target = input("Enter target website URL: ").strip()
        print()

    if not scan_target:
        print("[-] Error: No active web target designated. Exiting pipeline loop.")
        sys.exit(1)

    # Automatically normalize target url string format constraints if protocols leak out
    if not scan_target.startswith("http://") and not scan_target.startswith("https://"):
        scan_target = "http://" + scan_target

    run_web_scan_pipeline(scan_target)