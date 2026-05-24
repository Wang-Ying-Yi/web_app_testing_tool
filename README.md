# AI-Augmented DAST Scanner Framework

An automated, multi-threaded **Dynamic Application Security Testing (DAST)** framework designed to actively probe web applications for critical security flaws. The tool seamlessly couples high-speed concurrent network analysis with a localized threat intelligence pipeline powered by **Gemma 4** to generate comprehensive, engineer-focused remediation playbooks inside a responsive web dashboard.

---

## Key Features

* **Intelligent Target Verification:** Features a localised AI Router checkpoint that pre-evaluates input URLs to validate scope and ensure compliance with automated testing safety boundaries.
* **Multi-Threaded Execution Grid:** Dispatches active vulnerability scanners concurrently via a high-performance thread pool, drastically reducing execution time to fit within strict 1-minute runtime continuous integration (CI/CD) boundaries.
* **Modern Web Stack Compatibility:** Upgraded to handle both traditional form-based architectures and modern Single Page Applications (SPAs), including JSON-based REST API endpoints and client-side hash routing parameters (e.g., OWASP Juice Shop).
* **Local AI Triaging & Impact Analysis:** Communicates via local loopback endpoints with a local LLM instance to perform deep risk evaluations without sending sensitive data over the internet.
* **Interactive Security Dashboard:** Dynamically compiles raw JSON security findings into a clean, modern, responsive frontend report that launches natively in your system browser upon scan completion.

---

## Core Security Analysis Modules

1. **Reflected Cross-Site Scripting (XSS):** Automatically maps DOM/Reflected vector paths and evaluates input field sanitisation by injecting strict validation payloads across classic and hash-routed parameters.
2. **Path & Directory Traversal:** Probes parameters against system boundaries to identify arbitrary local file access vulnerabilities.
3. **Weak Credential Brute-Force Engine:** Performs targeted authentication testing using a minimised high-risk credential matrix optimised for both traditional login panels and modern JSON REST API backends.

---

## Project Structure

```text
├── src/
│   ├── ai_agent.py          # AI Orchestrator, URL validator & safety router
│   ├── main.py              # Core multi-threaded pipeline driver & execution matrix
│   ├── xss_detection.py     # Script reflection vulnerability scanner
│   ├── directory_traversal.py # Arbitrary path traversal scanner
│   ├── brute_force.py       # JSON/Form authentication validation scanner
│   └── report_generator.py  # Local Gemma log enrichment engine & HTML compiler
└── .gitignore               # Strict log, cache, and environment tracking exclusions
```

---
## Environment Prerequisites

1. Python Environment
Ensure you have Python 3.10+ installed. Install the necessary baseline network and web testing dependencies:


2. Local AI Configuration (LM Studio)
This framework uses a local inference engine to ensure data privacy:
```Bash
pip install requests flask
```

* Download and run LM Studio.
* Load the google/gemma-4-e4b model signature.
* Start the Local Server on the default host adapter port

---

## Usage Guide
1. Navigate to your project directory and start the orchestrator:
```Bash
cd src
python ai_agent.py
```
2. Enter the target URL string when prompted by the console:
```Plaintext
Enter the website target URL to scan (e.g., http://localhost:3000): http://localhost:3000
```
3. Watch the multi-threaded execution run live. Upon completion, your default web browser will automatically open the compiled dashboard (reports/report.html), complete with custom AI-generated mitigation instructions!

---
## Security & Safe Usage Disclaimer
CRITICAL NOTE: This tool is designed purely for authorised security research, local application debugging, and educational profiling. Never run active DAST scanning modules against public infrastructure or web properties without explicit, written legal authorisation from the asset owners.
