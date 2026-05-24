import json
import os
import requests
import webbrowser

# Target your local LM Studio Instance running on your host adapter
LM_STUDIO_URL = "http://192.168.56.1:1234/v1/chat/completions"
MODEL_SIGNATURE = "google/gemma-4-e4b"

def get_ai_vulnerability_analysis(finding_title, details):
    """
    Queries the local Gemma model via LM Studio to get automated 
    remediation and impact instructions for active web vulnerabilities.
    """
    prompt = f"""
    You are a Senior Application Security Engineer generating an executive remediation report.
    Analyze this security finding: '{finding_title}'
    Specific missing items/details: {details}

    Provide your assessment strictly in a valid JSON object matching this structure exactly (do not include markdown wrapping):
    {{
        "impact": "A clear, concise one-sentence explanation of what an attacker could achieve due to this misconfiguration.",
        "remediation": {{
            "step1": "First explicit fix step instruction with code or configuration example if applicable",
            "step2": "Second explicit fix step instruction with code or configuration example if applicable",
            "note": "Any operational deployment warnings or guidance"
        }}
    }}
    """
    payload = {
        "model": MODEL_SIGNATURE,
        "messages": [
            {
                "role": "system", 
                "content": "You are a professional AppSec reporting engine. You must output raw JSON objects only, without using markdown code blocks like ```json."
            },
            {
                "role": "user", 
                "content": prompt
            }
        ],
        "temperature": 0.1
    }
    
    try:
        response = requests.post(LM_STUDIO_URL, json=payload, timeout=25)
        response.raise_for_status()
        content_text = response.json()['choices'][0]['message']['content'].strip()
        
        # Defensive strip layer if the model forces markdown blocks despite system prompt
        if content_text.startswith("```"):
            content_text = content_text.split("```")[1]
            if content_text.startswith("json"):
                content_text = content_text[4:]
        content_text = content_text.strip()
        
        return json.loads(content_text)
    except Exception as e:
        print(f"[-] AI report enrichment failed: {e}")
        return {
            "impact": "Analysis unavailable. Local AI engine was offline or slow to respond.",
            "remediation": "Review industry standard defensive guidelines (OWASP / CWE) to fix this gap manually."
        }

def generate_report(results):
    """
    Takes scan outputs, builds a folder under the reports directory path,
    queries Gemma for insights, and compiles an interactive active scan dashboard.
    """
    output_dir = r"F:\web_app_testing_tool\WebAppTestingTool\reports"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    json_filename = os.path.join(output_dir, 'report.json')
    html_filename = os.path.join(output_dir, 'report.html')

    # Save raw backend logs cleanly
    try:
        with open(json_filename, 'w', encoding='utf-8') as report_file:
            json.dump(results, report_file, indent=4)
        print(f"[+] Raw JSON log path successfully updated: {json_filename}")
    except Exception as e:
        print(f"[-] Failed to write JSON log: {e}")

    # Build the HTML Dashboard Framework
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemma-Enriched Automated Security Scan Report</title>
    <link href="[https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/dist/css/bootstrap.min.css](https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/dist/css/bootstrap.min.css)" rel="stylesheet">
    <style>
        body { background-color: #f4f6f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        .card { border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.05); border-radius: 12px; margin-bottom: 2rem; }
        .badge-critical { background-color: #dc3545; color: white; }
        .badge-high { background-color: #fd7e14; color: white; }
        .badge-medium { background-color: #ffc107; color: #212529; }
        .badge-low { background-color: #0dcaf0; color: white; }
        .badge-informational { background-color: #6c757d; color: white; }
        .ai-analysis-box { background-color: #f8f9ff; border-left: 4px solid #4f46e5; border-radius: 4px; padding: 1.25rem; margin-top: 1rem; }
        .step-container { background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
        .step-badge { font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 0.35em 0.65em; }
        .remediation-box { background-color: #ffffff; border: 1px solid #e3e6f0; border-radius: 8px; padding: 1.25rem; }
    </style>
</head>
<body>

<div class="container my-5">
    <div class="p-5 mb-4 bg-dark text-white rounded-3 card">
        <div class="container-fluid py-2">
            <h1 class="display-5 fw-bold">Automated Vulnerability Assessment Report</h1>
            <p class="col-md-8 fs-5 text-muted">Gemma-Augmented Dynamic Application Security Testing (DAST) Engine Outputs</p>
            <hr class="border-secondary">
            <div class="d-flex gap-4">
                <div><strong>Status:</strong> <span class="badge bg-success">Scan Complete</span></div>
                <div><strong>Total Findings:</strong> <span class="badge bg-primary">""" + str(len(results)) + """</span></div>
            </div>
        </div>
    </div>

    <h3 class="mb-4 text-secondary">Identified Security Deficiencies</h3>
"""

    if not results:
        html_content += """
    <div class="card p-5 text-center text-muted">
        🎉 No security vulnerabilities or surface gaps were explicitly identified during this pass.
    </div>
        """
    else:
        for target, data in results.items():
            if isinstance(data, dict):
                severity = data.get("severity", "Informational")
                cvss = data.get("cvss", 0.0)
                details = data.get("details", "No detailed documentation provided.")
            else:
                severity = "Informational"
                cvss = 0.0
                details = str(data)

            badge_class = f"badge-{severity.lower()}"
            
            if isinstance(details, list):
                details_html = "<ul class='mb-0'>" + "".join([f"<li>{item}</li>" for item in details]) + "</ul>"
            else:
                details_html = details

            print(f"[*] Requesting local Gemma analysis for vulnerability module: {target}...")
            ai_analysis = get_ai_vulnerability_analysis(target, str(details))

            # --- SMART REMEDIATION FORMATTING ENGINE ---
            rere_content = ai_analysis.get('remediation', '')
            remediation_html = ""

            if isinstance(rere_content, dict):
                for step_key, step_value in rere_content.items():
                    clean_text = str(step_value).replace(r'\n', '\n').strip()
                    
                    if "step" in step_key.lower():
                        remediation_html += f"""
                        <div class="step-container shadow-sm">
                            <span class="badge bg-secondary step-badge mb-2">{step_key}</span>
                            <div style="white-space: pre-wrap; font-family: initial;" class="text-dark">{clean_text}</div>
                        </div>"""
                    elif "note" in step_key.lower():
                        remediation_html += f"""
                        <div class="alert alert-warning py-2 px-3 mt-2" role="alert" style="font-size: 0.9rem;">
                            <strong>Operational Note:</strong> <span style="white-space: pre-wrap;">{clean_text}</span>
                        </div>"""
                    else:
                        remediation_html += f"""
                        <div class="mb-2">
                            <strong>{step_key.title()}:</strong> 
                            <span class="text-muted" style="white-space: pre-wrap;">{clean_text}</span>
                        </div>"""
            else:
                clean_text = str(rere_content).replace(r'\n', '\n').strip()
                remediation_html = f"<div style='white-space: pre-wrap;' class='text-muted'>{clean_text}</div>"

            html_content += f"""
    <div class="card p-4">
        <div class="d-flex justify-content-between align-items-center border-bottom pb-3 mb-3">
            <h4 class="text-dark mb-0 text-break">{target}</h4>
            <div class="d-flex gap-2">
                <span class="badge {badge_class} px-3 py-2 fs-6">{severity}</span>
                <span class="badge bg-secondary px-3 py-2 fs-6">CVSS {cvss:.1f}</span>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-12">
                <h5 class="text-secondary">Technical Detection Details:</h5>
                <div class="text-muted bg-light p-3 rounded" style="border: 1px solid #eaecf2;">{details_html}</div>
            </div>
        </div>

        <div class="ai-analysis-box">
            <h5 class="d-flex align-items-center mb-3" style="color: #4f46e5;">
                <svg class="me-2" width="20" height="20" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M6 12.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5ZM3 8.062C3 6.716 4.055 5.5 5.5 5.5a2.5 2.5 0 0 1 4.717-1.13 2.5 2.5 0 0 1 1.44 3.731C12.443 8.643 13 9.61 13 10.75a2.25 2.25 0 0 1-2.25 2.25h-5.5A2.25 2.25 0 0 1 3 10.75c0-1.14.557-2.107 1.343-2.688A2.484 2.484 0 0 1 3 8.062Z"/>
                </svg>
                Local AI Agent Risk Intelligence Analysis (Gemma)
            </h5>
            <div class="mb-4">
                <strong class="text-dark">Potential Threat Impact:</strong> 
                <p class="text-muted mt-1 bg-white p-3 border rounded shadow-sm">{ai_analysis.get('impact', 'No threat impact analysis was returned.')}</p>
            </div>
            <div>
                <strong class="text-dark d-block mb-2">Recommended Engineering Remediation:</strong>
                <div class="remediation-box">
                    {remediation_html}
                </div>
            </div>
        </div>
    </div>
            """

    html_content += """
    <footer class="text-center text-muted mt-5 fs-7">
        <p>Generated automatically via Core AI-Augmented Security Automation Framework.</p>
    </footer>
</div>

<script src="[https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/dist/js/bootstrap.bundle.min.js](https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/dist/js/bootstrap.bundle.min.js)"></script>
</body>
</html>
"""

    try:
        with open(html_filename, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)
        print(f"[+] AI-Enriched HTML dashboard compiled successfully: {html_filename}")
        
        file_path = os.path.abspath(html_filename)
        webbrowser.open(f"file:///{file_path}")
        print("[*] Dashboard viewport updated inside default system browser.")
    except Exception as e:
        print(f"[-] Failed to generate or open HTML report: {e}")