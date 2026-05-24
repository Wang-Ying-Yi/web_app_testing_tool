import os
import sys
import json
import requests
import subprocess
from datetime import datetime

# Target your local LM Studio Instance running on your host adapter
LM_STUDIO_URL = "http://192.168.56.1:1234/v1/chat/completions"
MODEL_SIGNATURE = "google/gemma-4-e4b"

def query_local_lm_studio(prompt):
    """Queries your local Gemma model to validate the target configuration layout."""
    payload = {
        "model": MODEL_SIGNATURE,
        "messages": [
            {
                "role": "system",
                "content": "You are an automated security routing assistant. Respond ONLY with a valid raw JSON object. Never use markdown code blocks like ```json."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1
    }
    
    try:
        response = requests.post(LM_STUDIO_URL, json=payload, timeout=20)
        response.raise_for_status() 
        response_json = response.json()
        
        choices = response_json.get('choices', [])
        if not choices:
            return None
            
        message_obj = choices[0].get('message', {})
        content_text = message_obj.get('content', '').strip() if isinstance(message_obj, dict) else getattr(message_obj, 'content', '').strip()

        if not content_text:
            return {"should_scan": True, "reason": "Fallback bypass triggered due to empty response string."}

        # Clear markdown formatting wraps safely if they leak through
        if content_text.startswith("```"):
            content_text = content_text.split("```")[1]
            if content_text.startswith("json"):
                content_text = content_text[4:]
        content_text = content_text.strip()

        return json.loads(content_text)
    except Exception as e:
        print(f"[-] LM Studio server error details: {e}")
        return None

def main():
    print("=" * 60)
    print("             AI-AUGMENTED SECURITY AGENT ROUTER            ")
    print("=" * 60)
    
    # Allows you to insert the website manually in the terminal console
    target_url = input("Enter the website target URL to scan (e.g., http://localhost:3000): ").strip()
    
    if not target_url:
        print("[-] Error: No website targeted. Exiting.")
        sys.exit(1)

    print(f"\n[*] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Local AI Agent ({MODEL_SIGNATURE}) evaluating target...")
    print(f"[*] Checking safety boundary configurations for target: {target_url}")
    
    ai_prompt = f"""
    Analyze this target string: '{target_url}'.
    Return a JSON object matching this structure exactly, with no additional conversational text:
    {{
        "should_scan": true,
        "reason": "Provide a brief structural validation explanation here"
    }}
    Set should_scan to true if the URL appears to be a normal web application target interface.
    """
    
    # Run safety checks via Gemma
    decision = query_local_lm_studio(ai_prompt)
    
    if decision and decision.get("should_scan"):
        print(f"[+] AI Agent Approved Scan. Reason: {decision.get('reason')}")
        try:
            print("[*] Launching main.py test pipeline loop (Timeout limit: 60s)...")
            
            # Streams console logs live to your terminal screen
            process_execution = subprocess.run(
                [sys.executable, "main.py", "-t", target_url],
                text=True,
                timeout=60  # Strict 1-minute runtime constraint boundary
            )
            print(f"\n[+] Active pipeline testing cycle finished executing with code: {process_execution.returncode}")
            
        except subprocess.TimeoutExpired:
            print("[!] Processing threshold reached 1 minute constraint cutoff. Safety termination invoked.")
        except Exception as e:
            print(f"[-] Operational workflow dispatch crash: {e}")
    else:
        reason = decision.get('reason') if decision else "Local model connection error or bad response structure."
        print(f"[-] AI Agent Rejected Scan for target {target_url}. Reason: {reason}")

if __name__ == "__main__":
    main()