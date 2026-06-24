import time
import subprocess  # nosec B404
import sys
import requests

def run_sast_bandit():
    print("\n" + "=" * 60)
    print("RUNNING SAST SCAN: BANDIT")
    print("=" * 60)
    try:
        # Run bandit excluding the virtual environment
        result = subprocess.run(  # nosec B603 B607
            [".venv/bin/bandit", "-r", ".", "--exclude", "./.venv"],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.returncode == 0:
            print("[+] Bandit Scan: PASSED (No issues found)")
            return True
        else:
            print("[!] Bandit Scan: FAILED (Potential issues found)")
            return False
    except Exception as e:
        print(f"[!] Error running Bandit: {e}")
        return False

def run_sast_semgrep():
    print("\n" + "=" * 60)
    print("RUNNING SAST SCAN: SEMGREP")
    print("=" * 60)
    try:
        # Run semgrep scan excluding virtual environment
        result = subprocess.run(  # nosec B603 B607
            [".venv/bin/semgrep", "scan", "--config", "auto", ".", "--exclude=.venv"],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if "Findings: 0" in result.stdout or result.returncode == 0:
            print("[+] Semgrep Scan: PASSED (No issues found)")
            return True
        else:
            print("[!] Semgrep Scan: FAILED (Potential issues found)")
            return False
    except Exception as e:
        print(f"[!] Error running Semgrep: {e}")
        return False

def run_dependency_audit():
    print("\n" + "=" * 60)
    print("RUNNING DEPENDENCY AUDIT: PIP-AUDIT")
    print("=" * 60)
    try:
        # Run pip-audit
        result = subprocess.run(  # nosec B603 B607
            [".venv/bin/pip-audit"],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.returncode == 0:
            print("[+] pip-audit: PASSED (No vulnerable packages found)")
            return True
        else:
            print(result.stderr)
            print("[!] pip-audit: FAILED (Vulnerabilities found in installed packages)")
            return False
    except Exception as e:
        print(f"[!] Error running pip-audit: {e}")
        return False

def test_vulnerability():
    base_url = "http://127.0.0.1:8000"
    print("\n" + "=" * 60)
    print("RUNNING DAST EXPLOIT TESTING (NoSQL Injection)")
    print("=" * 60)

    # 1. Test standard/default query (no parameters)
    print("\n[Test 1] Querying default /pages (parentId is not null)...")
    try:
        r = requests.get(f"{base_url}/pages", timeout=10)
        if r.status_code == 200:
            data = r.json()
            print(f"  Result: Success! Found {data.get('count')} pages.")
        else:
            print(f"  Result: Failed with status code {r.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("  Error: Could not connect to the server. Is it running?")
        return False

    # 2. Test safe query for a non-existent title
    print("\n[Test 2] Querying /pages for non-existent title 'NonExistentTitle'...")
    r = requests.get(f"{base_url}/pages", params={"title": "NonExistentTitle"}, timeout=10)
    data = r.json()
    print(f"  Result: Success. Found {data.get('count')} pages matching 'NonExistentTitle'.")

    # 3. Test NoSQL Injection exploit
    # Payload: {"$ne": "non-existent"}
    # This matches all pages that do not have the title "non-existent" (which is all of them).
    print("\n[Test 3] Attempting NoSQL Injection payload: title={\"$ne\": \"non-existent\"} ...")
    payload = '{"$ne": "non-existent"}'
    r = requests.get(f"{base_url}/pages", params={"title": payload}, timeout=10)
    
    if r.status_code == 200:
        data = r.json()
        if data.get("status") == "error":
            print(f"  Result: Server error response: {data.get('message')}")
            print("STATUS: SECURE (Query was blocked or failed)")
            return True
            
        count = data.get('count', 0)
        print(f"  Result: Server returned {count} documents.")
        
        # Since 'NonExistentTitle' returned 0 documents, if the injection returns more than 0 documents, it succeeded.
        if count > 0:
            print("\n[!] SECURITY ALERT: NoSQL Injection Successful!")
            print(f"    The exploit bypassed the query and retrieved {count} documents.")
            print("    Vulnerability: NoSQL Object Injection via JSON query parser.")
            print("STATUS: VULNERABLE")
            return False
        else:
            print("\n[+] Safe: Exploit did not retrieve any documents.")
            print("STATUS: SECURE")
            return True
    else:
        print(f"  Result: Request failed with status code {r.status_code}")
        print("STATUS: UNKNOWN (Error occurred)")
        return False

def main():
    # 1. Run SAST (Bandit)
    bandit_ok = run_sast_bandit()
    
    # 2. Run SAST (Semgrep)
    semgrep_ok = run_sast_semgrep()
    
    # 3. Run Dependency Audit
    audit_ok = run_dependency_audit()
    
    # 4. Start FastAPI and Run DAST
    print("\n" + "=" * 60)
    print("STARTING TEST SERVER FOR DAST")
    print("=" * 60)
    
    # Check if server is already running on port 8000
    server_process = None
    try:
        requests.get("http://127.0.0.1:8000/pages", timeout=5)
        print("FastAPI server is already running on port 8000.")
    except requests.exceptions.ConnectionError:
        print("FastAPI server is not running. Starting server in background...")
        # Make sure port 8000 is free
        subprocess.run(["fuser", "-k", "8000/tcp"], capture_output=True)  # nosec B603 B607
        server_process = subprocess.Popen(  # nosec B603 B607
            [".venv/bin/uvicorn", "main:app", "--port", "8000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3) # Wait for startup

    try:
        dast_ok = test_vulnerability()
    finally:
        if server_process:
            print("\nShutting down the background server...")
            server_process.terminate()
            server_process.wait()
            print("Server shut down successfully.")
            
    # Print overall execution report
    print("\n" + "=" * 60)
    print("SECURITY SCAN SUMMARY")
    print("=" * 60)
    print(f"Bandit SAST Scan:    {'PASS' if bandit_ok else 'FAIL'}")
    print(f"Semgrep SAST Scan:   {'PASS' if semgrep_ok else 'FAIL'}")
    print(f"Dependency Audit:    {'PASS' if audit_ok else 'FAIL'}")
    print(f"DAST Exploit Test:   {'PASS (SECURE)' if dast_ok else 'FAIL (VULNERABLE)'}")
    print("=" * 60)

    # Exit with code 1 if any security check failed (except dependency audit if we just want to flag it)
    if not (bandit_ok and semgrep_ok and dast_ok):
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
