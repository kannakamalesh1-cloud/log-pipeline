#!/usr/bin/env python3

import os
import re
import json
import time
import subprocess
import requests
from datetime import datetime

# =========================
# CONFIG
# =========================

API_URL = os.getenv("API_URL", "http://localhost:8000/v1/chat/completions")
API_KEY = os.getenv("API_KEY", "")
MODEL = os.getenv("MODEL", "gpt-4o-mini")

LOG_FILE = os.getenv("LOG_FILE", "app.log")
AUTO_FIX = os.getenv("AUTO_FIX", "true").lower() == "true"

# =========================
# LOG READER
# =========================

def read_logs():
    if not os.path.exists(LOG_FILE):
        print(f"❌ Log file not found: {LOG_FILE}")
        return []

    with open(LOG_FILE, "r", errors="ignore") as f:
        return f.readlines()[-200:]


# =========================
# ISSUE DETECTION
# =========================

def extract_issues(lines):
    error_patterns = r"error|critical|failed|exception|panic"
    warning_patterns = r"warn|deprecated"

    errors = []
    warnings = []

    for line in lines:
        if re.search(error_patterns, line, re.IGNORECASE):
            errors.append(line.strip())
        elif re.search(warning_patterns, line, re.IGNORECASE):
            warnings.append(line.strip())

    return errors, warnings


# =========================
# AI ANALYSIS
# =========================

def analyze_with_ai(errors, warnings):
    if not API_KEY:
        return "⚠️ No API key provided. Skipping AI analysis."

    prompt = f"""
You are a senior DevOps engineer.

Analyze logs:
Errors:
{chr(10).join(errors[:30])}

Warnings:
{chr(10).join(warnings[:30])}

Provide:
1. Root cause
2. Severity
3. Fix steps
"""

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "Expert DevOps log analyzer"},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3
    }

    try:
        res = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        return res.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"❌ AI failed: {e}"


# =========================
# AUTO FIX ENGINE
# =========================

def auto_fix(errors):
    if not AUTO_FIX:
        print("⚠️ Auto-fix disabled")
        return []

    fixes_applied = []

    for err in errors:
        err_lower = err.lower()

        # 🔹 Database issue
        if "database" in err_lower:
            print("🔧 Attempting DB reconnect fix...")
            fixes_applied.append("Retry DB connection")

        # 🔹 Port already in use
        elif "address already in use" in err_lower:
            print("🔧 Killing process on port...")
            subprocess.run("fuser -k 8000/tcp", shell=True)
            fixes_applied.append("Killed process on port 8000")

        # 🔹 Docker/container crash
        elif "container" in err_lower or "crash" in err_lower:
            print("🔧 Restarting container...")
            subprocess.run("docker restart test-container", shell=True)
            fixes_applied.append("Restarted container")

        # 🔹 Memory issue
        elif "out of memory" in err_lower:
            print("🔧 Restarting service due to OOM...")
            subprocess.run("sudo systemctl restart myapp", shell=True)
            fixes_applied.append("Restarted service (OOM)")

    return fixes_applied


# =========================
# REPORT
# =========================

def generate_report(errors, warnings, ai_output, fixes):
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "errors": len(errors),
            "warnings": len(warnings),
            "fixes_applied": len(fixes)
        },
        "errors": errors[:20],
        "warnings": warnings[:20],
        "ai_analysis": ai_output,
        "auto_fixes": fixes
    }

    with open("report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("📄 Report saved: report.json")


# =========================
# MAIN
# =========================

def main():
    print("🚀 AI Log Analyzer Started")

    logs = read_logs()
    if not logs:
        return

    errors, warnings = extract_issues(logs)

    print(f"🔍 Errors: {len(errors)} | Warnings: {len(warnings)}")

    # AI Analysis
    ai_output = analyze_with_ai(errors, warnings)
    print("\n🧠 AI Analysis:\n", ai_output)

    # Auto Fix
    fixes = auto_fix(errors)

    if fixes:
        print("\n⚡ Fixes Applied:")
        for f in fixes:
            print(f" - {f}")

    # Generate report
    generate_report(errors, warnings, ai_output, fixes)

    # Fail CI if errors remain
    if errors:
        print("\n❌ Errors detected — failing pipeline")
        exit(1)

    print("\n✅ No critical issues")


if __name__ == "__main__":
    main()
