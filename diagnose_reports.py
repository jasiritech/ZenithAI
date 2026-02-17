
import os
import tempfile
import json
from datetime import datetime
from zenith.core.knowledge_base import KnowledgeBase
from zenith.utils.report_generator import HTMLReportGenerator

def diagnose():
    print("=== ZENITH SYSTEM DIAGNOSIS ===")
    
    # 1. Check Temp Directory
    tmp = tempfile.gettempdir()
    print(f"[*] System Temp Directory: {tmp}")
    
    # 2. Test KnowledgeBase Saving
    print("[*] Testing KnowledgeBase...")
    try:
        kb = KnowledgeBase("diag.test.com")
        print(f"[+] KB DB File Path: {kb.db_file}")
        
        kb.add_port(80, "http", "Apache")
        kb.add_vulnerability("Diagnostic Test", "INFO", "System check")
        
        report_path = kb.export_report()
        if os.path.exists(report_path):
            print(f"[✓] KB Report saved successfully at: {report_path}")
        else:
            print(f"[!] KB Report file NOT FOUND at: {report_path}")
            
    except Exception as e:
        print(f"[!] KnowledgeBase Error: {e}")

    # 3. Test HTML Report Generation
    print("\n[*] Testing HTML Report Generator...")
    try:
        reporter = HTMLReportGenerator()
        scan_info = {
            "target": "diag.test.com",
            "model": "diag-model",
            "duration": "0:00:10",
            "iterations": 1,
            "commands_executed": 1,
            "working_dir": kb.save_dir
        }
        kb_data = kb.get_full_data()
        ai_report = {
            "executive_summary": "Diagnostic test run.",
            "risk_rating": "LOW",
            "all_findings": [{"title": "Test Finding", "severity": "INFO"}]
        }
        
        html_path = reporter.generate(ai_report, kb_data, scan_info)
        if os.path.exists(html_path):
            print(f"[✓] HTML Report saved successfully at: {html_path}")
            print(f"[i] File size: {os.path.getsize(html_path)} bytes")
        else:
            print(f"[!] HTML Report file NOT FOUND at: {html_path}")
            
    except Exception as e:
        print(f"[!] HTML Report Error: {e}")

    print("\n=== DIAGNOSIS COMPLETE ===")

if __name__ == "__main__":
    diagnose()
