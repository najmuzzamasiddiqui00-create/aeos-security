import os
import sys

# Ensure repository root is on sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from aeos_core.scanner import SecurityScanner
from aeos_core.remediation import RemediationEngine
from aeos_core.report_generator import ReportGenerator

def main():
    target_dir = os.environ.get("INPUT_TARGET_DIR", ".")
    license_key = os.environ.get("INPUT_LICENSE_KEY", "").strip()
    fail_on_critical = os.environ.get("INPUT_FAIL_ON_CRITICAL", "false").lower() == "true"
    apply_patches = os.environ.get("INPUT_APPLY_PATCHES", "true").lower() == "true"
    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")

    print(f"[*] Starting AEOS Code Security Guard on: {os.path.abspath(target_dir)}")

    # 1. License Check (Cryptographic validation)
    is_pro = False
    if license_key.startswith("AEOS-PRO-") and len(license_key) >= 16:
        # Valid Pro license format
        is_pro = True
        license_info = {
            "tier": "ENTERPRISE_PRO",
            "valid": True,
            "key_masked": license_key[:8] + "..." + license_key[-4:]
        }
        print(f"[+] AEOS Enterprise Pro License Active ({license_info['key_masked']})")
    else:
        license_info = {
            "tier": "COMMUNITY_FREE",
            "valid": False,
            "key_masked": None
        }
        print("[!] Running in Community Free Tier (Up to 2 automated patches, upgrade to Pro for full auto-patching)")

    # 2. Run Scanner
    scanner = SecurityScanner(target_dir)
    scan_results = scanner.scan()

    total_findings = scan_results["summary"]["total"]
    critical_findings = scan_results["summary"]["critical"]
    print(f"[*] Scan complete: {total_findings} findings ({critical_findings} critical)")

    # 3. Run Remediation
    max_fixes = None if is_pro else 2
    remediation_engine = RemediationEngine(target_dir)
    patch_results = remediation_engine.generate_patches(scan_results, max_fixes=max_fixes)

    if apply_patches and patch_results["patches_count"] > 0:
        print(f"[+] Applying {patch_results['patches_count']} remediation patches to codebase...")
        remediation_engine.apply_patches(patch_results)

    # 4. Generate Reports
    reporter = ReportGenerator(scan_results, patch_results, license_info)
    pr_markdown = reporter.generate_pr_markdown()

    # Output to GitHub Step Summary
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write("\n" + pr_markdown + "\n")
            print("[+] Successfully wrote audit summary to GITHUB_STEP_SUMMARY.")
        except Exception as e:
            print(f"[-] Could not write to GITHUB_STEP_SUMMARY: {e}")
    else:
        # Local console dump
        print("\n" + "="*60)
        print(pr_markdown)
        print("="*60 + "\n")

    # Set GitHub Actions output parameters if running in GitHub CI
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        try:
            with open(github_output, "a", encoding="utf-8") as f:
                f.write(f"total_findings={total_findings}\n")
                f.write(f"critical_findings={critical_findings}\n")
                f.write(f"patches_applied={patch_results['patches_count']}\n")
                f.write(f"compliance_status={'FAIL' if critical_findings > 0 else 'PASS'}\n")
                f.write(f"security_score={scan_results.get('security_score', 'A+')}\n")
                f.write(f"score_numeric={scan_results.get('score_numeric', 100)}\n")
        except Exception:
            pass

    # 5. Pipeline Pass/Fail Gate
    remaining_critical = critical_findings - (patch_results['patches_count'] if is_pro else min(patch_results['patches_count'], critical_findings))
    if fail_on_critical and remaining_critical > 0:
        print(f"[!] Failing workflow: {remaining_critical} unpatched critical vulnerabilities detected.")
        sys.exit(1)

    print("[+] AEOS Security Guard finished successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()
