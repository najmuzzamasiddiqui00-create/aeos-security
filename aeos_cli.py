import argparse
import sys
import os
import json
import uvicorn

from aeos_core.scanner import SecurityScanner
from aeos_core.remediation import RemediationEngine
from aeos_core.report_generator import ReportGenerator
try:
    from aeos_financial.ledger import FinancialLedger
    from aeos_financial.wise_engine import WiseEngine
    HAS_ENTERPRISE_INTERNAL = True
except ImportError:
    HAS_ENTERPRISE_INTERNAL = False

def print_banner():
    banner = r"""
========================================================================
   ___    ______ ____   _____   Autonomous Enterprise Operating System
  / _ |  / __// __ \ / ___/   Security Intelligence, Supply Chain Audit
 / __ | / _/ / /_/ /_\_ \    & Autonomous Financial Settlement Platform
/_/ |_|/___/ \____//____/    v2.4.0 (Enterprise Production Build)
========================================================================
    """
    print(banner)

def cmd_scan(args):
    target = os.path.abspath(args.path)
    print(f"[*] Scanning repository target: {target}")
    scanner = SecurityScanner(target)
    results = scanner.scan()

    summary = results["summary"]
    print(f"\n[+] Scan Complete:")
    print(f"    - Total Findings: {summary['total']}")
    print(f"    - Critical:       {summary['critical']}")
    print(f"    - High:           {summary['high']}")
    print(f"    - Medium:         {summary['medium']}")
    print(f"    - Low:            {summary['low']}")

    if results["secrets"]:
        print("\n[!] Exposed Secrets Detected:")
        for s in results["secrets"]:
            print(f"    - [{s['severity']}] {s['type']} in {s['file']}:{s['line']} (Sample: {s['masked_value']})")

    if results["vulnerabilities"]:
        print("\n[!] Vulnerable Package Dependencies:")
        for v in results["vulnerabilities"]:
            print(f"    - [{v['severity']}] {v['package']} {v['installed_version']} -> Fix: {v['fixed_version']} ({v['cve']})")

    if results["configuration_flaws"]:
        print("\n[!] Configuration & Supply-Chain Flaws:")
        for c in results["configuration_flaws"]:
            print(f"    - [{c['severity']}] {c['type']} in {c['file']}")

    if results["license_risks"]:
        print("\n[!] License Compliance Risks:")
        for l in results["license_risks"]:
            print(f"    - [{l['severity']}] {l['type']} in {l['file']}")

def cmd_fix(args):
    target = os.path.abspath(args.path)
    print(f"[*] Scanning & auto-remediating: {target}")
    scanner = SecurityScanner(target)
    scan_results = scanner.scan()

    engine = RemediationEngine(target)
    max_fixes = args.max_fixes if args.max_fixes > 0 else None
    patch_data = engine.generate_patches(scan_results, max_fixes=max_fixes)

    print(f"[+] Patches Generated: {patch_data['patches_count']}")
    print(f"[+] Remaining Unpatched Issues: {patch_data['remaining_unpatched']}")

    if patch_data["unified_diff"]:
        print("\n--- UNIFIED DIFF ---")
        print(patch_data["unified_diff"])
        print("--------------------")

    if args.apply and patch_data["patches_count"] > 0:
        engine.apply_patches(patch_data)
        print("[+] Applied patches successfully to workspace.")

def cmd_report(args):
    target = os.path.abspath(args.path)
    scanner = SecurityScanner(target)
    scan_results = scanner.scan()

    engine = RemediationEngine(target)
    patch_data = engine.generate_patches(scan_results, max_fixes=2)

    reporter = ReportGenerator(scan_results, patch_data)

    if args.format == "html":
        content = reporter.generate_html_certificate()
    elif args.format == "json":
        content = json.dumps(reporter.generate_json_report(), indent=2)
    else:
        content = reporter.generate_pr_markdown()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Report written to {os.path.abspath(args.output)}")
    else:
        print(content)

def cmd_checkout(args):
    if HAS_ENTERPRISE_INTERNAL:
        ledger = FinancialLedger()
        session = ledger.create_checkout_session(customer_email=args.email, amount=args.amount)
    else:
        import requests
        resp = requests.post("https://depending-effect-voip-model.trycloudflare.com/api/v1/checkout", json={"customer_email": args.email, "amount": args.amount})
        session = resp.json()
    print("\n[+] Created AEOS Pro Checkout Session:")
    print(f"    - Session ID:       {session.get('session_id')}")
    print(f"    - Payment Ref:      {session.get('reference_code')} (Provide this in your Wise transfer)")
    print(f"    - Amount Due:       ${session.get('amount', 49.0):.2f} {session.get('currency', 'USD')}")
    print(f"    - Customer:         {session.get('customer_email')}")
    print(f"\n[i] Direct checkout URL: https://depending-effect-voip-model.trycloudflare.com/checkout?reference={session.get('reference_code')}")

def cmd_verify_license(args):
    if HAS_ENTERPRISE_INTERNAL:
        ledger = FinancialLedger()
        result = ledger.verify_license(args.key)
    else:
        import requests
        resp = requests.post("https://depending-effect-voip-model.trycloudflare.com/api/v1/verify-license", json={"license_key": args.key})
        result = resp.json()
    print("\n[+] License Verification Result:")
    print(json.dumps(result, indent=2))

def cmd_gateway(args):
    if not HAS_ENTERPRISE_INTERNAL:
        print("[-] Error: Gateway server is restricted to authorized enterprise internal hosts.")
        sys.exit(1)
    print(f"[*] Starting AEOS Gateway portal at http://{args.host}:{args.port}")
    uvicorn.run("aeos_gateway.app:app", host=args.host, port=args.port, reload=False)

def cmd_mcp(args):
    from aeos_distribution.mcp_server.server import main as mcp_main
    mcp_main()

def cmd_self_test(args):
    print("[*] Running Autonomous End-to-End System Verification...")

    # 1. Test target directory scan
    test_dir = os.path.abspath("test_repo")
    os.makedirs(test_dir, exist_ok=True)
    try:
        # Create test mock files
        req_file = os.path.join(test_dir, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("requests==2.28.0\nflask==2.1.0\n")

        env_file = os.path.join(test_dir, ".env")
        with open(env_file, "w") as f:
            dummy_key = "sk_" + "live_123456789012345678901234"
            f.write(f"SECRET_KEY={dummy_key}\n")

        print("[1/5] Testing SecurityScanner...")
        scanner = SecurityScanner(test_dir)
        scan_res = scanner.scan()
        assert scan_res["summary"]["total"] >= 3, "Scanner did not detect expected vulnerabilities"
        print(f"      PASS: Detected {scan_res['summary']['total']} vulnerabilities and secrets.")

        print("[2/5] Testing RemediationEngine...")
        engine = RemediationEngine(test_dir)
        patch_res = engine.generate_patches(scan_res, max_fixes=2)
        assert patch_res["patches_count"] == 2, "Remediation failed to cap at max_fixes=2"
        print(f"      PASS: Generated {patch_res['patches_count']} diff patches (capped at free tier limit).")

        print("[3/5] Testing ReportGenerator...")
        reporter = ReportGenerator(scan_res, patch_res)
        md = reporter.generate_pr_markdown()
        html = reporter.generate_html_certificate()
        assert "AEOS Code Security" in md and "AEOS COMPLIANCE CERTIFICATE" in html
        print("      PASS: Successfully rendered GitHub PR Markdown and HTML Executive Certificate.")

        print("[4/5] Testing Financial Ledger & Wise Simulation...")
        test_db = os.path.join(test_dir, "test_ledger.sqlite")
        ledger = FinancialLedger(db_path=test_db)
        session = ledger.create_checkout_session("test_dev@enterprise.internal", amount=49.0)
        ref = session["reference_code"]

        wise = WiseEngine()
        wise.ledger = ledger
        settlement = wise.simulate_transfer(reference_code=ref, amount=49.0)
        assert settlement["status"] == "SETTLED"
        license_key = settlement["license_key"]
        print(f"      PASS: Settled payment ref {ref} and issued license: {license_key}")

        print("[5/5] Testing License Cryptographic Verification...")
        ver = ledger.verify_license(license_key)
        assert ver["valid"] is True and ver["tier"] == "ENTERPRISE_PRO"
        print("      PASS: Cryptographic license verification confirmed valid Pro tier.")

        print("\n=======================================================")
        print(" [ALL 5/5 SUBSYSTEM VERIFICATION TESTS PASSED 100%] ")
        print("=======================================================\n")
    finally:
        # Cleanup test files
        import shutil
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir, ignore_errors=True)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="AEOS Autonomous Enterprise Operating System CLI")
    subparsers = parser.add_subparsers(dest="command")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan repository for secrets and vulnerabilities")
    p_scan.add_argument("path", nargs="?", default=".", help="Directory to scan")

    # fix
    p_fix = subparsers.add_parser("fix", help="Generate code patches for detected security issues")
    p_fix.add_argument("path", nargs="?", default=".", help="Directory to scan & fix")
    p_fix.add_argument("--max-fixes", type=int, default=2, help="Max patches to produce (default: 2)")
    p_fix.add_argument("--apply", action="store_true", help="Apply patches directly to disk")

    # report
    p_report = subparsers.add_parser("report", help="Generate compliance certificates and PR reviews")
    p_report.add_argument("path", nargs="?", default=".", help="Directory to scan")
    p_report.add_argument("--format", choices=["markdown", "html", "json"], default="markdown")
    p_report.add_argument("--output", "-o", help="Output file path")

    # checkout
    p_checkout = subparsers.add_parser("checkout", help="Create an AEOS Pro checkout session")
    p_checkout.add_argument("email", help="Customer email address")
    p_checkout.add_argument("--amount", type=float, default=49.0, help="Amount in USD (default: $49.00)")

    # verify-license
    p_verify = subparsers.add_parser("verify-license", help="Verify cryptographic license key")
    p_verify.add_argument("key", help="License key to verify")

    # gateway
    p_gw = subparsers.add_parser("gateway", help="Run the FastAPI operations portal and checkout gateway")
    p_gw.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    p_gw.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")

    # mcp
    subparsers.add_parser("mcp", help="Start the Model Context Protocol (MCP) server for Cursor / Claude")

    # self-test
    subparsers.add_parser("self-test", help="Run automated end-to-end self-test of all subsystems")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "scan": cmd_scan,
        "fix": cmd_fix,
        "report": cmd_report,
        "checkout": cmd_checkout,
        "verify-license": cmd_verify_license,
        "gateway": cmd_gateway,
        "mcp": cmd_mcp,
        "self-test": cmd_self_test
    }

    if args.command in dispatch:
        dispatch[args.command](args)

if __name__ == "__main__":
    main()
