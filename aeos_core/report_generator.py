"""
AEOS Multi-Format Report & Compliance Generator — God-Mode Visual Suite (v2.5.0)
Produces:
1. Executive GitHub Pull Request Markdown reviews with dynamic shields & compliance badges.
2. Standalone HTML Executive Compliance Certificates (SOC2 / ISO 27001 style).
3. Machine-readable JSON audit payloads.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

LIVE_GATEWAY_URL = "https://depending-effect-voip-model.trycloudflare.com"

class ReportGenerator:
    """
    AEOS Multi-Format Report & Compliance Generator.
    Produces GitHub Markdown PR reviews, JSON payloads, and HTML Executive Compliance Certificates.
    """
    def __init__(self, scan_results: Dict[str, Any], patch_results: Dict[str, Any] = None, license_info: Dict[str, Any] = None):
        self.scan = scan_results
        self.patch = patch_results or {}
        self.license = license_info or {"tier": "COMMUNITY_FREE", "valid": False}
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_pr_markdown(self) -> str:
        """
        Generates GitHub PR review comment body with high-contrast institutional hierarchy.
        """
        summary = self.scan.get("summary", {})
        total = summary.get("total", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        grade = self.scan.get("security_score", "A+" if total == 0 else "B")

        badge_color = "brightgreen" if grade in ["A+", "A"] else ("orange" if grade == "B" else "red")
        badge_status = "PASSED" if total == 0 else f"{total}%20ISSUES"

        md = []
        md.append(f"## 🛡️ AEOS Code Security & Compliance Guard")
        md.append(f"![Security Status](https://img.shields.io/badge/AEOS-{badge_status}-{badge_color}?style=flat-square) ![Grade](https://img.shields.io/badge/Score-{grade}-{badge_color}?style=flat-square)")
        md.append(f"\n**Audit Timestamp:** `{self.timestamp}` | **Scan Target:** `{os.path.basename(self.scan.get('target', 'workspace'))}`\n")

        # Summary Metrics Table
        md.append("| Grade | Critical | High | Medium | Low | Total Findings |")
        md.append("| :---: | :---: | :---: | :---: | :---: | :---: |")
        md.append(f"| **{grade}** | **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** |\n")

        # Detected Secrets
        secrets = self.scan.get("secrets", [])
        if secrets:
            md.append("### 🚨 Leaked Hardcoded Secrets")
            md.append("| Type | File | Line | Masked Value |")
            md.append("| :--- | :--- | :--- | :--- |")
            for s in secrets:
                md.append(f"| `{s['type']}` | `{s['file']}` | L{s['line']} | `{s['masked_value']}` |")
            md.append("")

        # Vulnerable Dependencies
        vulns = self.scan.get("vulnerabilities", [])
        if vulns:
            md.append("### 📦 Vulnerable Package Dependencies")
            md.append("| Package | Installed | Safe Version | CVE | Severity |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for v in vulns:
                md.append(f"| `{v['package']}` | `{v['installed_version']}` | `{v['fixed_version']}` | [{v['cve']}](https://nvd.nist.gov/vuln/detail/{v['cve']}) | **{v['severity']}** |")
            md.append("")

        # Configuration Flaws & Licenses
        configs = self.scan.get("configuration_flaws", [])
        licenses = self.scan.get("license_risks", [])
        if configs or licenses:
            md.append("### ⚙️ Configuration & License Compliance")
            for c in configs:
                md.append(f"- ⚠️ **{c['type']}**: {c['description']} (`{c['file']}`)")
            for l in licenses:
                md.append(f"- ⚖️ **{l['type']}**: {l['description']} (`{l['file']}`)")
            md.append("")

        # Auto-Remediation Summary
        patches_count = self.patch.get("patches_count", 0)
        remaining = self.patch.get("remaining_unpatched", 0)

        if patches_count > 0:
            md.append(f"### ⚡ Automated Remediation Applied")
            md.append(f"AEOS automatically generated and applied **{patches_count} patch(es)** directly to the codebase.")
            diff = self.patch.get("unified_diff", "")
            if diff:
                md.append("<details><summary><b>View Unified Git Diff Patch</b></summary>\n")
                md.append("```diff\n" + diff + "\n```\n</details>\n")

        # Pro Tier Upsell / Entitlement Banner
        portal_url = LIVE_GATEWAY_URL
        try:
            from aeos_gateway.cloud_tunnel import get_current_public_url
            portal_url = get_current_public_url()
        except Exception:
            pass

        if remaining > 0 and self.license.get("tier") != "ENTERPRISE_PRO":
            md.append("> [!TIP]")
            md.append(f"> **AEOS Community Tier Alert**: {patches_count} free automated patch was applied. **{remaining} additional issue(s)** require remediation.")
            md.append(f"> Upgrade to **AEOS Pro** ($49 one-time / repo) for unlimited automated zero-touch patching, verified compliance seals, and continuous CI/CD monitoring.")
            md.append(f"> 👉 **[Activate AEOS Enterprise Pro License]({portal_url}/checkout)**")
        elif self.license.get("tier") == "ENTERPRISE_PRO":
            md.append("> [!NOTE]")
            md.append(f"> 🏆 **AEOS Enterprise Pro Active**: Verified by Cryptographic License Key `{self.license.get('key_masked', 'AEOS-PRO-****')}`. All automated patches applied.")

        md.append("\n---\n*Verified by AEOS Autonomous Software Supply Chain Intelligence • American Swipes Ltd*")
        return "\n".join(md)

    def generate_json_report(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.scan.get("target"),
            "security_score": self.scan.get("security_score", "A"),
            "score_numeric": self.scan.get("score_numeric", 100),
            "summary": self.scan.get("summary", {}),
            "findings": {
                "secrets": self.scan.get("secrets", []),
                "vulnerabilities": self.scan.get("vulnerabilities", []),
                "configuration_flaws": self.scan.get("configuration_flaws", []),
                "license_risks": self.scan.get("license_risks", []),
            },
            "remediation": {
                "patches_count": self.patch.get("patches_count", 0),
                "remaining_unpatched": self.patch.get("remaining_unpatched", 0),
                "is_partial": self.patch.get("is_partial", False)
            },
            "license": self.license
        }

    def generate_html_certificate(self) -> str:
        summary = self.scan.get("summary", {})
        total = summary.get("total", 0)
        grade = self.scan.get("security_score", "A+" if total == 0 else "B")
        status_text = "PASS — COMPLIANT" if total == 0 else "ACTION REQUIRED"
        status_color = "#10b981" if total == 0 else "#f59e0b"

        # Deterministic audit checksum
        audit_hash = hashlib.sha256(f"{self.timestamp}-{total}-{grade}".encode()).hexdigest()[:16].upper()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AEOS Executive Compliance Certificate</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;700;800;900&family=JetBrains+Mono:wght@600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Plus Jakarta Sans', sans-serif; background: #0b0f19; color: #f8fafc; }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    </style>
</head>
<body class="min-h-screen py-12 px-4 flex items-center justify-center">
    <div class="max-w-3xl w-full bg-slate-900 border-2 border-slate-700 rounded-3xl p-8 sm:p-12 shadow-2xl space-y-8">
        <div class="flex justify-between items-start pb-6 border-b border-slate-800">
            <div>
                <div class="inline-flex items-center gap-2 px-3 py-1 bg-sky-500/20 text-sky-300 rounded-full text-xs font-bold font-mono">
                    🛡️ AEOS COMPLIANCE CERTIFICATE
                </div>
                <h1 class="text-3xl font-black text-white mt-2">Executive Security & Compliance Certificate</h1>
                <p class="text-xs text-slate-300 mt-1">Audit Reference ID: <span class="font-mono text-sky-400 font-bold">{audit_hash}</span></p>
            </div>
            <div class="text-right">
                <div class="text-4xl font-black text-sky-400 font-mono">{grade}</div>
                <div class="text-[11px] text-slate-400 uppercase tracking-wider font-bold">Security Grade</div>
            </div>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
            <div class="p-4 bg-slate-950 rounded-2xl border border-slate-800">
                <div class="text-xs uppercase text-slate-400 font-bold">Total Scanned</div>
                <div class="text-2xl font-black text-white mt-1">{total} findings</div>
            </div>
            <div class="p-4 bg-slate-950 rounded-2xl border border-slate-800">
                <div class="text-xs uppercase text-slate-400 font-bold">Critical Flaws</div>
                <div class="text-2xl font-black text-red-400 mt-1">{summary.get('critical', 0)}</div>
            </div>
            <div class="p-4 bg-slate-950 rounded-2xl border border-slate-800">
                <div class="text-xs uppercase text-slate-400 font-bold">Auto-Patched</div>
                <div class="text-2xl font-black text-emerald-400 mt-1">{self.patch.get('patches_count', 0)}</div>
            </div>
            <div class="p-4 bg-slate-950 rounded-2xl border border-slate-800">
                <div class="text-xs uppercase text-slate-400 font-bold">Status</div>
                <div class="text-xs font-black mt-2 font-mono" style="color: {status_color}">{status_text}</div>
            </div>
        </div>

        <div class="p-4 bg-slate-950 rounded-2xl border border-slate-800 text-xs space-y-2 text-slate-300">
            <div class="flex justify-between">
                <span>Verification Authority:</span>
                <strong class="text-white">American Swipes Ltd (UK Reg: 16087804)</strong>
            </div>
            <div class="flex justify-between">
                <span>Audit Standard:</span>
                <span class="text-sky-300 font-mono">Gitleaks v8.18 / NIST NVD CVE / OWASP Top 10</span>
            </div>
            <div class="flex justify-between">
                <span>Timestamp:</span>
                <span class="text-slate-400 font-mono">{self.timestamp}</span>
            </div>
        </div>

        <div class="pt-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-400">
            <div>Verified Ephemeral Execution • Zero Source Code Retention</div>
            <a href="{LIVE_GATEWAY_URL}" target="_blank" class="text-sky-400 hover:text-sky-300 font-bold transition">aeos.americanswipes.com &rarr;</a>
        </div>
    </div>
</body>
</html>"""
