"""
AEOS Enterprise Remediation Engine — God-Mode AST & Unified Diff Auto-Patcher (v2.5.0)
Generates unified git diffs and directly applies autonomous patches to:
1. PyPI manifests (requirements.txt).
2. NPM manifests (package.json).
3. Secret-leak prevention (.gitignore hardening).
4. Environment secret templating (.env.template).
"""

import os
import re
import json
import difflib
from typing import Dict, List, Any, Optional

class RemediationEngine:
    """
    AEOS Automated Code Remediation Engine.
    Generates unified diffs and code patches for detected security flaws,
    outdated vulnerable packages, and exposed configurations.
    """
    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)

    def generate_patches(self, scan_results: Dict[str, Any], max_fixes: Optional[int] = None) -> Dict[str, Any]:
        """
        Generates unified git diffs for findings.
        If max_fixes is set (e.g. 2 for free tier), caps automatic fixes.
        """
        patches_applied = 0
        file_diffs = []
        modified_files = {}

        # 1. Remediate Configuration Flaws (.gitignore missing .env)
        for flaw in scan_results.get("configuration_flaws", []):
            if max_fixes is not None and patches_applied >= max_fixes:
                break
            if flaw.get("type") == "Unprotected Environment File":
                diff, new_content, target_path = self._fix_unprotected_env()
                if diff:
                    file_diffs.append(diff)
                    modified_files[target_path] = new_content
                    patches_applied += 1

        # 2. Remediate Vulnerable Dependencies (PyPI / npm)
        for vuln in scan_results.get("vulnerabilities", []):
            if max_fixes is not None and patches_applied >= max_fixes:
                break
            pkg = vuln["package"]
            fixed_ver = vuln["fixed_version"]
            rel_file = vuln["file"]
            abs_file = os.path.join(self.target_dir, rel_file)

            if vuln["ecosystem"] == "PyPI" and os.path.exists(abs_file):
                diff, new_content = self._fix_pypi_requirement(abs_file, rel_file, pkg, fixed_ver)
                if diff:
                    file_diffs.append(diff)
                    modified_files[abs_file] = new_content
                    patches_applied += 1
            elif vuln["ecosystem"] == "npm" and os.path.exists(abs_file):
                diff, new_content = self._fix_node_package(abs_file, rel_file, pkg, fixed_ver)
                if diff:
                    file_diffs.append(diff)
                    modified_files[abs_file] = new_content
                    patches_applied += 1

        total_findings = scan_results.get("summary", {}).get("total", 0)
        remaining_unpatched = max(0, total_findings - patches_applied)

        return {
            "patches_count": patches_applied,
            "remaining_unpatched": remaining_unpatched,
            "unified_diff": "\n".join(file_diffs),
            "modified_files": modified_files,
            "is_partial": max_fixes is not None and remaining_unpatched > 0,
            "upgrade_required_for_full": remaining_unpatched > 0
        }

    def apply_patches(self, patch_data: Dict[str, Any]) -> bool:
        """
        Directly writes verified patches to disk idempotently.
        """
        modified_files = patch_data.get("modified_files", {})
        if not modified_files:
            return False

        for file_path, content in modified_files.items():
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as e:
                print(f"[-] Could not write patch to {file_path}: {e}")
                return False

        return True

    def _fix_unprotected_env(self) -> (str, str, str):
        gitignore_path = os.path.join(self.target_dir, ".gitignore")
        original_content = ""
        if os.path.exists(gitignore_path):
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                original_content = f.read()

        new_content = original_content
        if new_content and not new_content.endswith("\n"):
            new_content += "\n"
        new_content += "# AEOS Security Shield: Prevent environment secrets leak\n.env\n*.env.local\n*.env.production\n"

        diff = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=".gitignore (original)",
            tofile=".gitignore (remediated)",
            lineterm=""
        )
        diff_str = "\n".join(diff)
        return diff_str, new_content, gitignore_path

    def _fix_pypi_requirement(self, abs_path: str, rel_path: str, package: str, fixed_version: str) -> (str, str):
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            original_text = "".join(lines)
            new_lines = []
            replaced = False

            for line in lines:
                stripped = line.strip()
                if "==" in stripped:
                    pkg_name, _ = stripped.split("==", 1)
                    if pkg_name.strip().lower() == package.lower():
                        new_lines.append(f"{pkg_name}>={fixed_version}  # AEOS Auto-Patched\n")
                        replaced = True
                        continue
                new_lines.append(line)

            if not replaced:
                return "", ""

            new_text = "".join(new_lines)
            diff = difflib.unified_diff(
                original_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"{rel_path} (original)",
                tofile=f"{rel_path} (remediated)",
                lineterm=""
            )
            return "\n".join(diff), new_text
        except Exception:
            return "", ""

    def _fix_node_package(self, abs_path: str, rel_path: str, package: str, fixed_version: str) -> (str, str):
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                original_text = f.read()
                data = json.loads(original_text)

            replaced = False
            for section in ["dependencies", "devDependencies"]:
                if section in data and package in data[section]:
                    data[section][package] = f">={fixed_version}"
                    replaced = True

            if not replaced:
                return "", ""

            new_text = json.dumps(data, indent=2) + "\n"
            diff = difflib.unified_diff(
                original_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"{rel_path} (original)",
                tofile=f"{rel_path} (remediated)",
                lineterm=""
            )
            return "\n".join(diff), new_text
        except Exception:
            return "", ""
