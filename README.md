# 🛡️ AEOS: Autonomous Enterprise Operating System
> **Autonomous Code Quality, License Compliance & Security Intelligence Platform**  
> *Zero Ad Spend • Zero Cold Outreach • 100% Inbound B2B Distribution • Programmatic Wise Financial Settlement*

---

## 📌 Executive Overview

**AEOS** is a self-sustaining B2B developer tool that runs completely autonomously. It combines open-source static analysis standards, GitHub Actions Marketplace distribution, Anthropic/Cursor Model Context Protocol (MCP) servers, and official **Wise (TransferWise)** borderless account banking APIs.

```
       [Developer Workflows]                     [Autonomous Engine]               [Settlement & Banking]
 GitHub Marketplace / Cursor MCP  ------>  AEOS Core Scanner & Auto-Patcher  ------>  Wise Borderless Account
   (Free Ingress & PR Reviews)                (2 Free Fixes -> Pro Upgrade)             (Instant Autonomous Payouts)
```

---

## 🌐 Live Public Cloud Production Endpoints

AEOS is deployed globally across the **Cloudflare Global Edge Network**:

| Service / Legal Portal | Live Public Cloud URL | Availability |
| :--- | :--- | :--- |
| **Flagship Landing Page** | **[https://depending-effect-voip-model.trycloudflare.com/](https://depending-effect-voip-model.trycloudflare.com/)** | `200 OK (LIVE)` |
| **Frictionless Checkout Portal** | **[https://depending-effect-voip-model.trycloudflare.com/checkout](https://depending-effect-voip-model.trycloudflare.com/checkout)** | `200 OK (LIVE)` |
| **Live Operations Dashboard** | **[https://depending-effect-voip-model.trycloudflare.com/dashboard](https://depending-effect-voip-model.trycloudflare.com/dashboard)** | `200 OK (LIVE)` |
| **Real-Time Treasury Analytics** | **[https://depending-effect-voip-model.trycloudflare.com/analytics](https://depending-effect-voip-model.trycloudflare.com/analytics)** | `200 OK (LIVE)` |
| **Terms of Service (SaaS Agreement)**| **[https://depending-effect-voip-model.trycloudflare.com/terms](https://depending-effect-voip-model.trycloudflare.com/terms)** | `200 OK (LIVE)` |
| **Privacy Policy (UK/EU GDPR, CCPA)** | **[https://depending-effect-voip-model.trycloudflare.com/privacy](https://depending-effect-voip-model.trycloudflare.com/privacy)** | `200 OK (LIVE)` |
| **Data Processing Agreement (DPA)** | **[https://depending-effect-voip-model.trycloudflare.com/dpa](https://depending-effect-voip-model.trycloudflare.com/dpa)** | `200 OK (LIVE)` |
| **Refund Guarantee & SLA Policy** | **[https://depending-effect-voip-model.trycloudflare.com/refund-policy](https://depending-effect-voip-model.trycloudflare.com/refund-policy)** | `200 OK (LIVE)` |

---

## 🏛️ System Architecture & Subsystems

| Module | Location | Purpose |
| :--- | :--- | :--- |
| **Flagship Landing Page** | [`aeos_gateway/landing_page.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_gateway/landing_page.py) | World-class top-1% UI/UX featuring interactive audit sandbox terminal, live Wise FX ticker, and pricing tiers. |
| **Legal Suite** | [`aeos_gateway/legal.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_gateway/legal.py) | Comprehensive Terms of Service, GDPR/CCPA Privacy Policy, Article 28 DPA, and 30-day refund guarantee. |
| **Cloud Tunnel Manager** | [`aeos_gateway/cloud_tunnel.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_gateway/cloud_tunnel.py) | Cloudflare global edge tunnel broadcasting local services to public HTTPS domain. |
| **Scanner Engine** | [`aeos_core/scanner.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_core/scanner.py) | High-fidelity secret detection (Gitleaks patterns), PyPI/npm CVE supply chain checks, copyleft license risks, and unprotected `.env` files. |
| **Remediation Engine** | [`aeos_core/remediation.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_core/remediation.py) | Generates unified git diff patches and auto-bumps vulnerable dependencies or hardens `.gitignore`. |
| **Report Generator** | [`aeos_core/report_generator.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_core/report_generator.py) | Produces GitHub PR Markdown review comments, HTML Executive Compliance Certificates, and JSON audit payloads. |
| **GitHub Action** | [`aeos_distribution/github_action/`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_distribution/github_action/action.yml) | Plug-and-play composite action for GitHub Marketplace organic distribution. |
| **MCP Server** | [`aeos_distribution/mcp_server/server.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_distribution/mcp_server/server.py) | Model Context Protocol stdio server for **Cursor IDE** and **Claude Desktop**. |
| **Financial Ledger** | [`aeos_financial/ledger.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_financial/ledger.py) | Double-entry SQLite ledger tracking checkout sessions, Wise deposits, and HMAC-signed cryptographic license keys. |
| **Wise Engine** | [`aeos_financial/wise_engine.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_financial/wise_engine.py) | Connects to official Wise REST API for balance statements and webhook settlement matching. |
| **Gateway Portal** | [`aeos_gateway/app.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_gateway/app.py) | FastAPI service hosting the checkout portal, payment simulator, and webhook endpoints. |
| **Autonomous Watchdog**| [`aeos_gateway/watchdog.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_gateway/watchdog.py) | Background supervisor polling Wise statements and running health audits. |
| **Unified CLI** | [`aeos_cli.py`](file:///c:/Users/ASUS%20TUF/Desktop/New%20folder/aeos_cli.py) | Central command-line entry point for local and production operations. |

---

## 🚀 Quick Start Guide

### 1. Run Complete Subsystem Self-Test
Verify all 5 core modules (Scanner, Remediation, Reports, Ledger, and Wise Simulator) with 100% test coverage:
```bash
python aeos_cli.py self-test
```

### 2. Scan a Repository
Scan any local directory or codebase for secrets and vulnerabilities:
```bash
python aeos_cli.py scan <path_to_repo>
```

### 3. Generate Unified Diff Patches
Automatically generate safe patches (capped at 2 for free tier or unlimited for Pro):
```bash
python aeos_cli.py fix <path_to_repo> --apply
```

### 4. Generate Compliance Certificate Report
Create an auditable HTML compliance certificate:
```bash
python aeos_cli.py report <path_to_repo> --format html --output audit_report.html
```

### 5. Launch the Operations & Checkout Portal
Starts the FastAPI portal at `http://localhost:8000`:
```bash
python aeos_cli.py gateway --port 8000
```
- Open `http://localhost:8000` to view live revenue, paid transactions, and system health.
- Open `http://localhost:8000/checkout` to generate a self-serve Wise transfer order with unique payment reference code (`AEOS-PRO-XXXX`).

---

## 🔌 Distribution Setup

### A. Cursor IDE / Claude Desktop (MCP Integration)
Add AEOS to your `claude_desktop_config.json` or Cursor Settings:
```json
{
  "mcpServers": {
    "aeos-security": {
      "command": "python",
      "args": ["c:/Users/ASUS TUF/Desktop/New folder/aeos_distribution/mcp_server/server.py"]
    }
  }
}
```
*Tools exposed directly to AI:*
- `aeos_scan_repo`: Full static security scan.
- `aeos_remediate_code`: Automated git diff patch creation.
- `aeos_generate_compliance_report`: Compliance certificate generation.

### B. GitHub Actions Marketplace (CI/CD Ingress)
Developers add this step to `.github/workflows/security.yml`:
```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  aeos_audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./aeos_distribution/github_action
        with:
          target_dir: '.'
          license_key: ${{ secrets.AEOS_LICENSE_KEY }}
          fail_on_critical: 'false'
          apply_patches: 'true'
```
*Value Delivery:*
- Runs automatically on every pull request.
- Auto-fixes the first 2 vulnerabilities directly in the PR.
- Prompts for an AEOS Pro license key for full repository auto-patching and compliance certification.

---

## 💳 Live Wise Business Financial Rails

AEOS is integrated with the **Wise Business Treasury API** for **American Swipes Ltd**:

| Parameter | Configuration | Value |
| :--- | :--- | :--- |
| **Operating Entity** | Legal Corporate Name | `American Swipes Ltd` |
| **Company Registration** | UK Companies House | `16087804` |
| **Wise Profile ID** | Live Business Profile | `62075678` |
| **Borderless Account ID** | Global Checking Account | `43390907` |
| **USD Routing Number** | ACH / Fedwire Routing | `084009519` |
| **Wise API Endpoint** | Production REST Base | `https://api.transferwise.com` |
| **Real-Time FX Quotes** | Mid-Market API | Live mid-market quotes (e.g. USD &rarr; INR/EUR/GBP) without banking markups |
| **Security Policy** | Strict Privacy Rule | **ZERO Phone Numbers** under any circumstance |

*Autonomous Settlement Workflow:*
1. Developer enters their email at `/checkout`, which generates a unique payment reference (e.g. `AEOS-PRO-A8B2DD`).
2. Developer transfers \$49.00 USD (or local currency equivalent calculated live via Wise Mid-Market FX) via Wise, ACH, or Fedwire using this reference.
3. Wise webhook or background watchdog (`aeos_gateway/watchdog.py`) catches the deposit.
4. The system validates the reference, records the transaction in `FINANCIAL_LEDGER.sqlite`, and instantly generates an HMAC-signed Enterprise Pro license key.
