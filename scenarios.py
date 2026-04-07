"""
armorflo/scenarios.py
---------------------
Three realistic vulnerability triage scenarios for ArmorFlo.

Task 1 — easy   : Single CVE (Log4Shell). Classify and close.
Task 2 — medium : Three CVEs, mixed applicability, one fully non-applicable.
Task 3 — hard   : Eight CVEs, diverse assets, many false-positive CVEs to suppress,
                  full remediation plan, escalation, detailed summary required.
"""
from __future__ import annotations
from typing import Any, Dict


SCENARIO_CLASSIFY_SEVERITY: Dict[str, Any] = {
    "task_id":   "task_classify_severity",
    "report_id": "RPT-001",
    "max_steps": 10,

    "reports": [{
        "cve_id": "CVE-2021-44228",
        "title":  "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "description": (
            "A critical RCE vulnerability in Apache Log4j2 versions 2.0-beta9 through 2.14.1. "
            "The JNDI lookup feature allows attackers to execute arbitrary code by sending a "
            "specially crafted log message. Exploitable without authentication over the network. "
            "PoC exploit code is widely available and actively exploited in the wild."
        ),
        "cvss_score": 10.0,
        "cvss_vector": {
            "attack_vector": "NETWORK", "attack_complexity": "LOW",
            "privileges_required": "NONE", "user_interaction": "NONE",
            "scope": "CHANGED",
            "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
        },
        "affected_products": ["Apache Log4j 2.0-beta9 through 2.14.1"],
        "patch_available": True,
        "exploit_public": True,
        "published_date": "2021-12-10",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ],
    }],

    "assets": [
        {
            "asset_id": "AST-001", "name": "api-gateway",
            "product": "Apache Log4j", "version": "2.12.0",
            "environment": "production", "internet_facing": True,
            "business_criticality": "critical",
        },
        {
            "asset_id": "AST-002", "name": "batch-processor",
            "product": "Apache Log4j", "version": "2.10.0",
            "environment": "production", "internet_facing": False,
            "business_criticality": "high",
        },
        {
            "asset_id": "AST-003", "name": "data-warehouse",
            "product": "Apache Log4j", "version": "2.17.1",
            "environment": "production", "internet_facing": False,
            "business_criticality": "high",
        },
    ],

    "_assess_data": {
        "log4j": (
            "api-gateway (AST-001) runs Log4j 2.12.0 — VULNERABLE. "
            "batch-processor (AST-002) runs Log4j 2.10.0 — VULNERABLE. "
            "data-warehouse (AST-003) runs Log4j 2.17.1 — PATCHED, not affected. "
            "Remediation: upgrade to 2.17.1+. Interim: set log4j2.formatMsgNoLookups=true."
        ),
        "cvss": (
            "CVSS v3.1 Base Score: 10.0 CRITICAL. "
            "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H. "
            "Network-exploitable, no auth required, full system compromise possible."
        ),
        "exploit": (
            "Active exploitation confirmed since 2021-12-09. Public PoC on GitHub. "
            "Used in ransomware campaigns and nation-state intrusions. CISA KEV listed."
        ),
        "remediation": (
            "1. Upgrade Log4j to 2.17.1+ on AST-001 and AST-002 immediately. "
            "2. Apply JVM flag -Dlog4j2.formatMsgNoLookups=true as interim mitigation. "
            "3. Block outbound JNDI/LDAP at firewall level. "
            "4. AST-003 is already patched — no action needed."
        ),
        "asset": (
            "AST-001 api-gateway: Log4j 2.12.0, production, internet-facing, critical. "
            "AST-002 batch-processor: Log4j 2.10.0, production, internal, high. "
            "AST-003 data-warehouse: Log4j 2.17.1, production, internal, high — NOT AFFECTED."
        ),
    },

    "_ground_truth": {
        "severity_tier": "CRITICAL",
        "cvss_score": 10.0,
        "applicable_assets":     ["AST-001", "AST-002"],
        "not_applicable_assets": ["AST-003"],
        "required_remediation": [
            {"action": "upgrade log4j", "target_asset_ids": ["AST-001"]},
            {"action": "upgrade log4j", "target_asset_ids": ["AST-002"]},
        ],
        "required_escalation": None,
        "resolution_keywords": [
            "log4j", "2.17.1", "critical", "rce", "upgrade",
            "AST-001", "AST-002", "not affected",
        ],
        "par_steps": 5,
    },
}


SCENARIO_MIXED_APPLICABILITY: Dict[str, Any] = {
    "task_id":   "task_mixed_applicability",
    "report_id": "RPT-002",
    "max_steps": 20,

    "reports": [
        {
            "cve_id": "CVE-2023-44487",
            "title":  "HTTP/2 Rapid Reset Attack (DoS)",
            "description": (
                "A DoS vulnerability in HTTP/2 implementations. Attackers send many HEADERS "
                "frames followed by RST_STREAM to exhaust server resources without maintaining "
                "connections. Affects nginx < 1.25.3 and Apache httpd < 2.4.58."
            ),
            "cvss_score": 7.5,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality": "NONE", "integrity": "NONE", "availability": "HIGH",
            },
            "affected_products": ["nginx < 1.25.3", "Apache httpd < 2.4.58"],
            "patch_available": True,
            "exploit_public": True,
            "published_date": "2023-10-10",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        },
        {
            "cve_id": "CVE-2023-4911",
            "title":  "glibc Looney Tunables — Local Privilege Escalation",
            "description": (
                "A buffer overflow in glibc's dynamic loader via GLIBC_TUNABLES env var. "
                "Allows local users to escalate to root. Affects glibc 2.34 through 2.38."
            ),
            "cvss_score": 7.8,
            "cvss_vector": {
                "attack_vector": "LOCAL", "attack_complexity": "LOW",
                "privileges_required": "LOW", "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["glibc 2.34 through 2.38"],
            "patch_available": True,
            "exploit_public": True,
            "published_date": "2023-10-03",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4911"],
        },
        {
            "cve_id": "CVE-2023-20198",
            "title":  "Cisco IOS XE Web UI Privilege Escalation",
            "description": (
                "Critical auth bypass in Cisco IOS XE Web UI allows unauthenticated remote "
                "attackers to create privilege-level-15 accounts. Only affects IOS XE with "
                "HTTP Server feature enabled."
            ),
            "cvss_score": 10.0,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["Cisco IOS XE with HTTP Server enabled"],
            "patch_available": False,
            "exploit_public": True,
            "published_date": "2023-10-16",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
        },
    ],

    "assets": [
        {
            "asset_id": "AST-010", "name": "web-frontend",
            "product": "nginx", "version": "1.24.0",
            "environment": "production", "internet_facing": True,
            "business_criticality": "critical",
        },
        {
            "asset_id": "AST-011", "name": "app-server-1",
            "product": "Ubuntu Linux", "version": "22.04",
            "environment": "production", "internet_facing": False,
            "business_criticality": "high",
        },
        {
            "asset_id": "AST-012", "name": "app-server-2",
            "product": "Ubuntu Linux", "version": "20.04",
            "environment": "production", "internet_facing": False,
            "business_criticality": "high",
        },
        {
            "asset_id": "AST-013", "name": "core-switch",
            "product": "Cisco IOS", "version": "15.2",
            "environment": "production", "internet_facing": False,
            "business_criticality": "critical",
        },
    ],

    "_assess_data": {
        "nginx": (
            "web-frontend (AST-010) runs nginx 1.24.0 — VULNERABLE to CVE-2023-44487. "
            "Upgrade to nginx 1.25.3+. Interim: limit http2_max_concurrent_streams."
        ),
        "glibc": (
            "app-server-1 (AST-011) runs Ubuntu 22.04 with glibc 2.35 — VULNERABLE to CVE-2023-4911. "
            "app-server-2 (AST-012) runs Ubuntu 20.04 with glibc 2.31 — NOT in affected range (2.34-2.38). "
            "Patch: apt-get upgrade libc6 on AST-011 only."
        ),
        "cisco": (
            "core-switch (AST-013) runs Cisco IOS 15.2, NOT IOS XE. "
            "CVE-2023-20198 only affects IOS XE with HTTP Server enabled. "
            "AST-013 is NOT affected. No IOS XE devices in inventory."
        ),
        "http2": (
            "HTTP/2 Rapid Reset affects AST-010 (nginx 1.24.0). "
            "AST-011 and AST-012 are not running nginx or httpd — not affected."
        ),
        "cvss": (
            "CVE-2023-44487: CVSS 7.5 HIGH. CVE-2023-4911: CVSS 7.8 HIGH. "
            "CVE-2023-20198: CVSS 10.0 CRITICAL (but no IOS XE assets in inventory)."
        ),
        "remediation": (
            "Priority 1: upgrade nginx on AST-010 (internet-facing, critical). "
            "Priority 2: patch glibc on AST-011 (local priv-esc, production). "
            "CVE-2023-20198: no action required — no IOS XE assets."
        ),
        "asset": (
            "AST-010: nginx 1.24.0, production, internet-facing, critical. "
            "AST-011: Ubuntu 22.04 glibc 2.35, production, internal, high. "
            "AST-012: Ubuntu 20.04 glibc 2.31, production, internal, high. "
            "AST-013: Cisco IOS 15.2, production, internal, critical."
        ),
    },

    "_ground_truth": {
        "severity_tiers": {
            "CVE-2023-44487": "HIGH",
            "CVE-2023-4911":  "HIGH",
            "CVE-2023-20198": "CRITICAL",
        },
        "applicable_map": {
            "CVE-2023-44487": {"AST-010": True,  "AST-011": False, "AST-012": False, "AST-013": False},
            "CVE-2023-4911":  {"AST-010": False, "AST-011": True,  "AST-012": False, "AST-013": False},
            "CVE-2023-20198": {"AST-010": False, "AST-011": False, "AST-012": False, "AST-013": False},
        },
        "required_remediation": [
            {"action": "upgrade nginx to 1.25.3+",        "target_asset_ids": ["AST-010"]},
            {"action": "patch glibc on app-server-1",     "target_asset_ids": ["AST-011"]},
        ],
        "required_escalation": "security",
        "resolution_keywords": [
            "nginx", "AST-010", "glibc", "AST-011", "not applicable",
            "CVE-2023-20198", "IOS XE", "upgrade",
        ],
        "par_steps": 10,
    },
}


SCENARIO_FULL_TRIAGE: Dict[str, Any] = {
    "task_id":   "task_full_triage",
    "report_id": "RPT-003",
    "max_steps": 60,

    "reports": [
        {
            "cve_id": "CVE-2024-3094",
            "title":  "XZ Utils Backdoor (Supply Chain Attack)",
            "description": (
                "A malicious backdoor inserted into XZ Utils 5.6.0 and 5.6.1 by a malicious "
                "contributor. Modifies sshd to allow arbitrary command execution as root via SSH "
                "on systemd-based Linux with compromised liblzma linked into sshd."
            ),
            "cvss_score": 10.0,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["XZ Utils 5.6.0", "XZ Utils 5.6.1"],
            "patch_available": True, "exploit_public": False,
            "published_date": "2024-03-29",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
        },
        {
            "cve_id": "CVE-2024-6387",
            "title":  "OpenSSH regreSSHion — Remote Code Execution",
            "description": (
                "Signal handler race condition in OpenSSH sshd allows unauthenticated RCE as root "
                "on glibc-based Linux. Affects OpenSSH 8.5p1 through 9.7p1."
            ),
            "cvss_score": 8.1,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "HIGH",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["OpenSSH 8.5p1 through 9.7p1"],
            "patch_available": True, "exploit_public": True,
            "published_date": "2024-07-01",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        },
        {
            "cve_id": "CVE-2024-21626",
            "title":  "runc Container Escape",
            "description": (
                "File descriptor leak in runc allows container escape giving an attacker "
                "full root access to the host. Affects runc < 1.1.12."
            ),
            "cvss_score": 8.6,
            "cvss_vector": {
                "attack_vector": "LOCAL", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "REQUIRED",
                "scope": "CHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["runc < 1.1.12"],
            "patch_available": True, "exploit_public": True,
            "published_date": "2024-01-31",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21626"],
        },
        {
            "cve_id": "CVE-2023-46805",
            "title":  "Ivanti Connect Secure Authentication Bypass",
            "description": (
                "Auth bypass in Ivanti ICS web component. Allows unauthenticated remote access "
                "to restricted resources. Actively exploited by state-sponsored actors."
            ),
            "cvss_score": 8.2,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality": "HIGH", "integrity": "LOW", "availability": "NONE",
            },
            "affected_products": ["Ivanti Connect Secure < 9.1R14.4"],
            "patch_available": True, "exploit_public": True,
            "published_date": "2024-01-10",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46805"],
        },
        {
            "cve_id": "CVE-2024-1709",
            "title":  "ConnectWise ScreenConnect Authentication Bypass",
            "description": (
                "Critical auth bypass in ConnectWise ScreenConnect allows attackers to create "
                "admin accounts, leading to RCE. Affects ScreenConnect 23.9.7 and earlier."
            ),
            "cvss_score": 10.0,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["ConnectWise ScreenConnect <= 23.9.7"],
            "patch_available": True, "exploit_public": True,
            "published_date": "2024-02-19",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1709"],
        },
        {
            "cve_id": "CVE-2023-36884",
            "title":  "Microsoft Office HTML Remote Code Execution",
            "description": (
                "RCE in Microsoft Office and Windows HTML. Malicious Office documents execute "
                "arbitrary code on open. Delivered via phishing. Actively exploited."
            ),
            "cvss_score": 8.3,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["Microsoft Office 2019", "Microsoft Office LTSC 2021",
                                   "Windows 10", "Windows 11"],
            "patch_available": True, "exploit_public": True,
            "published_date": "2023-07-11",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-36884"],
        },
        {
            "cve_id": "CVE-2024-0204",
            "title":  "Fortra GoAnywhere MFT Authentication Bypass",
            "description": (
                "Auth bypass in Fortra GoAnywhere MFT allows attackers to create admin users "
                "leading to RCE. Affects versions prior to 7.4.1."
            ),
            "cvss_score": 9.8,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "LOW",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH",
            },
            "affected_products": ["Fortra GoAnywhere MFT < 7.4.1"],
            "patch_available": True, "exploit_public": True,
            "published_date": "2024-01-22",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0204"],
        },
        {
            "cve_id": "CVE-2023-48795",
            "title":  "Terrapin SSH Protocol Vulnerability",
            "description": (
                "MITM attack exploiting SSH Binary Packet Protocol weaknesses to downgrade "
                "connection security by removing extension negotiation messages. Affects "
                "OpenSSH when using ChaCha20-Poly1305 or CBC-EtM ciphers."
            ),
            "cvss_score": 5.9,
            "cvss_vector": {
                "attack_vector": "NETWORK", "attack_complexity": "HIGH",
                "privileges_required": "NONE", "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality": "LOW", "integrity": "HIGH", "availability": "NONE",
            },
            "affected_products": ["OpenSSH < 9.6p1"],
            "patch_available": True, "exploit_public": False,
            "published_date": "2023-12-18",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-48795"],
        },
    ],

    "assets": [
        {
            "asset_id": "AST-020", "name": "k8s-node-1",
            "product": "Ubuntu Linux / runc", "version": "runc 1.1.10",
            "environment": "production", "internet_facing": False,
            "business_criticality": "critical",
        },
        {
            "asset_id": "AST-021", "name": "k8s-node-2",
            "product": "Ubuntu Linux / runc", "version": "runc 1.1.12",
            "environment": "production", "internet_facing": False,
            "business_criticality": "critical",
        },
        {
            "asset_id": "AST-022", "name": "bastion-host",
            "product": "OpenSSH", "version": "9.3p1",
            "environment": "production", "internet_facing": True,
            "business_criticality": "critical",
        },
        {
            "asset_id": "AST-023", "name": "internal-ssh-server",
            "product": "OpenSSH", "version": "8.9p1",
            "environment": "production", "internet_facing": False,
            "business_criticality": "high",
        },
        {
            "asset_id": "AST-024", "name": "dev-workstation",
            "product": "Ubuntu Linux", "version": "23.04",
            "environment": "development", "internet_facing": False,
            "business_criticality": "medium",
        },
        {
            "asset_id": "AST-025", "name": "file-transfer-server",
            "product": "Fortra GoAnywhere MFT", "version": "7.3.0",
            "environment": "production", "internet_facing": True,
            "business_criticality": "critical",
        },
        {
            "asset_id": "AST-026", "name": "employee-workstation-fleet",
            "product": "Microsoft Office", "version": "2021",
            "environment": "production", "internet_facing": False,
            "business_criticality": "high",
        },
        {
            "asset_id": "AST-027", "name": "vpn-gateway",
            "product": "Palo Alto GlobalProtect", "version": "6.1.2",
            "environment": "production", "internet_facing": True,
            "business_criticality": "critical",
        },
    ],

    "_assess_data": {
        "xz": (
            "dev-workstation (AST-024) runs Ubuntu 23.04 — had XZ 5.6.0 briefly. Treat as affected. "
            "All other assets run Ubuntu 22.04 LTS with XZ 5.4.x — NOT affected by CVE-2024-3094."
        ),
        "openssh": (
            "bastion-host (AST-022) OpenSSH 9.3p1 — AFFECTED by CVE-2024-6387 and CVE-2023-48795. "
            "internal-ssh-server (AST-023) OpenSSH 8.9p1 — AFFECTED by CVE-2024-6387 and CVE-2023-48795. "
            "Both must be upgraded to OpenSSH 9.8p1+. AST-022 is internet-facing — higher priority."
        ),
        "runc": (
            "k8s-node-1 (AST-020) runc 1.1.10 — VULNERABLE to CVE-2024-21626. "
            "k8s-node-2 (AST-021) runc 1.1.12 — PATCHED, not affected."
        ),
        "ivanti": (
            "vpn-gateway (AST-027) runs Palo Alto GlobalProtect, NOT Ivanti Connect Secure. "
            "CVE-2023-46805 does NOT apply to AST-027. No Ivanti devices in inventory."
        ),
        "goanywhere": (
            "file-transfer-server (AST-025) runs Fortra GoAnywhere MFT 7.3.0 — VULNERABLE to CVE-2024-0204. "
            "Internet-facing critical asset. Patch to 7.4.1+ immediately."
        ),
        "office": (
            "employee-workstation-fleet (AST-026) runs Microsoft Office 2021 — AFFECTED by CVE-2023-36884. "
            "Apply July 2023 Patch Tuesday update or set FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION."
        ),
        "screenconnect": (
            "No ConnectWise ScreenConnect in asset inventory. CVE-2024-1709 does NOT apply."
        ),
        "cvss": (
            "CVE-2024-3094: CRITICAL 10.0. CVE-2024-6387: HIGH 8.1. CVE-2024-21626: HIGH 8.6. "
            "CVE-2023-46805: HIGH 8.2. CVE-2024-1709: CRITICAL 10.0. CVE-2023-36884: HIGH 8.3. "
            "CVE-2024-0204: CRITICAL 9.8. CVE-2023-48795: MEDIUM 5.9."
        ),
        "remediation": (
            "Priority 1: patch GoAnywhere AST-025 (internet-facing CRITICAL RCE). "
            "Priority 2: upgrade OpenSSH on AST-022 (internet-facing RCE). "
            "Priority 3: patch runc on AST-020 (container escape). "
            "Priority 4: upgrade OpenSSH on AST-023. "
            "Priority 5: patch Office fleet AST-026 + audit XZ on AST-024."
        ),
        "asset": (
            "AST-020: runc 1.1.10 k8s. AST-021: runc 1.1.12 k8s (patched). "
            "AST-022: OpenSSH 9.3p1 bastion internet-facing critical. "
            "AST-023: OpenSSH 8.9p1 internal. AST-024: Ubuntu 23.04 dev. "
            "AST-025: GoAnywhere 7.3.0 internet-facing critical. "
            "AST-026: Office 2021 workstations. AST-027: Palo Alto GlobalProtect vpn."
        ),
    },

    "_ground_truth": {
        "severity_tiers": {
            "CVE-2024-3094":  "CRITICAL",
            "CVE-2024-6387":  "HIGH",
            "CVE-2024-21626": "HIGH",
            "CVE-2023-46805": "HIGH",
            "CVE-2024-1709":  "CRITICAL",
            "CVE-2023-36884": "HIGH",
            "CVE-2024-0204":  "CRITICAL",
            "CVE-2023-48795": "MEDIUM",
        },
        "applicable_map": {
            "CVE-2024-3094":  {
                "AST-020": False, "AST-021": False, "AST-022": False, "AST-023": False,
                "AST-024": True,  "AST-025": False, "AST-026": False, "AST-027": False,
            },
            "CVE-2024-6387":  {
                "AST-020": False, "AST-021": False, "AST-022": True,  "AST-023": True,
                "AST-024": False, "AST-025": False, "AST-026": False, "AST-027": False,
            },
            "CVE-2024-21626": {
                "AST-020": True,  "AST-021": False, "AST-022": False, "AST-023": False,
                "AST-024": False, "AST-025": False, "AST-026": False, "AST-027": False,
            },
            "CVE-2023-46805": {
                "AST-020": False, "AST-021": False, "AST-022": False, "AST-023": False,
                "AST-024": False, "AST-025": False, "AST-026": False, "AST-027": False,
            },
            "CVE-2024-1709":  {
                "AST-020": False, "AST-021": False, "AST-022": False, "AST-023": False,
                "AST-024": False, "AST-025": False, "AST-026": False, "AST-027": False,
            },
            "CVE-2023-36884": {
                "AST-020": False, "AST-021": False, "AST-022": False, "AST-023": False,
                "AST-024": False, "AST-025": False, "AST-026": True,  "AST-027": False,
            },
            "CVE-2024-0204":  {
                "AST-020": False, "AST-021": False, "AST-022": False, "AST-023": False,
                "AST-024": False, "AST-025": True,  "AST-026": False, "AST-027": False,
            },
            "CVE-2023-48795": {
                "AST-020": False, "AST-021": False, "AST-022": True,  "AST-023": True,
                "AST-024": False, "AST-025": False, "AST-026": False, "AST-027": False,
            },
        },
        "required_remediation": [
            {"action": "patch GoAnywhere to 7.4.1+",          "target_asset_ids": ["AST-025"]},
            {"action": "upgrade OpenSSH on bastion-host",     "target_asset_ids": ["AST-022"]},
            {"action": "patch runc on k8s-node-1",            "target_asset_ids": ["AST-020"]},
            {"action": "upgrade OpenSSH on internal-ssh-server", "target_asset_ids": ["AST-023"]},
            {"action": "patch Office fleet and audit XZ",     "target_asset_ids": ["AST-026", "AST-024"]},
        ],
        "required_escalation": "management",
        "resolution_keywords": [
            "GoAnywhere", "AST-025", "bastion", "AST-022", "runc", "AST-020",
            "OpenSSH", "CVE-2023-46805", "not applicable", "CVE-2024-1709",
            "patch", "upgrade",
        ],
        "par_steps": 18,
    },
}


ALL_SCENARIOS = {
    "task_classify_severity":   SCENARIO_CLASSIFY_SEVERITY,
    "task_mixed_applicability": SCENARIO_MIXED_APPLICABILITY,
    "task_full_triage":         SCENARIO_FULL_TRIAGE,
}
