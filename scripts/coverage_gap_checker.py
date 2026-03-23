#!/usr/bin/env python3
"""
coverage_gap_checker.py — Map detection files to MITRE ATT&CK and surface gaps.

Reads the detection rules in this portfolio, extracts ATT&CK technique tags,
and produces a gap report showing which techniques have coverage and which don't.
Useful for maintaining detection coverage as the threat landscape evolves.

Usage:
    python coverage_gap_checker.py
    python coverage_gap_checker.py --detections-dir detections/
    python coverage_gap_checker.py --format markdown
    python coverage_gap_checker.py --format json

Requirements:
    pip install pyyaml

Optional (for ATT&CK technique name lookup):
    pip install requests
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)

# ATT&CK technique names for display (subset relevant to this portfolio)
# In production, fetch from https://attack.mitre.org/api/v1/ or use mitreattack-python
TECHNIQUE_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1005": "Data from Local System",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1036.005": "Match Legitimate Name or Location",
    "T1046": "Network Service Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1055.001": "DLL Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta",
    "T1219": "Remote Access Software",
    "T1486": "Data Encrypted for Impact",
    "T1528": "Steal Application Access Token",
    "T1546": "Event Triggered Execution",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.009": "Shortcut Modification",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1555": "Credentials from Password Stores",
    "T1556": "Modify Authentication Process",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1564": "Hide Artifacts",
    "T1564.003": "Hidden Window",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1567": "Exfiltration Over Web Service",
    "T1572": "Protocol Tunneling",
    "T1574": "Hijack Execution Flow",
    "T1574.001": "DLL Search Order Hijacking",
    "T1621": "Multi-Factor Authentication Request Generation",
}

# Expected coverage from the portfolio (techniques that SHOULD be covered)
# Update this list as the portfolio evolves
PORTFOLIO_TECHNIQUES = set(TECHNIQUE_NAMES.keys())


def extract_techniques_from_sigma(rule_path: Path) -> list[str]:
    """Extract ATT&CK technique IDs from a Sigma rule's tags."""
    techniques = []
    try:
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
        tags = rule.get("tags", [])
        for tag in tags:
            # Sigma tags format: "attack.t1078" or "attack.t1547.009"
            if tag.startswith("attack.t") and tag != "attack.":
                tech_id = tag.replace("attack.", "").upper().replace(".", ".")
                # Normalize: "T1547.009" format
                if "." in tech_id:
                    parts = tech_id.split(".")
                    tech_id = f"{parts[0]}.{parts[1].zfill(3)}"
                techniques.append(tech_id)
    except Exception:
        pass
    return techniques


def extract_techniques_from_comments(rule_path: Path) -> list[str]:
    """Extract ATT&CK technique IDs from comment-based rules (Next-Gen SIEM, Pseudo)."""
    techniques = []
    try:
        content = rule_path.read_text()
        import re
        # Match T1234 or T1234.567 patterns in text
        matches = re.findall(r"T\d{4}(?:\.\d{3})?", content)
        techniques = list(set(matches))
    except Exception:
        pass
    return techniques


def scan_detections(detections_dir: Path) -> list[dict]:
    """Scan all detection files and extract their metadata."""
    results = []

    for rule_path in sorted(detections_dir.rglob("*.yml")):
        # Skip non-detection files
        if rule_path.name.startswith("HUNT-"):
            continue

        rule_name = rule_path.stem
        rel_path = rule_path.relative_to(detections_dir.parent)
        format_type = rule_path.parent.name  # taegis, sigma, or pseudo

        # Extract techniques based on format
        if format_type == "sigma":
            techniques = extract_techniques_from_sigma(rule_path)
            if not techniques:
                techniques = extract_techniques_from_comments(rule_path)
        else:
            techniques = extract_techniques_from_comments(rule_path)

        # Get rule severity from content
        content = rule_path.read_text()
        severity = "UNKNOWN"
        for line in content.splitlines():
            if "severity" in line.lower() and ":" in line:
                severity = line.split(":", 1)[1].strip().upper().strip("#")
                if severity:
                    break

        results.append({
            "name": rule_name,
            "path": str(rel_path),
            "format": format_type,
            "techniques": sorted(set(techniques)),
            "severity": severity,
        })

    return results


def build_coverage_map(detections: list[dict]) -> dict[str, list[str]]:
    """Build a map of technique_id → [rule_names]."""
    coverage = {}
    for det in detections:
        for tech in det["techniques"]:
            if tech not in coverage:
                coverage[tech] = []
            coverage[tech].append(det["name"])
    return coverage


def generate_report(
    detections: list[dict],
    coverage_map: dict[str, list[str]],
    output_format: str = "text"
) -> str:
    """Generate coverage gap report."""

    covered = {t: rules for t, rules in coverage_map.items() if rules}
    gaps = PORTFOLIO_TECHNIQUES - set(covered.keys())

    if output_format == "json":
        report_data = {
            "summary": {
                "total_detections": len(detections),
                "techniques_covered": len(covered),
                "techniques_in_portfolio_scope": len(PORTFOLIO_TECHNIQUES),
                "gaps": len(gaps),
            },
            "detections": detections,
            "coverage": {t: rules for t, rules in sorted(covered.items())},
            "gaps": sorted([
                {"id": t, "name": TECHNIQUE_NAMES.get(t, "Unknown")}
                for t in gaps
            ], key=lambda x: x["id"]),
        }
        return json.dumps(report_data, indent=2)

    # Text / Markdown format
    lines = []

    if output_format == "markdown":
        lines.extend([
            "# Detection Coverage Gap Report",
            "",
            f"**Detections scanned:** {len(detections)}  ",
            f"**Techniques covered:** {len(covered)}  ",
            f"**Portfolio scope:** {len(PORTFOLIO_TECHNIQUES)} techniques  ",
            f"**Gaps identified:** {len(gaps)}  ",
            "",
            "---",
            "",
            "## Detection Inventory",
            "",
            "| Rule | Format | Techniques | Severity |",
            "|------|--------|-----------|----------|",
        ])
        for det in detections:
            techs = ", ".join(det["techniques"]) or "—"
            lines.append(
                f"| {det['name']} | {det['format']} | {techs} | {det['severity']} |"
            )
        lines.extend([
            "",
            "---",
            "",
            "## Coverage Map (Technique → Rules)",
            "",
        ])
        for tech_id, rules in sorted(covered.items()):
            tech_name = TECHNIQUE_NAMES.get(tech_id, "Unknown")
            lines.append(f"- **{tech_id}** {tech_name}: {', '.join(rules)}")

        lines.extend([
            "",
            "---",
            "",
            "## Coverage Gaps",
            "",
            "Techniques in portfolio scope with no detection rule:",
            "",
        ])
        for tech_id in sorted(gaps):
            tech_name = TECHNIQUE_NAMES.get(tech_id, "Unknown")
            lines.append(f"- ❌ **{tech_id}** — {tech_name}")

    else:
        # Plain text
        lines.extend([
            "=" * 60,
            "DETECTION COVERAGE GAP REPORT",
            "=" * 60,
            f"Detections scanned:    {len(detections)}",
            f"Techniques covered:    {len(covered)}",
            f"Portfolio scope:       {len(PORTFOLIO_TECHNIQUES)} techniques",
            f"Gaps identified:       {len(gaps)}",
            "",
            "-" * 60,
            "DETECTION INVENTORY",
            "-" * 60,
        ])
        for det in detections:
            techs = ", ".join(det["techniques"]) or "none tagged"
            lines.append(f"  {det['name']:<45} [{det['format']}]")
            lines.append(f"    Techniques: {techs}")
            lines.append(f"    Severity:   {det['severity']}")
            lines.append("")

        lines.extend([
            "-" * 60,
            "COVERAGE GAPS",
            "-" * 60,
        ])
        for tech_id in sorted(gaps):
            tech_name = TECHNIQUE_NAMES.get(tech_id, "Unknown")
            lines.append(f"  [GAP] {tech_id:<15} {tech_name}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Map detections to MITRE ATT&CK and surface coverage gaps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--detections-dir",
        type=Path,
        default=Path(__file__).parent.parent / "detections",
        help="Path to detections directory (default: ../detections)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args()

    if not args.detections_dir.exists():
        print(f"Error: Detections directory not found: {args.detections_dir}", file=sys.stderr)
        sys.exit(1)

    detections = scan_detections(args.detections_dir)
    coverage_map = build_coverage_map(detections)
    report = generate_report(detections, coverage_map, args.format)

    if args.output:
        args.output.write_text(report)
        print(f"Report written to {args.output}")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
