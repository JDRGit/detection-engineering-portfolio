#!/usr/bin/env python3
"""
sigma_to_splunk.py — Convert Sigma detection rules to Splunk SPL queries.

Demonstrates detection engineering automation: portable Sigma rules shouldn't
require manual rewriting for each SIEM. This script handles the translation
for the Sigma rules in this portfolio (DET-002, DET-004, DET-007, DET-010).

Usage:
    python sigma_to_splunk.py --rule detections/sigma/DET-002_impossible_travel.yml
    python sigma_to_splunk.py --dir detections/sigma/
    python sigma_to_splunk.py --dir detections/sigma/ --output spl_queries/

Note: For production use, consider sigma-cli (https://github.com/SigmaHQ/sigma)
which supports full Sigma specification. This script covers common patterns
for educational/portfolio demonstration purposes.
"""

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)


# Field name mappings: Sigma canonical → Splunk field names
# Adjust these to match your Splunk environment's field naming
FIELD_MAPPING = {
    # Process fields
    "Image": "process_path",
    "CommandLine": "process_cmd",
    "ParentImage": "parent_process_path",
    "ParentCommandLine": "parent_cmd",
    "User": "user",
    "IntegrityLevel": "integrity_level",
    # File fields
    "TargetFilename": "file_path",
    "Contents": "file_contents",
    # Network / Azure
    "SourceAddress": "src_ip",
    "UserPrincipalName": "user_principal_name",
    "ResultType": "result_type",
    "MFAUsed": "mfa_used",
    "AppDisplayName": "app_name",
    "DeviceDetail": "device_detail",
    "ConditionalAccessStatus": "ca_status",
    # Registry
    "TargetObject": "registry_path",
    "Details": "registry_value",
}

# Logsource → Splunk index/sourcetype mapping
LOGSOURCE_MAPPING = {
    ("azure", "signinlogs"): 'index=azure sourcetype="azure:aad:signin"',
    ("windows", "process_creation"): 'index=wineventlog EventCode=4688',
    ("windows", "file_event"): 'index=wineventlog EventCode=4663',
    ("windows", "registry_event"): 'index=wineventlog EventCode=4657',
    ("windows", "dns_query"): 'index=sysmon EventCode=22',
}


def translate_field(field: str) -> str:
    return FIELD_MAPPING.get(field, field.lower().replace(" ", "_"))


def translate_condition_value(field: str, modifier: str, value) -> str:
    """Translate a single field+modifier+value into a Splunk expression."""
    spl_field = translate_field(field)

    if isinstance(value, list):
        parts = [translate_condition_value(field, modifier, v) for v in value]
        return f"({' OR '.join(parts)})"

    value_str = str(value)

    if modifier in ("contains", "contains|all"):
        return f'{spl_field}="*{value_str}*"'
    elif modifier == "startswith":
        return f'{spl_field}="{value_str}*"'
    elif modifier == "endswith":
        return f'{spl_field}="*{value_str}"'
    elif modifier == "re":
        return f'{spl_field}=/{value_str}/'
    elif modifier == "cidr":
        # Splunk uses cidrmatch for CIDR notation
        return f'cidrmatch("{value_str}", {spl_field})'
    else:
        # Exact match (no modifier, or "=")
        return f'{spl_field}="{value_str}"'


def parse_detection_selection(selection: dict) -> str:
    """Parse a Sigma detection selection block into SPL."""
    parts = []

    for field_expr, value in selection.items():
        # Parse field|modifier syntax
        if "|" in field_expr:
            field, modifier = field_expr.split("|", 1)
        else:
            field, modifier = field_expr, "exact"

        if isinstance(value, list):
            sub_parts = [translate_condition_value(field, modifier, v) for v in value]
            operator = " AND " if modifier == "contains|all" else " OR "
            parts.append(f"({operator.join(sub_parts)})")
        else:
            parts.append(translate_condition_value(field, modifier, value))

    return " AND ".join(parts)


def parse_logsource(logsource: dict) -> str:
    """Get the Splunk search head from a Sigma logsource block."""
    product = logsource.get("product", "")
    service = logsource.get("service", "")
    category = logsource.get("category", "")
    key = (product, service or category)
    return LOGSOURCE_MAPPING.get(key, f'index=* sourcetype="{product}:{service}"')


def convert_rule(rule_path: Path) -> dict:
    """Convert a single Sigma rule file to SPL."""
    with open(rule_path) as f:
        rule = yaml.safe_load(f)

    title = rule.get("title", rule_path.stem)
    rule_id = rule.get("id", "unknown")
    level = rule.get("level", "unknown")
    description = rule.get("description", "").strip()

    logsource = rule.get("logsource", {})
    detection = rule.get("detection", {})
    falsepositives = rule.get("falsepositives", [])

    # Build base search
    base_search = parse_logsource(logsource)

    # Parse selection blocks
    selection_spls = {}
    filter_spls = {}

    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, dict):
            if key.startswith("filter"):
                filter_spls[key] = parse_detection_selection(value)
            else:
                selection_spls[key] = parse_detection_selection(value)

    # Parse condition
    condition = detection.get("condition", "selection")
    timeframe = detection.get("timeframe", None)

    # Build where clause from condition (simplified)
    where_parts = []
    for sel_name, sel_spl in selection_spls.items():
        where_parts.append(sel_spl)

    filter_parts = []
    for filt_name, filt_spl in filter_spls.items():
        filter_parts.append(f"NOT ({filt_spl})")

    all_conditions = where_parts + filter_parts

    # Assemble SPL
    spl_parts = [base_search]
    if all_conditions:
        spl_parts.append(f'| where {" AND ".join(all_conditions)}')

    # Add timeframe-based stats if condition includes count
    if "count" in condition and timeframe:
        # Extract field being counted by from condition
        # e.g., "selection | count(SourceAddress) by UserPrincipalName > 1"
        spl_parts.append(
            f'| bin _time span={timeframe}'
            f'\n| stats count by user_principal_name, _time'
            f'\n| where count > 1'
        )

    spl_parts.append(f'| table _time, *')

    spl_query = "\n".join(spl_parts)

    return {
        "title": title,
        "rule_id": rule_id,
        "level": level,
        "description": description[:200] + "..." if len(description) > 200 else description,
        "false_positives": falsepositives,
        "spl": spl_query,
        "source_file": str(rule_path),
    }


def format_output(result: dict) -> str:
    """Format conversion result for display or file output."""
    lines = [
        f"{'=' * 70}",
        f"Title:   {result['title']}",
        f"ID:      {result['rule_id']}",
        f"Level:   {result['level']}",
        f"Source:  {result['source_file']}",
        f"",
        f"Description:",
        f"  {result['description']}",
        f"",
        f"False Positives:",
    ]
    for fp in result.get("false_positives", []):
        lines.append(f"  - {fp}")
    lines.extend([
        f"",
        f"SPL Query:",
        f"{'─' * 70}",
        result["spl"],
        f"{'─' * 70}",
        f"",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Convert Sigma rules to Splunk SPL queries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--rule", type=Path, help="Path to a single Sigma YAML rule")
    group.add_argument("--dir", type=Path, help="Directory containing Sigma YAML rules")
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Output directory for SPL files (default: print to stdout)"
    )
    args = parser.parse_args()

    rule_files = []
    if args.rule:
        rule_files = [args.rule]
    else:
        rule_files = sorted(args.dir.glob("*.yml")) + sorted(args.dir.glob("*.yaml"))

    if not rule_files:
        print(f"No YAML files found in {args.dir}", file=sys.stderr)
        sys.exit(1)

    results = []
    errors = []

    for rule_path in rule_files:
        try:
            result = convert_rule(rule_path)
            results.append(result)
        except Exception as e:
            errors.append((rule_path, str(e)))

    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        for result in results:
            out_file = args.output / f"{Path(result['source_file']).stem}.spl"
            with open(out_file, "w") as f:
                f.write(format_output(result))
            print(f"Written: {out_file}")
    else:
        for result in results:
            print(format_output(result))

    if errors:
        print(f"\n{'=' * 70}", file=sys.stderr)
        print(f"Errors ({len(errors)}):", file=sys.stderr)
        for path, error in errors:
            print(f"  {path}: {error}", file=sys.stderr)

    print(f"\nConverted {len(results)} rule(s), {len(errors)} error(s).")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
