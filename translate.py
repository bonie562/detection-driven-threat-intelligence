"""Restricted Sigma-to-Wazuh translator for this book's one-event lab.

This is not a Sigma CLI backend. Unsupported semantics raise ValueError.
"""
import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from uuid import UUID

import yaml

FIELD_MAP = {
    "ParentImage|endswith": "win.eventdata.parentImage",
    "Image|endswith": "win.eventdata.image",
}
LEVELS = {"informational": 3, "low": 5, "medium": 7, "high": 10, "critical": 12}


def load_rule(path):
    rule = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rule, dict):
        raise ValueError("Expected a single Sigma mapping")
    UUID(rule["id"])
    if rule.get("logsource") != {"category": "process_creation", "product": "windows"}:
        raise ValueError("Only windows/process_creation is supported")
    detection = rule.get("detection", {})
    if set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
        raise ValueError("Only a single selection with condition: selection is supported")
    selection = detection["selection"]
    if not isinstance(selection, dict) or set(selection) != set(FIELD_MAP):
        raise ValueError("Require both ParentImage|endswith and Image|endswith only")
    for key, values in selection.items():
        values = values if isinstance(values, list) else [values]
        if not values or not all(isinstance(v, str) and v.startswith("\\") for v in values):
            raise ValueError("Expected non-empty Windows filename suffixes")
        if any(any(c in v for c in "*?\r\n\x00") for v in values):
            raise ValueError("Wildcards and control characters are unsupported")
    if rule.get("level") not in LEVELS:
        raise ValueError("Unknown Sigma level")
    return rule


def translate(path, output):
    rule = load_rule(path)
    sha = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    group = ET.Element("group", name="local,cti_lab,")
    node = ET.SubElement(group, "rule", id="100200", level=str(LEVELS[rule["level"]]))
    # Wazuh 4.14.9 built-in Sysmon Event 1 parent rule.
    ET.SubElement(node, "if_sid").text = "61603"
    for key, field in FIELD_MAP.items():
        values = rule["detection"]["selection"][key]
        values = values if isinstance(values, list) else [values]
        ET.SubElement(node, "field", name=field, type="pcre2").text = (
            "(?i)(?:" + "|".join(re.escape(v) for v in values) + ")$"
        )
    ET.SubElement(node, "description").text = f"Sigma {rule['id']} sha256={sha} {rule['title']}"
    mitre = ET.SubElement(node, "mitre")
    for tag in rule.get("tags", []):
        if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag):
            ET.SubElement(mitre, "id").text = tag.removeprefix("attack.").upper()
    if not len(mitre):
        raise ValueError("At least one ATT&CK technique tag is required")
    ET.indent(group, space="  ")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(ET.tostring(group, encoding="unicode") + "\n", encoding="utf-8")
    output.with_suffix(".manifest.json").write_text(json.dumps({
        "sigma_id": rule["id"], "sigma_sha256": sha,
        "translator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "wazuh_rule_id": 100200, "wazuh_parent_rule": 61603,
        "wazuh_version": "4.14.9", "field_map": FIELD_MAP,
    }, indent=2) + "\n", encoding="utf-8")
    return group


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("output")
    args = parser.parse_args()
    translate(args.source, args.output)
