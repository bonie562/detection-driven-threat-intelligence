"""Bounded, dry-run-first MISP intake and optional OpenCTI indicator creation.

Use only an approved MISP export tag to authorize cross-platform distribution.
No discovery of secrets, automatic enrichment, or detection deployment occurs.
"""
import argparse
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from stix2patterns.validator import run_validator


def normalize(kind, value):
    value = value.strip()
    if kind in {"ip-src", "ip-dst"}:
        addr = ipaddress.ip_address(value)
        return f"ipv{addr.version}-addr:value", str(addr)
    if kind == "domain":
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
            raise ValueError("Invalid domain")
        return "domain-name:value", value
    if kind == "url":
        u = urlsplit(value)
        if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password:
            raise ValueError("Require an HTTP(S) URL without user information")
        return "url:value", value
    if kind == "sha256" and re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "file:hashes.'SHA-256'", value.lower()
    raise ValueError("Unsupported type or invalid value")


def make_pattern(kind, value):
    path, value = normalize(kind, value)
    if any(ord(c) < 32 for c in value):
        raise ValueError("Control characters are prohibited")
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    pattern = f"[{path} = '{escaped}']"
    errors = run_validator(pattern, stix_version="2.1")
    if errors:
        raise ValueError("Invalid STIX pattern: " + "; ".join(errors))
    return value, pattern


def fetch_events(client, since, tag, page_size=50, max_pages=10):
    """A full final page is treated as truncation, never as a complete result."""
    events = []
    for page in range(1, max_pages + 1):
        batch = client.search(controller="events", published=True,
                              publish_timestamp=since, tags=tag,
                              limit=page_size, page=page, pythonify=True)
        if not isinstance(batch, list):
            raise RuntimeError("MISP returned an error or unexpected response")
        events.extend(batch)
        if len(batch) < page_size:
            return events
    raise RuntimeError("Retrieval cap reached; narrow the window before retrying")


def prepare(events, now, ttl_days=7):
    seen, records = set(), []
    for event in events:
        if not getattr(event, "uuid", None):
            raise ValueError("Source event UUID is required")
        for attr in event.attributes:
            if not getattr(attr, "to_ids", False) or getattr(attr, "deleted", False):
                continue
            if attr.type not in {"ip-src", "ip-dst", "domain", "url", "sha256"}:
                continue
            value, pattern = make_pattern(attr.type, attr.value)
            stamp = getattr(attr, "timestamp", None)
            if not isinstance(stamp, datetime):
                raise ValueError("Source attribute modification timestamp is required")
            stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
            if stamp > now:
                raise ValueError("Source timestamp is in the future; check clock synchronization")
            expiry = stamp + timedelta(days=ttl_days)
            if expiry <= now or pattern in seen:
                continue
            seen.add(pattern)
            records.append({"value": value, "pattern": pattern,
                            "event_uuid": event.uuid, "attribute_uuid": attr.uuid,
                            "valid_from": stamp.isoformat(), "valid_until": expiry.isoformat()})
    return records


def create_indicator(client, record, source_url, marking_id):
    filters = {"mode": "and", "filters": [{"key": "pattern", "values": [record["pattern"]]}], "filterGroups": []}
    existing = client.indicator.list(filters=filters, first=2)
    if existing:
        return "existing"
    ref = client.external_reference.create(
        source_name="MISP", external_id=record["attribute_uuid"],
        url=source_url.rstrip("/") + "/events/view/" + record["event_uuid"])
    result = client.indicator.create(
        name=record["value"], pattern_type="stix", pattern=record["pattern"],
        x_opencti_main_observable_type=("IPv6-Addr" if "ipv6-addr:" in record["pattern"] else
                                      "IPv4-Addr" if "ipv4-addr:" in record["pattern"] else
                                      "Domain-Name" if "domain-name:" in record["pattern"] else
                                      "Url" if "url:value" in record["pattern"] else "StixFile"),
        valid_from=record["valid_from"], valid_until=record["valid_until"],
        confidence=50, objectMarking=[marking_id], externalReferences=[ref["id"]],
        description="Approved MISP lab import; confidence 50 is a lab policy value, not a source assessment.")
    if not result or not result.get("id"):
        raise RuntimeError("OpenCTI did not return a created indicator ID")
    return "created"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Create approved indicators in OpenCTI")
    parser.add_argument("--output", default="build/indicators.json")
    args = parser.parse_args()
    from pymisp import PyMISP
    url, key, tag = (os.environ[n] for n in ("MISP_URL", "MISP_API_KEY", "MISP_EXPORT_TAG"))
    client = PyMISP(url, key, ssl=os.getenv("MISP_CA_BUNDLE", True), timeout=30)
    now = datetime.now(timezone.utc)
    since = int((now - timedelta(days=7)).timestamp())
    events = fetch_events(client, since, tag)
    records = prepare(events, now)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    output.chmod(0o600)
    print(json.dumps({"events": len(events), "candidates": len(records), "mode": "apply" if args.apply else "dry-run"}))
    if args.apply:
        from pycti import OpenCTIApiClient
        api = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_API_TOKEN"])
        marking_id = os.environ["OPENCTI_MARKING_ID"]
        # Serialize runs: the read-before-create check is not a distributed lock.
        for record in records:
            print(json.dumps({"attribute_uuid": record["attribute_uuid"], "result": create_indicator(api, record, url, marking_id)}))


if __name__ == "__main__":
    main()
