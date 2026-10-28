"""Inspect existing ATT&CK entities; do not fabricate an attribution relationship."""
import os
from pycti import OpenCTIApiClient


def find_one(api, external_id, name):
    # Search names, then inspect returned source IDs locally instead of assuming
    # that every OpenCTI entity type exposes an external_id filter.
    results = api.list(search=name, first=100)
    if len(results) == 100:
        raise RuntimeError('Search cap reached; inspect the imported dataset before continuing')
    matches = []
    for entity in results:
        references = entity.get('externalReferences', [])
        if isinstance(references, dict):
            references = [edge['node'] for edge in references.get('edges', [])]
        if entity.get('x_mitre_id') == external_id or any(
            ref.get('source_name') == 'mitre-attack' and ref.get('external_id') == external_id
            for ref in references):
            matches.append(entity)
    if len(matches) != 1:
        raise RuntimeError(f"Expected one imported ATT&CK entity for {external_id}; found {len(matches)}")
    return matches[0]


def main():
    client = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_API_TOKEN"])
    group = find_one(client.intrusion_set, "G0016", "APT29")
    technique = find_one(client.attack_pattern, "T1059.001", "PowerShell")
    print("Intrusion set:", group["id"], group["name"])
    print("Attack pattern:", technique["id"], technique["name"])
    print("Inspect the imported uses relationship and its cited procedure evidence in OpenCTI.")
    print("Source: https://attack.mitre.org/groups/G0016/")


if __name__ == "__main__":
    main()
