# Change log and validation report

Revision date: 28 October 2026

## Status

Revised manuscript and companion implementation supplied. Publication approval remains pending the live integration and final production checks below. Offline checks do not establish that the complete lab runs successfully.

## Changes

- Replaced the nonworking Wazuh conversion placeholders with a restricted project translator, native XML output, source UUID/hash traceability, seven fixtures, installation, replay and rollback helpers. Unsupported Sigma structures fail validation.
- Replaced broken Appendix C snippets with references to complete runnable companion scripts.
- Added vendored Compose configurations, image locks, dependency lock, dummy environment example, ignore rules, initialization and setup instructions.
- Standardized APT29 as the existing ATT&CK intrusion set G0016; the inspection script reuses imported entities and avoids inventing attribution.
- Corrected MISP publication-time retrieval, bounded pagination, validation, deduplication and expiration behavior. Distinguished local approval tags from sharing-policy enforcement.
- Updated the NIST reference to SP 800-61 Revision 3 and qualified detection, attribution and CTI claims.
- Reduced repeated transitions, repaired title-page author placement, and supplied numbered print contents. The preserved author is Craig F. McCormack.

## Checks and results

The six companion unit tests were rerun successfully for this delivery. They cover unsupported translation semantics; fixture equivalence against an independent suffix evaluator; STIX patterns, escaping and IPv6; pagination limits; expiry/deduplication/to_ids; and creation payload provenance and markings. These use local logic and fake API clients, not live services.

All project Python files pass AST parsing. The revised manuscript contains none of the three identified broken Wazuh placeholders. Retained manuscript code-check records contain 35 blocks, including non-code excerpts; they are not evidence that every block was executed.

Retained Compose configuration checks show exit code zero for all four files. MISP emitted unset optional-variable warnings with the check environment. Configuration validation does not test image startup, credentials, service health or API behavior.

The Word document has an existing matching 163-page PDF render. All page contact sheets were reviewed for layout; title, contents and appendix placement are improved. Retained coordinate checks reported no out-of-bounds text, and 29 contents entries matched their target pages. This is not a completed full-size, every-page production proof or an ebook-device navigation test.

## Version baseline

| Component | Selected baseline | Verification boundary |
|---|---|---|
| Python | 3.12 | Local tests |
| Sigma CLI / pySigma | 3.1.0 / 1.5.1 | Retained rule validation; local translation tests |
| PyMISP | 2.5.9 | Local imports and fake-client tests |
| PyCTI / OpenCTI | 7.261026.0 | Client inspection and fake payload tests; server pending |
| Wazuh | 4.14.9 | Ruleset mapping and fixture logic; native/live runtime pending |
| Docker Compose | 2.39.4 | Retained configuration validation only |
| Container images | See images-lock.json | Startup pending |

## Remaining publication blockers

1. On a clean isolated Linux host, install the locked dependencies and initialize all stacks. Record host details, image digests, startup logs and healthy services. This environment has no Docker executable available.
2. Run the native Wazuh seven-fixture test, replay a positive event and retain the actual alerts.json result. Confirm the four negative fixtures do not match custom rule 100200. Test installation failure and rollback.
3. Verify actual Windows Sysmon collection and Wazuh forwarding with the harmless positive and negative commands.
4. Run MISP seeding, publication-time retrieval, OpenCTI apply and repeated-run duplicate checks against live servers. Verify permissions and markings, and inspect the imported ATT&CK entities and relationships.
5. Complete a full-size proof of every page, check all reference links, and validate navigation in the chosen ebook format. A printer-specific trim size and ebook export have not been certified.

The companion README contains execution instructions and expected results; those expected results must not be reported as observed results until the live checks are completed.
