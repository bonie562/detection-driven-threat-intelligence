# Detection Driven Threat Intelligence Companion

Revision: 28 October 2026. Run all commands from this directory on an isolated Linux lab host.
Repository: https://github.com/bonie562/detection-driven-threat-intelligence

Status: revised candidate. Live integration remains pending; see VALIDATION.md.
Start with CASE_STUDY.md for the learning path. The book and code revision must match.

## Scope and versions

The primary detection exercise uses one Sigma process-creation rule, a deliberately restricted
translator, and native Wazuh XML. The translator is project code, not an official Sigma backend.
It supports AND between the two fields, OR within their suffix lists, case-insensitive literal
suffix matching, and Sysmon Event ID 1. Other conditions, filters and modifiers fail validation.
Rule 100200 is a lab allocation; check for local ID collisions before installing it elsewhere.

| Component | Selected baseline | Validation scope |
|---|---|---|
| Python | CPython 3.12 on Linux x86_64 | Interpreter and local tests |
| Sigma CLI / pySigma | 3.1.0 / 1.5.1 | Rule validation and parsing |
| PyMISP | 2.5.9 | Import and client signature inspection; fake-client tests |
| PyCTI / OpenCTI | 7.261026.0 | Client source inspection and fake-client payload tests; server integration pending |
| Wazuh | 4.14.9 | Official ruleset field mapping inspected; native runtime and live alert tests pending |
| Docker Compose | 2.39.4 or compatible newer v2 | See delivered validation report |
| MISP and supporting containers | Immutable registry digests in images-lock.json | Manifest resolution; startup pending |

The newest PyMISP 2.5.34.4 and PyCTI 7.261026.0 did not resolve together because their Requests
constraints conflict. The selected older PyMISP resolves with the other dependencies.
requirements-lock.txt records the complete installed resolver result. Review package support
and image advisories before reusing this baseline outside a disposable lab.

## Acquire the companion

Open the repository link or scan the printed QR code. Read this README, then download
Code → Download ZIP and extract it, or clone with Git. Open Bash in the extracted
repository root, where `lab`, `requirements-lock.txt` and `rules/` are visible.
Run `chmod +x lab` if ZIP extraction did not preserve its executable permission.
Keep `EDITION.json` with your notes; record `git rev-parse HEAD` when using Git.

## Prepare the host and Python

Use Linux x86_64 with Docker Engine, Docker Compose v2, Python 3.12, and a working internet connection.
For all three stacks together, budget 8 virtual CPUs, 32 GB RAM, and 100 GB free SSD space,
plus a Windows VM if doing endpoint telemetry. These are planning estimates, not measured minima.
For a smaller host, complete the Wazuh replay exercise first and run the CTI stacks separately.
On Windows 11 use an Ubuntu VM or WSL2 with Docker Desktop integration. Run the commands in Bash.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m unittest discover -p 'test_*.py' -v
sigma check rules/
python translate.py rules/powershell_child.yml build/local_cti_rules.xml
sudo sysctl -w vm.max_map_count=262144
python scripts/initialize.py
```

Initialization generates unique credentials, hashes the two indexer passwords using the pinned
Wazuh indexer image, and prepares the first-boot configuration from committed, sanitized `.template.yml` inputs.
Generated outputs remain ignored; the templates contain no usable passwords. It refuses to overwrite an existing
.env. Use it only before creating the lab volumes; it is not a credential-rotation tool.
Do not commit .env, generated Wazuh credentials, or MISP working data. Preserve .env for restarts.

## Start the services

Generate Wazuh certificates once, before starting its stack:

```bash
docker compose --env-file .env -p cti-wazuh \
  -f vendor/wazuh/single-node/generate-indexer-certs.yml run --rm generator
./lab wazuh config --quiet
./lab opencti config --quiet
./lab misp config --quiet
./lab wazuh up -d
./lab opencti up -d
./lab misp up -d
./lab wazuh ps
./lab opencti ps
./lab misp ps
```

Each stack has its own bridge network and named data volumes. Host Python calls the services
through loopback ports; the stacks do not need a shared Docker network. Initialization preserves
the upstream MISP environment template and appends lab settings. OpenCTI includes Redis,
Elasticsearch, S3-compatible storage, RabbitMQ, the platform and one worker. Wazuh includes the
manager, indexer and dashboard. MISP includes its application, nginx, database, cache, modules
and upstream mail service. No external enrichment connectors are enabled.

Wait for the OpenCTI and MISP dependency health checks to become healthy; startup may take several
minutes. Verify service readiness, not just that containers exist:

```bash
./lab wazuh exec -T wazuh.manager /var/ossec/bin/wazuh-control status
./lab opencti logs --tail=50 opencti worker
./lab misp logs --tail=50 misp-core misp-nginx
```

Open the local UIs: Wazuh at https://localhost, OpenCTI at http://localhost:8080,
and MISP at http://localhost:8081. Wazuh uses the generated local CA; verify its certificate
against the generated files. Wazuh login is admin with WAZUH_INDEXER_PASSWORD from .env.
The CTI applications use the generated admin email/password settings.
HTTP CTI endpoints are loopback-only, for synthetic data on the same lab host.

## Build and verify the Wazuh rule

```bash
python translate.py rules/powershell_child.yml build/local_cti_rules.xml
python scripts/wazuh_lab.py install
python scripts/wazuh_lab.py test
python scripts/wazuh_lab.py replay
./lab wazuh exec -T wazuh.manager tail -n 100 /var/ossec/logs/alerts/alerts.json
```

The native test stores output in build/native-<run-id> and must pass all seven fixtures. Positive cases use native -U criteria for rule 100200, level 7 and JSON decoding. The positive, uppercase and rundll32 fixtures should
match rule 100200 at level 7. The other four fixtures must not match this custom rule, although
other built-in Wazuh rules may match. The replay helper uses a unique command-line marker, waits up to 30 seconds, and saves a matching new alert under build/replay-<marker>. It checks the last 2,000 alert lines; a timeout or rotation needs investigation. The expected live alerts.json entry has
rule.id 100200 and a description containing the source Sigma UUID and SHA-256. The test log is
/var/ossec/logs/cti-lab.json, monitored as JSON by the supplied manager configuration.
Allow a few seconds for log collection. wazuh-logtest output alone does not prove live ingestion
and does not write the same live alert stream.

The synthetic fixtures test decoder/matcher behavior. They do not prove endpoint collection,
maliciousness, actor attribution, performance under load, or coverage of all PowerShell execution.
Confirm real Windows collection separately as described below.

The installer backs up an existing local_cti_rules.xml and creates a marker. A second installation
is refused until rollback, so retries cannot silently replace the backup. If validation or restart
fails after installation, restore the pre-lab state:

```bash
python scripts/wazuh_lab.py rollback
```

## Collect a harmless Windows event

Use a disposable Windows VM with Sysmon and a Wazuh agent compatible with manager 4.14.9.
Install Sysmon from Microsoft Sysinternals and enable ProcessCreate (Event ID 1).
Confirm both Image and ParentImage appear in the Sysmon Operational channel before proceeding.
Merge config/windows-agent-fragment.xml into the agent's existing ossec_config and restart the agent.

All manager host ports are bound to loopback by default. A VM cannot connect to those bindings.
For endpoint collection, change only the manager's 1514/TCP and 1515/TCP bindings to the Linux
host's private lab-interface address; configure that interface's firewall for the Windows VM only.
Set the Windows agent manager address to that private address and complete agent enrollment.
Record the selected address in the lab notes; no universal IP address is hard-coded here.

In Windows PowerShell, run this harmless command:

```powershell
& "$env:WINDIR\System32\cmd.exe" /c echo CTI-LAB
```

Expect PowerShell as the parent, cmd.exe as the image, and rule 100200 in Wazuh after forwarding.
As a negative control, start Notepad from the same PowerShell session. It must not trigger 100200.
The positive command is benign; a matching alert is a true match to behavior, not evidence of compromise.

## MISP intake and OpenCTI indicators

The three Python entry points load the root `.env` as data using python-dotenv.
Do not run `source .env`: this is not a Bash script. Existing exported environment
variables take precedence; unset stale lab variables before switching environments.

The synthetic seed uses a separate, temporary write key. In MISP create a lab user/key allowed to
create and publish events, then put it in MISP_LAB_WRITE_KEY. Create a second retrieval-only key in
MISP_API_KEY. Keep these keys local. In OpenCTI copy the ID of an appropriate existing marking
definition into OPENCTI_MARKING_ID. For the synthetic .example data, a TLP:CLEAR marking is suitable.
The application token in .env starts as the lab administrator token; use a narrowly scoped account
for any later operational adaptation.

```bash
python seed_misp.py --apply
python ingest.py --output build/indicators.json
# Review the JSON candidates and source event before applying them.
python ingest.py --apply --output build/indicators.json
python ingest.py --apply --output build/indicators.json
```

The seed creates an organization-only event containing cti-lab.example, a reserved synthetic name.
It is not evidence of real malicious activity. Approve export only for the disposable event owned
by the lab organization. MISP_EXPORT_TAG is a local approval convention, not a TLP enforcement engine.
Before tagging any real event, review event AND attribute distribution/TLP restrictions and the
destination audience. The supplied exporter does not translate arbitrary sharing-group policy.

Intake uses publish_timestamp (not event date), retrieves at most ten pages of fifty events, and
fails if the last permitted page is full. It selects supported to_ids attributes, validates values
and STIX patterns, handles IPv4/IPv6, deduplicates, and rejects indicators whose seven-day lifetime
from source attribute modification has elapsed. Re-reading old data does not renew its lifetime.
Expired objects can remain as historical context in OpenCTI; downstream detection consumers must
exclude valid_until <= now. The script does not delete or revoke remote objects automatically.

Dry-run writes no remote indicators. Apply mode adds source references, an explicit destination
marking and validity times. A repeated serial run should report existing instead of creating a
duplicate indicator. Existing objects are left unchanged; this is not a refresh/update service.
Concurrent runs require external locking. This exercise creates contextual indicators only;
it does not automatically turn the domain into the behavioral PowerShell detection.

## APT29 context and analyst review

Import official MITRE ATT&CK data into OpenCTI using its supported STIX import or MITRE connector,
recording the imported ATT&CK release and file hash. Then run:

```bash
python model_apt29.py
```

The script retrieves intrusion set G0016 and attack pattern T1059.001. It fails if either is missing
or ambiguous and does not create new copies. Inspect the imported uses relationship and its cited
procedure evidence. General PowerShell activity cannot attribute an alert to APT29. The analyst
must link a reviewed intelligence hypothesis to the detection in the case record. Do not attach
the synthetic .example indicator to APT29 as if it were reported infrastructure.

## Troubleshooting and teardown

- Dependency conflict: recreate the Python environment from requirements-lock.txt; do not silently
  upgrade PyMISP or PyCTI independently.
- Port conflict: stop the process using the port or deliberately change the host binding and corresponding URL.
- Unhealthy Elasticsearch/indexer: check vm.max_map_count, RAM, disk and container logs.
- Wazuh authentication failure on first startup: verify .env and generated password hashes belong to
  the same initialization. Existing data volumes need the official credential-rotation procedure.
- Rule not firing: inspect Sysmon Event ID 1, decoder win.eventdata.image/parentImage casing, rule 61603,
  configuration-test output and rule-ID collisions before changing detection logic.
- MISP returns zero candidates: check publication time, export tag, to_ids, source attribute age and key permissions.
- OpenCTI rejects an import: check token access, marking ID, server/client versions and GraphQL errors.

```bash
./lab wazuh down
./lab opencti down
./lab misp down
```

These commands stop containers and preserve named volumes. Do not add -v unless intentionally
destroying disposable lab data after backing up the required evidence and configuration.
Keep upstream license files with vendored sources. See upstream-sources.json for commit provenance,
images-lock.json for immutable images, and the separate validation report for checks actually run.
