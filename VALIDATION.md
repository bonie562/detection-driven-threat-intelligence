# Validation record

Revision: book-1-technical-revision-2026-10-28-r2, 28 October 2026.
Status: revised candidate. Live integration remains unverified.

## Observed in the editing environment

Eleven offline unittest cases pass: the original six logic tests plus five setup
and replay regressions. The new checks cover clean initialization from committed
templates using simulated Docker hash output, refusal to overwrite .env, missing
template preflight, hash failure, literal dotenv loading and replay correlation.
These are offline checks. They do not establish Docker startup or native Wazuh
execution. No Docker executable is available in this environment.

The earlier GitHub package omitted generated paths that initialization also used
as templates. This revision supplies separate sanitized .template.yml inputs and
keeps generated credentials private. Python entry points now load .env with
python-dotenv instead of requiring Bash source. Existing process variables win.

## Required live evidence

On a clean isolated host, record acquisition revision, dependency installation,
initialization output, service health, image digests and configuration checks.
Then retain seven native matcher results, a newly marked replay alert, Windows
positive/negative controls if that path is used, MISP seeding and publication,
OpenCTI create/repeat results, actual markings/references and rollback evidence.
Use CASE_RECORD_TEMPLATE.md. Record failed and unrun checks explicitly.

Native helper and replay changes have offline logic coverage but remain untested
against a live manager. OpenCTI context import needs its supported import
capability or connector configured; the supplied stack does not automatically
install a MITRE connector. Import and relationship review are reader prerequisites.

## Claims not established

Production readiness, complete ATT&CK technique coverage, attack-detection
precision/recall, actor attribution, live stack compatibility, workload capacity
and response-time improvement have not been established by these checks.
Expected outcomes in CASE_STUDY.md and the book are teaching expectations, not
observed live results. Preserve this distinction when reporting your own work.
