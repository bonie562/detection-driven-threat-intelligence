# Worked case From source context to an explainable alert

Edition: book-1-technical-revision-2026-10-28-r2.
This is a completed analytical example with synthetic inputs and expected live outcomes.
It is not a record of a real intrusion or a claim that the live lab was run.
Use CASE_RECORD_TEMPLATE.md to record your own observed results.

## 1 Define the decision

Question: can the monitored Windows lab identify the selected relationship of a
Windows PowerShell process launching cmd.exe or rundll32.exe, and can an analyst
explain a resulting match without claiming maliciousness or attribution?

The target is a process relationship. The initial rule is experimental. It is not
an APT29 detector or a detector for every implementation of PowerShell execution.
A useful outcome includes discovering that telemetry or an implementation cannot
support the requirement. Do not silently weaken the question to get a pass.

## 2 Review the source and make the analytical choice

Source references:
- https://attack.mitre.org/groups/G0016/
- https://attack.mitre.org/techniques/T1059/001/

The technique page describes adversary abuse of PowerShell, including execution
that need not invoke powershell.exe. The group page supplies the G0016 context.
Use the cited procedure evidence in your imported ATT&CK release to assess a
particular claim; record the release and file hash. These pages justify reviewing
PowerShell visibility. They do not establish that the exact cmd.exe/rundll32.exe
selection in this exercise is a uniquely identifying APT29 procedure.

Analyst decision: use a simple parent–child relationship to teach field mapping,
translation and alert interpretation. Choose two child images so the test can
exercise OR within one field and AND between two fields. The choice is an
educational approximation, not a reported attack reconstruction.

Alternative considered: match every PowerShell execution. Rejected for this
exercise because it does not teach the selected parent–child contract and would
increase benign overlap. This is not a measured production comparison.

Evidence gap: an operational rule would need local baseline observations and
additional context to discriminate suspicious from expected administration.
Do not infer actor identity from the selected behavior.

## 3 Keep the MISP and OpenCTI roles explicit

Complete Appendix A's synthetic intake exercise separately. Record the MISP event
UUID, attribute UUID, normalized pattern, validity, destination marking and
OpenCTI indicator ID. Run dry-run before apply and review the candidate. Repeat
apply serially and record whether the server reports an existing indicator.
Do not label this expectation as observed until your server actually returns it.

The source value cti-lab.example is reserved synthetic data. Its purpose is to
teach controlled transfer, provenance and expiry. It is not included in the
PowerShell rule, and it must not be linked to APT29 as hostile infrastructure.
The explicit decision in this case is to keep that indicator context-only.

Next inspect imported ATT&CK entities with model_apt29.py. Record the IDs returned
for G0016 and T1059.001 and inspect the uses relationship and its source evidence
in OpenCTI. The script performs entity lookup, not a complete graph audit.
The analyst records the relationship between the source assessment and rule in
the case record. No automatic MISP-to-Sigma generation or alert enrichment is
implemented by the companion.

## 4 Specify telemetry and matching semantics

Required event class: Sysmon ProcessCreate, Event ID 1, forwarded to a compatible
Wazuh manager. For the manager replay, supplied JSON simulates the decoded shape.

| Source field | Sigma field | Native decoded field | Requirement |
|---|---|---|---|
| ParentImage | ParentImage | win.eventdata.parentImage | Ends with backslash plus powershell.exe |
| Image | Image | win.eventdata.image | Ends with backslash plus cmd.exe or rundll32.exe |
| Event ID | process_creation logsource | win.system.eventID | Process-creation parent rule 61603 |

Both image conditions must hold. Matching is case-insensitive and treats suffixes
literally. The leading backslash prevents a filename such as notpowershell.exe
from matching the parent suffix. Missing fields cannot satisfy the corresponding
field predicate. A matching name does not establish binary authenticity.

Excluded scope includes pwsh.exe, renamed executable paths, PowerShell hosted
in another process, other child images and activity without a selected child.
Some are useful future detection requirements; none is covered by claiming the
whole ATT&CK technique is green on a coverage chart.

## 5 Build and predict before executing

Use Appendix A to acquire the matching companion, prepare Python and initialize
the disposable services. Work from the repository root. Then run:

```bash
python -m unittest discover -p 'test_*.py' -v
sigma check rules/
python translate.py rules/powershell_child.yml build/local_cti_rules.xml
```

Inspect the manifest and XML. Record source UUID, source SHA-256 and translator
SHA-256. Confirm native rule 100200, level 7, parent 61603 and both mapped fields.
Do not copy the printed XML fragment in place of the complete generated file.

| Fixture | Expected custom-rule result | Reason |
|---|---|---|
| positive | Match | Selected parent and cmd.exe child |
| positive_case | Match | Case differences do not change matching |
| positive_rundll32 | Match | Second selected child alternative |
| negative_parent | No match | Wrong parent |
| negative_child | No match | Unselected child |
| negative_suffix | No match | Filename suffix boundary differs |
| negative_eventid | No match | Wrong event class |

The offline evaluator uses Python regular expressions. These predictions must
also be checked by the native engine; offline agreement is not PCRE2 validation.

## 6 Establish native and collection evidence separately

After service readiness and configuration review:

```bash
python scripts/wazuh_lab.py install
python scripts/wazuh_lab.py test
python scripts/wazuh_lab.py replay
```

The native helper stores output under build/native-<run-id>. Positive tests
require rule 100200, level 7 and JSON decoding. Negative tests must decode without
matching that custom rule; unrelated built-in matches are not automatically
failures. A failed subprocess stops the test and exposes its error.

Replay adds a unique marker to the synthetic command line and waits up to thirty
seconds for a matching new alert in the last 2,000 alert lines. It checks rule ID,
level, marker and parent/child fields, then saves input, alert and receipt files
under build/replay-<marker>. A timeout is an unresolved test failure, not proof
of absent behavior. Rotation or unusually high volume can also defeat this
bounded observation method; inspect the manager logs and collection state.

Replay proves only the tested manager path if it succeeds. It does not prove
that Sysmon or a Windows agent is configured. Complete the separate endpoint
exercise in Appendix A to test that path. Verify the positive and negative
source events in Windows independently, then correlate the positive alert.

## 7 Interpret the harmless event

Illustrative input: a lab analyst deliberately runs cmd.exe /c echo CTI-LAB from
Windows PowerShell on an isolated enrolled VM. The authorization and generated
command are part of this scenario; they are not facts about an unknown alert.

Expected behavior result: the rule matches the selected parent–child relationship.
Expected disposition after confirming the test authorization and event context:
authorized lab activity. Maliciousness is not established. APT29 attribution is
unsupported. A correct behavioral match can therefore have a benign disposition.

For an unknown alert, first confirm the host, rule revision and event fields.
Inspect user/session context, command lines, ancestry and related activity.
Check authorization through an appropriate record or owner. Prioritize using
behavior, impact, asset context and uncertainty. Missing CTI association is not
a default reason to reduce priority. Record what evidence would change the
assessment and escalate under the established response procedure when warranted.

## 8 Close the loop with a defensible decision

Proposed change: suppress all matches from the administrative account used in
the lab. Decision: reject this broad exception. The account's authorized use in
one event does not prove that future activity from it will be safe.

Selected action: retain the rule as experimental, document its benign overlap
and collect a local sample before proposing a narrower condition. A candidate
exception could depend on verified script identity and approved execution
context, but neither is implemented by this translator. Adding such fields
requires a changed contract, implementation and regression tests before promotion.

This is a completed feedback decision: the evidence changes the documented scope
and prevents an unjustified exclusion. It does not claim a measured reduction in
false positives. Record the decision owner and review date in your own case.

## 9 Diagnose failures in order

If initialization fails, inspect template availability, Docker access and hashing
errors before starting stacks. Preserve an existing .env; it is not disposable
when its volumes remain in use. The Python clients parse .env as data; do not
source it as Bash. Explicit exported environment variables override local values.

If the rule fails, check service health, input event ID, decoding, field names,
parent rule, installed artifact and configuration errors before changing the
hypothesis. A new rule cannot repair missing telemetry. If the CTI import fails,
check source publication, approval tag, to_ids, age, permissions and destination
marking. A successful empty response differs from an API error.

## Completion rubric

A complete reader record contains source references and uncertainty, a bounded
hypothesis, the intake decision, context IDs if inspected, field mapping, exact
artifact identities, separately labeled test layers, disposition and feedback.
“Passed” without evidence and an ATT&CK tag does not satisfy the exercise.
Live layers that were not run remain marked not run. The provided VALIDATION.md
records checks actually performed for this revision and the outstanding work.
