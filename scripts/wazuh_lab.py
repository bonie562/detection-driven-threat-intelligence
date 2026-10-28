"""Install, test, replay and restore the lab rule in the Docker Wazuh manager."""
import argparse
import json
import subprocess
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker', 'compose', '--env-file', str(ROOT / '.env'), '-p', 'cti-wazuh', '-f', str(ROOT / 'vendor/wazuh/single-node/docker-compose.yml')]
DEST = '/var/ossec/etc/rules/local_cti_rules.xml'


def run(args, **kwargs):
    return subprocess.run(COMPOSE + args, check=kwargs.pop("check", True), text=True, **kwargs)


def execute(command, **kwargs):
    return run(['exec', '-T', 'wazuh.manager', 'sh', '-c', 'set -eu; ' + command], **kwargs)


def replay_matches(alert, marker):
    rule = alert.get('rule', {})
    data = alert.get('data', {}).get('win', {}).get('eventdata', {})
    return (str(rule.get('id')) == '100200' and str(rule.get('level')) == '7'
            and data.get('commandLine') == 'cmd.exe /c echo ' + marker
            and str(data.get('image', '')).lower().endswith('\\cmd.exe')
            and str(data.get('parentImage', '')).lower().endswith('\\powershell.exe'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'test', 'replay', 'rollback'])
    args = parser.parse_args()
    if args.action == 'install':
        # A persistent one-deployment backup prevents retries from replacing the original.
        execute(f'test ! -e {DEST}.lab-installed; if test -e {DEST}; then cp -p {DEST} {DEST}.lab-backup; else touch {DEST}.lab-absent; fi; touch {DEST}.lab-installed')
        run(['cp', str(ROOT / 'build/local_cti_rules.xml'), 'wazuh.manager:/tmp/local_cti_rules.xml'])
        execute(f'install -o root -g wazuh -m 0640 /tmp/local_cti_rules.xml {DEST}')
        execute('touch /var/ossec/logs/cti-lab.json; /var/ossec/bin/wazuh-analysisd -t')
        execute('/var/ossec/bin/wazuh-control restart')
        print('Installed. Run test before replaying or generating endpoint events.')
    elif args.action == 'test':
        expectations = json.loads((ROOT / 'fixtures/expected.json').read_text())
        evidence = ROOT / 'build' / ('native-' + uuid.uuid4().hex)
        evidence.mkdir(parents=True)
        for name, expected in expectations.items():
            data = (ROOT / f'fixtures/{name}.json').read_text().strip() + '\n'
            command = '/var/ossec/bin/wazuh-logtest'
            if expected:
                command += ' -U 100200:7:json'
            result = execute(command, input=data, capture_output=True, check=False)
            output = result.stdout + result.stderr
            (evidence / f'{name}.txt').write_text(output)
            matched = bool(re.search(r"id: ['\"]100200['\"]", output))
            decoded = "name: 'json'" in output and 'win.system.eventID' in output
            if result.returncode != 0 or not decoded or matched != expected:
                raise RuntimeError(f'{name}: expected match={expected}; see {evidence}')
            print(f'{name}: PASS match={matched}')
        print(f'Native evidence: {evidence}. This does not establish live collection.')
    elif args.action == 'replay':
        marker = 'CTI-LAB-' + uuid.uuid4().hex
        data = json.loads((ROOT / 'fixtures/positive.json').read_text())
        data['win']['eventdata']['commandLine'] = 'cmd.exe /c echo ' + marker
        submitted = datetime.now(timezone.utc).isoformat()
        evidence = ROOT / 'build' / ('replay-' + marker)
        evidence.mkdir(parents=True)
        (evidence / 'input.json').write_text(json.dumps(data) + '\n')
        execute('cat >> /var/ossec/logs/cti-lab.json', input=json.dumps(data) + '\n')
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = execute('tail -n 2000 /var/ossec/logs/alerts/alerts.json', capture_output=True)
            for line in result.stdout.splitlines():
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if replay_matches(alert, marker):
                    (evidence / 'alert.json').write_text(json.dumps(alert, indent=2) + '\n')
                    (evidence / 'receipt.json').write_text(json.dumps({
                        'marker': marker, 'submitted_at': submitted,
                        'observed_at': datetime.now(timezone.utc).isoformat(),
                        'status': 'observed synthetic replay alert'
                    }, indent=2) + '\n')
                    print(f'Observed new rule 100200 level 7 alert. Evidence: {evidence}')
                    return
            time.sleep(1)
        raise RuntimeError(f'No matching new alert within 30 seconds; retain {evidence}. '
                           'Check collection, manager logs and rotation; do not call this a pass.')
    else:
        execute(f'test -e {DEST}.lab-installed; if test -e {DEST}.lab-backup; then cp -p {DEST}.lab-backup {DEST}; elif test -e {DEST}.lab-absent; then rm -f {DEST}; else exit 1; fi')
        execute('touch /var/ossec/logs/cti-lab.json; /var/ossec/bin/wazuh-analysisd -t')
        execute('/var/ossec/bin/wazuh-control restart')
        execute(f'rm -f {DEST}.lab-installed {DEST}.lab-absent {DEST}.lab-backup')
        print('Restored the pre-lab rule state.')


if __name__ == '__main__':
    main()
