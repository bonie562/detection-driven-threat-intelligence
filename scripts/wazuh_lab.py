"""Install, test, replay and restore the lab rule in the Docker Wazuh manager."""
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker', 'compose', '--env-file', str(ROOT / '.env'), '-p', 'cti-wazuh', '-f', str(ROOT / 'vendor/wazuh/single-node/docker-compose.yml')]
DEST = '/var/ossec/etc/rules/local_cti_rules.xml'


def run(args, **kwargs):
    return subprocess.run(COMPOSE + args, check=True, text=True, **kwargs)


def execute(command, **kwargs):
    return run(['exec', '-T', 'wazuh.manager', 'sh', '-c', 'set -eu; ' + command], **kwargs)


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
        for name, expected in expectations.items():
            data = (ROOT / f'fixtures/{name}.json').read_text()
            result = execute('/var/ossec/bin/wazuh-logtest', input=data, capture_output=True)
            output = result.stdout + result.stderr
            matched = "id: '100200'" in output
            if matched != expected:
                raise RuntimeError(f'{name}: expected match={expected}\n{output}')
            print(f'{name}: PASS match={matched}')
    elif args.action == 'replay':
        # Configuration installed by setup: one JSON event per line.
        execute('cat >> /var/ossec/logs/cti-lab.json', input=(ROOT / 'fixtures/positive.json').read_text())
        print('Replayed one positive fixture. Check alerts.json for rule.id 100200; logtest alone does not write live alerts.')
    else:
        execute(f'test -e {DEST}.lab-installed; if test -e {DEST}.lab-backup; then cp -p {DEST}.lab-backup {DEST}; elif test -e {DEST}.lab-absent; then rm -f {DEST}; else exit 1; fi')
        execute('touch /var/ossec/logs/cti-lab.json; /var/ossec/bin/wazuh-analysisd -t')
        execute('/var/ossec/bin/wazuh-control restart')
        execute(f'rm -f {DEST}.lab-installed {DEST}.lab-absent {DEST}.lab-backup')
        print('Restored the pre-lab rule state.')


if __name__ == '__main__':
    main()
